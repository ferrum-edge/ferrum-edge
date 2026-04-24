//! Deterministic port reservation for scripted-backend tests.
//!
//! ## Why this module exists
//!
//! Functional tests in ferrum-edge bind ephemeral ports, drop the listener,
//! then re-bind the same port later from a different process (the gateway
//! subprocess, a scripted backend, etc.). Under parallel test load, another
//! test can steal the freed port between the drop and the re-bind. CLAUDE.md
//! codifies this as the "bind-drop-rebind race" and mandates two defenses:
//!
//! 1. **Retry** on bind failure with a fresh port.
//! 2. **Hold** the listener open until the consumer is ready, so there is no
//!    interval during which the port is free.
//!
//! [`reserve_port`] implements (1). Its return value includes the live
//! [`TcpListener`], so callers doing (2) can pass the listener directly to
//! their scripted backend rather than dropping and re-binding.
//!
//! ## Usage
//!
//! ```ignore
//! let reservation = reserve_port().await?;
//! let port = reservation.port;
//! let listener = reservation.into_listener();
//! spawn_backend(listener).await;
//! ```
//!
//! For callers that only need a port (e.g., the gateway subprocess which
//! will itself bind), use [`PortReservation::drop_and_take_port`] explicitly
//! so the reasoning is captured in the test source.

use std::io;
use std::time::Duration;
use tokio::net::TcpListener;

/// Maximum number of bind attempts before giving up.
///
/// 10 is the same budget used by [`crate::common::gateway_harness`]'s spawn
/// retry — experience shows this is enough even under heavy parallel load.
const MAX_RESERVE_ATTEMPTS: u32 = 10;

/// A port held by a live `TcpListener` on `127.0.0.1`.
///
/// Prevents the "bind-drop-rebind" race by keeping the listener alive until
/// the caller explicitly hands it to a scripted backend (via
/// [`PortReservation::into_listener`]) or releases it (via
/// [`PortReservation::drop_and_take_port`]).
pub struct PortReservation {
    /// The reserved local port.
    pub port: u16,
    listener: TcpListener,
}

impl PortReservation {
    /// Consume this reservation and return the held listener. The caller
    /// owns the socket from here on; dropping the listener will free the
    /// port.
    pub fn into_listener(self) -> TcpListener {
        self.listener
    }

    /// Release the listener (freeing the port) and return just the port
    /// number. Only use this when the caller is about to hand the port to a
    /// subprocess that will itself bind — the return is a best-effort hint,
    /// and another test or process may steal the port in the interim.
    pub fn drop_and_take_port(self) -> u16 {
        let port = self.port;
        drop(self.listener);
        port
    }

    /// Return the `SocketAddr` (e.g., for constructing a backend URL) without
    /// releasing the listener.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

/// Bind `127.0.0.1:0` and return the live listener. Retries on transient
/// errors (EADDRINUSE, EADDRNOTAVAIL) up to [`MAX_RESERVE_ATTEMPTS`] times
/// with a short backoff — on a healthy machine this loop exits on the first
/// attempt.
pub async fn reserve_port() -> io::Result<PortReservation> {
    let mut last_err: Option<io::Error> = None;
    for attempt in 0..MAX_RESERVE_ATTEMPTS {
        match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => {
                let port = listener.local_addr()?.port();
                return Ok(PortReservation { port, listener });
            }
            Err(e) => {
                last_err = Some(e);
                // Brief backoff before retry — keeps the retry from hot-looping
                // on a saturated port namespace while still being responsive.
                tokio::time::sleep(Duration::from_millis(10 * (attempt + 1) as u64)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "exhausted port reservation retries",
        )
    }))
}

/// Reserve a pair of ports (common for gateway proxy/admin or frontend/backend).
/// Returns both reservations live; callers can pass each listener into a
/// scripted backend or release it separately.
pub async fn reserve_port_pair() -> io::Result<(PortReservation, PortReservation)> {
    // Reserve sequentially so if the second fails we drop the first cleanly.
    let first = reserve_port().await?;
    let second = reserve_port().await?;
    Ok((first, second))
}

/// Reserve and immediately release a port. Connects to the returned port
/// produce a genuine `ECONNREFUSED` at the kernel level (nothing is
/// listening), unlike
/// [`super::backends::tcp::TcpStep::RefuseNextConnect`] which accepts and
/// drops — that emits FIN/RST, not a connect-time refusal.
///
/// **Race caveat**: There is a brief window after the listener is dropped
/// and before the caller connects in which another process/test could
/// grab the port. Callers should expect sporadic test flakes if the host
/// is saturated with parallel tests; for `#[ignore]`d functional tests
/// the window is tiny and the risk is acceptable.
pub async fn unbound_port() -> io::Result<u16> {
    Ok(reserve_port().await?.drop_and_take_port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn reserve_port_returns_live_listener() {
        let reservation = reserve_port().await.expect("reserve");
        let port = reservation.port;
        let listener = reservation.into_listener();

        // Spawn a server that accepts one connection and echoes.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read");
            stream.write_all(&buf).await.expect("write");
        });

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        client.write_all(b"hello").await.expect("write");
        let mut resp = [0u8; 5];
        client.read_exact(&mut resp).await.expect("read");
        assert_eq!(&resp, b"hello");
        server.await.expect("server join");
    }

    #[tokio::test]
    async fn reserve_port_pair_unique() {
        let (a, b) = reserve_port_pair().await.expect("pair");
        assert_ne!(a.port, b.port);
    }

    #[tokio::test]
    async fn drop_and_take_port_returns_port_number() {
        let reservation = reserve_port().await.expect("reserve");
        let port = reservation.drop_and_take_port();
        assert!(port > 0);
    }
}
