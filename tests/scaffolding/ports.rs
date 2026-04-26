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
use tokio::net::{TcpListener, UdpSocket};

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

/// A UDP port held by a live `UdpSocket` on `127.0.0.1`. Mirror of
/// [`PortReservation`] for the datagram-oriented backends in Phase 4.
///
/// TCP's bind-drop-rebind race also exists for UDP — holding the socket
/// until the backend is ready avoids it. Drop the socket to release the
/// port.
pub struct UdpPortReservation {
    /// The reserved local port.
    pub port: u16,
    socket: UdpSocket,
}

impl UdpPortReservation {
    /// Consume this reservation and return the held socket. The caller
    /// owns it from here on; dropping frees the port.
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }

    /// Release the socket (freeing the port) and return just the port
    /// number. Use only when handing the port to a subprocess that will
    /// itself bind — another process may steal the port in the interim.
    pub fn drop_and_take_port(self) -> u16 {
        let port = self.port;
        drop(self.socket);
        port
    }

    /// Return the `SocketAddr` without releasing the socket.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }
}

/// Bind `127.0.0.1:0` on UDP and return the live socket. Retry semantics
/// mirror [`reserve_port`].
pub async fn reserve_udp_port() -> io::Result<UdpPortReservation> {
    let mut last_err: Option<io::Error> = None;
    for attempt in 0..MAX_RESERVE_ATTEMPTS {
        match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => {
                let port = socket.local_addr()?.port();
                return Ok(UdpPortReservation { port, socket });
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(10 * (attempt + 1) as u64)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "exhausted UDP port reservation retries",
        )
    }))
}

/// Reserve and immediately release a UDP port. Useful for handing the
/// port to a subprocess (like the gateway) that will itself bind. Has
/// the same bind-drop-rebind race caveat as [`unbound_port`] for TCP.
pub async fn unbound_udp_port() -> io::Result<u16> {
    Ok(reserve_udp_port().await?.drop_and_take_port())
}

/// Reserve a co-located TCP + UDP pair on the same port number.
///
/// Returned as a `(PortReservation, UdpPortReservation)` tuple — the same
/// types `reserve_port` / `reserve_udp_port` use individually. Callers can
/// hand the TCP listener and UDP socket to a TCP+TLS backend and an H3
/// backend respectively, so the proxy's single `backend_port` value works
/// for both.
///
/// Strategy: bind TCP on `0`, note its port, then bind UDP on that same
/// port. Retry on UDP conflict. TCP and UDP share the port namespace at
/// the kernel level without issue (different protocol numbers), so a UDP
/// bind at the same port generally succeeds on the first try.
pub async fn reserve_colocated_tcp_udp() -> io::Result<(PortReservation, UdpPortReservation)> {
    for attempt in 0..MAX_RESERVE_ATTEMPTS {
        let tcp_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                if attempt + 1 == MAX_RESERVE_ATTEMPTS {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(10 * (attempt + 1) as u64)).await;
                continue;
            }
        };
        let port = tcp_listener.local_addr()?.port();
        match UdpSocket::bind(("127.0.0.1", port)).await {
            Ok(udp_socket) => {
                return Ok((
                    PortReservation {
                        port,
                        listener: tcp_listener,
                    },
                    UdpPortReservation {
                        port,
                        socket: udp_socket,
                    },
                ));
            }
            Err(e) => {
                drop(tcp_listener);
                if attempt + 1 == MAX_RESERVE_ATTEMPTS {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(10 * (attempt + 1) as u64)).await;
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "exhausted colocated TCP/UDP port reservation retries",
    ))
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

    #[tokio::test]
    async fn reserve_colocated_tcp_udp_shares_port_across_protocols() {
        let (tcp, udp) = reserve_colocated_tcp_udp()
            .await
            .expect("colocated reserve");
        assert_eq!(tcp.port, udp.port, "TCP and UDP halves must share a port");
        // Both halves should still be live — drop them in sequence and
        // confirm `local_addr()` works on each.
        assert_eq!(tcp.local_addr().unwrap().port(), tcp.port);
        assert_eq!(udp.local_addr().unwrap().port(), udp.port);
    }
}
