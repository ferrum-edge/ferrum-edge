//! Cross-process port reservations for functional and integration tests.
//!
//! ## Why this module exists
//!
//! Nextest runs tests in separate processes. Every allocation uses the shared
//! [`super::port_registry`] so concurrent tests cannot receive the same port,
//! including across TCP/UDP and wildcard/loopback binds (issue #5479).
//!
//! Keep fixture sockets bound and pass them to the consumer. For a gateway
//! subprocess, release only the socket with `drop_and_take_port`: the registry
//! lease survives until the test process exits. Reservations exclude the host's
//! ephemeral source range so outbound connects cannot steal a released port.
//! TCP and UDP reservations bind exclusively with `SO_REUSEADDR` disabled,
//! also skipping TCP TIME_WAIT ports that the gateway could not bind. Each process
//! scans from a PID/time-derived pseudo-random offset in the eligible range and wraps once,
//! spreading consecutive test processes across ports instead of recycling the
//! lowest numbers. Registry coordination and lease retention still apply.
//! Native `TestSocket::bind_test(...:0)` fixtures must keep their socket bound.
//! Keep the gateway's bounded bind retries for unrelated OS users, which do not
//! participate in this registry.
//!
//! Dropping an unused reservation releases its lease. Transferring a native
//! socket extends its lease to process exit because the socket cannot carry a
//! Rust lease guard. This also makes teardown and subsequent subprocess handoffs
//! safe in libtest, where multiple tests can share a process.
//! Readiness must never rebind a handed-off UDP port: the spawning process owns
//! the lease, so the registry cannot distinguish that probe from the intended
//! consumer. Use the child's authenticated admin readiness barrier instead.
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

use super::port_registry::{
    PortLease, TestSocket, bind_tcp_listener, bind_tcp_socket, bind_udp_socket, process_registry,
};

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

/// Spawn-retry budget after a bind-drop-rebind of a port handed to a gateway.
///
/// This covers residual OS collisions with nonparticipating processes. A whole
/// gateway (or in-process listener) start is expensive, and 3 matches
/// [`crate::common::gateway_harness::TestGateway`]'s default `max_attempts`.
/// Callers wrapping `GatewayHarnessBuilder::spawn()` with this budget must
/// set inner `max_attempts(1)` — the inner loop cannot pick a new
/// env-pinned port such as `FERRUM_PROXY_HTTPS_PORT`.
///
/// The reservation **cannot** stay open on these paths: the gateway
/// subprocess (or `start_tcp_listener` / `start_udp_listener`) binds its
/// own socket, so the test must drop the socket before spawn while retaining
/// the registry lease. An unrelated OS process can still take the number.
pub const BIND_DROP_SPAWN_ATTEMPTS: u32 = 3;

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
    lease: Arc<PortLease>,
}

impl PortReservation {
    /// Consume this reservation and return the held listener. The caller
    /// owns the socket from here on; the lease lasts until process exit.
    pub fn into_listener(self) -> TcpListener {
        self.lease.retain_for_process();
        self.listener
    }

    /// Release the listener (freeing the port) and return just the port
    /// number. Only use this when the caller is about to hand the port to a
    /// subprocess that will itself bind. The lease prevents participating tests
    /// from receiving this number until the current process exits.
    pub fn drop_and_take_port(self) -> u16 {
        let port = self.lease.retain_for_process();
        drop(self.listener);
        port
    }

    /// Return the `SocketAddr` (e.g., for constructing a backend URL) without
    /// releasing the listener.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

/// The source-port range in the gateway's network namespace. Linux CI may
/// override its default; a missing proc file uses the Linux default. Other
/// supported hosts use the IANA dynamic range. Malformed/read errors fail closed.
pub fn ephemeral_source_port_range() -> io::Result<RangeInclusive<u16>> {
    #[cfg(target_os = "linux")]
    {
        let raw = match std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
            Ok(raw) => raw,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(32_768..=60_999);
            }
            Err(error) => return Err(error),
        };
        let bounds = raw
            .split_whitespace()
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bounds.len() != 2 || bounds[0] == 0 || bounds[0] > bounds[1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ip_local_port_range",
            ));
        }
        Ok(bounds[0]..=bounds[1])
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(49_152..=65_535)
    }
}

/// Match the registry's mesh allocation floor, avoiding well-known/service
/// ports. Never fall back to port zero when this candidate set is exhausted.
fn handoff_ports() -> io::Result<impl Iterator<Item = u16>> {
    let ephemeral = ephemeral_source_port_range()?;
    let candidates = (10_240..=u16::MAX).filter(move |port| !ephemeral.contains(port));
    Ok(process_registry()?.candidates(candidates))
}

fn reserve_tcp_listener() -> io::Result<(PortLease, std::net::TcpListener)> {
    process_registry()?.lease_with(handoff_ports()?, |port| {
        let listener = bind_tcp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        Ok((port, listener))
    })
}

/// Return a live listener and lease outside the host's ephemeral source range.
/// Reservations can be handed to a backend or released for a subprocess without
/// letting the kernel's automatic source-port allocator steal the handoff.
pub async fn reserve_port() -> io::Result<PortReservation> {
    let (lease, listener) = reserve_tcp_listener()?;
    listener.set_nonblocking(true)?;
    Ok(PortReservation {
        port: lease.port,
        listener: TcpListener::from_std(listener)?,
        lease: Arc::new(lease),
    })
}

/// Reserve a listener in a bounded range outside the host's ephemeral source
/// ports when a fixture must release and rebind the socket during startup.
pub fn reserve_port_in_range(ports: std::ops::Range<u16>) -> io::Result<PortReservation> {
    let ephemeral = ephemeral_source_port_range()?;
    let registry = process_registry()?;
    let candidates =
        registry.candidates(ports.filter(|port| *port >= 10_240 && !ephemeral.contains(port)));
    let (lease, listener) = registry.lease_with(candidates, |port| {
        let listener = bind_tcp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        Ok((port, listener))
    })?;
    listener.set_nonblocking(true)?;
    Ok(PortReservation {
        port: lease.port,
        listener: TcpListener::from_std(listener)?,
        lease: Arc::new(lease),
    })
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
/// until the backend is ready avoids it. A subprocess handoff releases only
/// the socket; the lease stays held until the test process exits, after the
/// gateway guard has killed and waited for its child.
pub struct UdpPortReservation {
    /// The reserved local port.
    pub port: u16,
    socket: UdpSocket,
    lease: Arc<PortLease>,
}

impl UdpPortReservation {
    /// Consume this reservation and return the held socket. The caller
    /// owns it from here on; the lease lasts until process exit.
    pub fn into_socket(self) -> UdpSocket {
        self.lease.retain_for_process();
        self.socket
    }

    /// Release the socket (freeing the port) and return just the port
    /// number. Use only when handing the port to a subprocess that will
    /// itself bind. The registry lease stays owned until process exit.
    pub fn drop_and_take_port(self) -> u16 {
        let port = self.lease.retain_for_process();
        drop(self.socket);
        port
    }

    /// Return the `SocketAddr` without releasing the socket.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }
}

/// Reserve a live UDP socket outside the source range, like [`reserve_port`].
pub async fn reserve_udp_port() -> io::Result<UdpPortReservation> {
    let (lease, socket) = process_registry()?.lease_with(handoff_ports()?, |port| {
        let socket = bind_udp_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        Ok((port, socket))
    })?;
    socket.set_nonblocking(true)?;
    Ok(UdpPortReservation {
        port: lease.port,
        socket: UdpSocket::from_std(socket)?,
        lease: Arc::new(lease),
    })
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
/// Strategy: bind TCP outside the source range, then bind UDP on that same
/// port. Retry on UDP conflict. TCP and UDP share the port namespace at
/// the kernel level without issue (different protocol numbers), so a UDP
/// bind at the same port generally succeeds on the first try.
pub async fn reserve_colocated_tcp_udp() -> io::Result<(PortReservation, UdpPortReservation)> {
    let (lease, (tcp, udp)) = process_registry()?.lease_with(handoff_ports()?, |port| {
        let tcp = bind_tcp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        let udp = bind_udp_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        Ok((port, (tcp, udp)))
    })?;
    tcp.set_nonblocking(true)?;
    udp.set_nonblocking(true)?;
    let lease = Arc::new(lease);
    Ok((
        PortReservation {
            port: lease.port,
            listener: TcpListener::from_std(tcp)?,
            lease: Arc::clone(&lease),
        },
        UdpPortReservation {
            port: lease.port,
            socket: UdpSocket::from_std(udp)?,
            lease,
        },
    ))
}

/// Reserve and immediately release a non-ephemeral port for a subprocess.
/// Connects to the returned port produce a genuine `ECONNREFUSED` at the kernel
/// level (nothing is listening), unlike
/// [`super::backends::tcp::TcpStep::RefuseNextConnect`] which accepts and
/// drops — that emits FIN/RST, not a connect-time refusal.
///
/// **OS race caveat**: The process lease excludes other participating tests,
/// but an unrelated OS process can still bind. For a held refused connect use
/// [`reserve_refused_tcp_port`] instead, which keeps the port bound
/// without listening.
pub async fn unbound_port() -> io::Result<u16> {
    unbound_tcp_port()
}

/// Synchronous gateway handoff for spawners that do not own a Tokio runtime.
pub fn unbound_tcp_port() -> io::Result<u16> {
    let (lease, listener) = reserve_tcp_listener()?;
    let port = lease.retain_for_process();
    drop(listener);
    Ok(port)
}

/// Whether a held [`RefusedTcpPort`] makes a connect fail IMMEDIATELY on this
/// host.
///
/// A bound-but-unlistened TCP socket answers a SYN with RST on Linux, so a
/// connect there fails at once with `ECONNREFUSED`. Darwin and the BSDs drop
/// the SYN instead: the port stays owned exactly the same way, but a connect
/// hangs until the client's own timeout (issue #4983). Ownership is the
/// reservation's guarantee on every host; the observable failure is not, so a
/// fixture must assert the category its host actually produces rather than
/// assuming Linux's.
pub const REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY: bool = cfg!(target_os = "linux");

/// A TCP port bound on `127.0.0.1` without `listen()`.
///
/// The socket stays held, so a parallel test cannot steal the port; drop the
/// reservation to release it. A connect fails with a kernel `ECONNREFUSED`
/// where [`REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY`] holds, and otherwise
/// black-holes until the caller's own deadline.
pub struct RefusedTcpPort {
    /// The reserved local port.
    pub port: u16,
    _socket: socket2::Socket,
    lease: PortLease,
}

impl RefusedTcpPort {
    /// Release a [`reserve_future_tcp_port`] reservation for a gateway handoff.
    /// Retain genuine refused-backend reservations instead of releasing them.
    pub fn drop_and_take_port(self) -> u16 {
        self.lease.retain_for_process()
    }

    /// Begin listening on this exact reservation without releasing its port.
    pub fn into_listener(self) -> io::Result<TcpListener> {
        self._socket.listen(1024)?;
        self._socket.set_nonblocking(true)?;
        self.lease.retain_for_process();
        TcpListener::from_std(self._socket.into())
    }

    /// Return the bound `SocketAddr` without releasing the socket.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }
}

fn bind_unlistened_tcp_port(port: u16) -> io::Result<(u16, socket2::Socket)> {
    let socket = bind_tcp_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("reserved address was not a socket address"))?
        .port();
    Ok((port, socket))
}

/// Bind `127.0.0.1:0` without listening. Retries transient bind failures
/// with the same budget as [`reserve_port`]; this is reservation retry, not
/// a whole-scenario retry-until-green loop.
pub fn reserve_refused_tcp_port() -> io::Result<RefusedTcpPort> {
    let (lease, socket) =
        process_registry()?.lease_with(std::iter::repeat_n(0, 256), bind_unlistened_tcp_port)?;
    Ok(RefusedTcpPort {
        port: lease.port,
        _socket: socket,
        lease,
    })
}

/// A future subprocess listener that must refuse connections before handoff.
/// Genuine refused-backend fixtures should keep using [`reserve_refused_tcp_port`].
pub fn reserve_future_tcp_port() -> io::Result<RefusedTcpPort> {
    let (lease, socket) =
        process_registry()?.lease_with(handoff_ports()?, bind_unlistened_tcp_port)?;
    Ok(RefusedTcpPort {
        port: lease.port,
        _socket: socket,
        lease,
    })
}

/// DTLS fixtures use the same registry and pass their held UDP socket to the server.
pub async fn bind_dtls(
    addr: SocketAddr,
    config: ferrum_edge::dtls::FrontendDtlsConfig,
) -> Result<ferrum_edge::dtls::DtlsServer, anyhow::Error> {
    let socket = UdpSocket::bind_test(addr).await?;
    Ok(ferrum_edge::dtls::DtlsServer::from_socket(socket, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
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

    /// Ownership is unconditional; the connect failure is host-shaped. Both
    /// halves are asserted explicitly so a host whose kernel changes behaviour
    /// fails here rather than silently degrading every consumer that treats
    /// this reservation as "a backend that is definitely down".
    #[tokio::test]
    async fn reserve_refused_tcp_port_fails_connect_and_cannot_be_stolen() {
        let reservation = reserve_refused_tcp_port().expect("reserve refused port");
        let port = reservation.port;
        let connect = tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
        )
        .await;
        if REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY {
            let err = connect
                .expect("a refusing host must not black-hole the connect")
                .expect_err("bound-but-not-listening port must refuse connect");
            assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        } else {
            assert!(
                connect.is_err(),
                "a host that drops the SYN must leave the connect pending, not complete it"
            );
        }
        let steal = TcpListener::bind_test(("127.0.0.1", port)).await;
        assert!(
            steal.is_err(),
            "held refused reservation must keep the port from being stolen"
        );
        drop(reservation);
    }
}
