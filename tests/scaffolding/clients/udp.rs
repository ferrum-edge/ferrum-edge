//! Thin UDP client wrapper for scripted-backend tests.
//!
//! `UdpClient` wraps a `tokio::net::UdpSocket` connected to a target
//! `host:port` so the caller doesn't juggle bind + connect each time.
//! The API is deliberately minimal — `send_datagram` and
//! `recv_datagram_with_timeout` — because scripted-backend tests model
//! UDP as discrete datagrams, not streams.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// A UDP socket connected to a fixed peer. Binds `127.0.0.1:0` on
/// construction; drops the socket on drop (freeing the port).
pub struct UdpClient {
    socket: UdpSocket,
    peer: SocketAddr,
    /// `true` when `connect()` has been called. Controls whether
    /// [`UdpClient::send_datagram`] uses `send()` (connected) or
    /// `send_to()` (unconnected) — BSD sockets refuse `send_to` on a
    /// connected socket with EISCONN.
    connected: bool,
}

impl UdpClient {
    /// Bind an ephemeral local port and connect the socket to `peer`.
    /// `UdpSocket::connect` just sets the default send destination; the
    /// kernel still accepts datagrams from other sources unless filtered.
    pub async fn connect(peer: impl Into<SocketAddr>) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let peer = peer.into();
        socket.connect(peer).await?;
        Ok(Self {
            socket,
            peer,
            connected: true,
        })
    }

    /// Bind an ephemeral port without calling `connect`. `send_datagram`
    /// then uses `send_to(peer)` so the caller can redirect where each
    /// datagram goes by swapping `peer` if needed. Added for tests that
    /// exercise passthrough-SNI flows where the gateway hands every
    /// datagram to the same backend regardless of source pinning.
    pub async fn bind(peer: impl Into<SocketAddr>) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Self {
            socket,
            peer: peer.into(),
            connected: false,
        })
    }

    /// The ephemeral local address the client bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The peer address the client was constructed against.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Send one datagram to the configured peer. Uses `send()` on a
    /// connected socket, `send_to(peer)` otherwise. Returns the number
    /// of bytes sent (usually == `bytes.len()`).
    pub async fn send_datagram(&self, bytes: &[u8]) -> io::Result<usize> {
        if self.connected {
            self.socket.send(bytes).await
        } else {
            self.socket.send_to(bytes, self.peer).await
        }
    }

    /// Wait up to `deadline` for a datagram. On timeout returns
    /// `io::ErrorKind::TimedOut`. Returns the datagram bytes (allocated
    /// fresh) — the caller doesn't need to manage a buffer.
    pub async fn recv_datagram_with_timeout(&self, deadline: Duration) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(deadline, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _src))) => {
                buf.truncate(n);
                Ok(buf)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "udp recv timed out",
            )),
        }
    }

    /// Collect up to `expected` datagrams or until `deadline` expires.
    /// Useful for amplification tests where the test asserts on the
    /// total count of received datagrams.
    pub async fn recv_batch_with_deadline(
        &self,
        expected: usize,
        deadline: Duration,
    ) -> Vec<Vec<u8>> {
        let overall_deadline = tokio::time::Instant::now() + deadline;
        let mut out = Vec::with_capacity(expected);
        let mut buf = vec![0u8; 65535];
        loop {
            if out.len() >= expected {
                break;
            }
            let now = tokio::time::Instant::now();
            if now >= overall_deadline {
                break;
            }
            let remaining = overall_deadline - now;
            match tokio::time::timeout(remaining, self.socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    out.push(buf[..n].to_vec());
                }
                _ => break,
            }
        }
        out
    }

    /// Expose the raw socket — for tests that need `send_to` with a
    /// different target, or direct `recv_from` semantics.
    pub fn as_socket(&self) -> &UdpSocket {
        &self.socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_udp_port;

    #[tokio::test]
    async fn udp_client_round_trip() {
        // Set up a tiny echo server for the client to talk to.
        let reservation = reserve_udp_port().await.expect("reserve");
        let server_port = reservation.port;
        let server = reservation.into_socket();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((n, src)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&buf[..n], src).await;
            }
        });

        let client: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
        let client = UdpClient::connect(client).await.expect("client");
        let sent = client.send_datagram(b"hello").await.expect("send");
        assert_eq!(sent, 5);

        let got = client
            .recv_datagram_with_timeout(Duration::from_secs(2))
            .await
            .expect("recv");
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn udp_client_recv_timeout_surfaces_as_timed_out() {
        // Send to an unconnected address; no server, so recv times out.
        let port = crate::scaffolding::ports::unbound_udp_port()
            .await
            .expect("port");
        let peer: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = UdpClient::connect(peer).await.expect("client");
        let err = client
            .recv_datagram_with_timeout(Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
