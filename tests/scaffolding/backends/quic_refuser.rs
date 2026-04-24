//! `QuicRefuser` — a UDP listener that accepts the first datagram and
//! immediately answers with a QUIC `CONNECTION_CLOSE` (`NO_ERROR`).
//!
//! This is the key fixture for testing `mark_h3_unsupported`: a backend
//! that "used to speak H3 but stopped". The TCP port may still be open
//! (real backend has both H1 and H3), but attempts to establish QUIC never
//! succeed — probing classifies the target as H3-`Unsupported`.
//!
//! Implementation note: real QUIC `CONNECTION_CLOSE` requires TLS/crypto,
//! which is overkill for this fixture. Instead we use `quinn::Endpoint`
//! with a TLS config that has no ALPN overlap with the client's `h3`, so
//! quinn tears the handshake down at the transport layer, producing a
//! QUIC-level close error that exercises the gateway's H3 classifier. We
//! also offer a lower-level variant via [`QuicRefuser::start_alpn_mismatch`]
//! that uses an ALPN of `no-quic` specifically so the gateway's ALPN check
//! fails deterministically.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use quinn::Endpoint;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::http3::{H3TlsConfig, UdpSocketReservation};

/// A running QUIC "refuser" backend. Drop shuts it down.
pub struct QuicRefuser {
    pub addr: SocketAddr,
    endpoint: Endpoint,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    connections_seen: Arc<AtomicU32>,
}

impl QuicRefuser {
    /// Start a QUIC refuser that closes every incoming connection with
    /// `code=0` (`NO_ERROR`) immediately after accept. The UDP socket must
    /// be pre-bound via [`super::http3::reserve_udp_port`] to avoid the
    /// bind-drop-rebind race.
    pub fn start(
        reservation: UdpSocketReservation,
        tls: H3TlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_alpn(reservation, tls, vec![b"h3".to_vec()])
    }

    /// Start a QUIC refuser whose server ALPN is explicitly *not* `h3`, so
    /// the gateway's H3 handshake fails with an ALPN-mismatch class
    /// error. Useful when the test wants to exercise the "QUIC spoke to
    /// us but refused the H3 negotiation" path rather than a raw
    /// `CONNECTION_CLOSE`.
    pub fn start_alpn_mismatch(
        reservation: UdpSocketReservation,
        tls: H3TlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_alpn(reservation, tls, vec![b"no-h3".to_vec()])
    }

    fn start_with_alpn(
        reservation: UdpSocketReservation,
        tls: H3TlsConfig,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let udp: UdpSocket = reservation.into_socket();
        let addr = udp.local_addr()?;
        let server_config = Self::build_server_config(&tls, alpn)?;

        let std_udp = udp.into_std()?;
        std_udp.set_nonblocking(true)?;
        let runtime = quinn::default_runtime()
            .ok_or("quinn runtime not available; install a tokio runtime")?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            std_udp,
            runtime,
        )?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let endpoint_task = endpoint.clone();
        let connections_seen = Arc::new(AtomicU32::new(0));
        let counter = connections_seen.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        endpoint_task.close(0u32.into(), b"shutdown");
                        return;
                    }
                    incoming = endpoint_task.accept() => {
                        let Some(incoming) = incoming else {
                            return;
                        };
                        counter.fetch_add(1, Ordering::SeqCst);
                        // Accept, then immediately close with NO_ERROR.
                        // Doing it this way (rather than refuse()) gives
                        // the client a visible CONNECTION_CLOSE rather
                        // than a retry/drop, which is what `mark_h3_unsupported`
                        // scenarios want to observe.
                        tokio::spawn(async move {
                            match incoming.accept() {
                                Ok(conn_fut) => {
                                    if let Ok(conn) = conn_fut.await {
                                        conn.close(0u32.into(), b"refused");
                                    }
                                }
                                Err(_) => {
                                    // Rare: accept() can fail under
                                    // transport-level errors. Drop
                                    // silently; the client's handshake
                                    // fails the same way.
                                }
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            addr,
            endpoint,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
            connections_seen,
        })
    }

    fn build_server_config(
        tls: &H3TlsConfig,
        alpn: Vec<Vec<u8>>,
    ) -> Result<quinn::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let mut cert_reader = tls.cert_pem.as_bytes();
        let cert_chain: Vec<_> = certs(&mut cert_reader).filter_map(|c| c.ok()).collect();
        if cert_chain.is_empty() {
            return Err("no certificates in cert_pem".into());
        }
        let mut key_reader = tls.key_pem.as_bytes();
        let key = private_key(&mut key_reader)?.ok_or("no private key in key_pem")?;

        let provider = rustls::crypto::ring::default_provider();
        let mut server_tls_config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        server_tls_config.alpn_protocols = alpn;

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)
                .map_err(|e| format!("QuicServerConfig build failed: {e}"))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|e| format!("idle timeout: {e}"))?,
        ));
        server_config.transport_config(Arc::new(transport));
        Ok(server_config)
    }

    /// Port the refuser is listening on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Number of incoming QUIC connections this refuser observed.
    pub fn connections_seen(&self) -> u32 {
        self.connections_seen.load(Ordering::SeqCst)
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

impl Drop for QuicRefuser {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::backends::http3::reserve_udp_port;
    use crate::scaffolding::certs::TestCa;

    #[tokio::test]
    async fn start_reports_bind_address() {
        let ca = TestCa::new("refuser-test").expect("ca");
        let (cert, key) = ca.valid().expect("leaf");
        let reservation = reserve_udp_port().await.expect("udp");
        let expected_port = reservation.port;
        let refuser =
            QuicRefuser::start(reservation, H3TlsConfig::new(cert, key)).expect("refuser");
        assert_eq!(refuser.port(), expected_port);
        assert_eq!(refuser.connections_seen(), 0);
    }
}
