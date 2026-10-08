//! HTTP/3 frontend QUIC admission, driven through a real listener.
//!
//! - The listener must not advertise the QUIC DATAGRAM extension: nothing in
//!   the gateway reads QUIC datagrams, and an undrained receive queue is held
//!   for the connection's lifetime outside QUIC flow control.
//! - A client whose source address is unvalidated is sent a stateless Retry
//!   once the listener's unvalidated-handshake budget is full (`0` here), and
//!   completes the handshake after echoing the token. Within the budget no
//!   Retry is sent. Either way the shared overload connection counter is
//!   charged exactly once for an established connection and released when it
//!   closes.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::http3::address_validation::H3_MAX_UNVALIDATED_HANDSHAKES_DEFAULT;
use ferrum_edge::http3::config::Http3ServerConfig;
use ferrum_edge::http3::server::{Http3ListenerOptions, start_http3_listener_with_signal};
use ferrum_edge::proxy::ProxyState;

use crate::scaffolding::certs::TestCa;
use crate::scaffolding::port_registry::TestSocket;
use crate::scaffolding::ports::reserve_udp_port;

fn ensure_crypto_provider_installed() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn server_tls_config(ca: &TestCa) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::PrivateKeyDer;

    let (cert_pem, key_pem) = ca.valid().expect("test leaf cert");
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .filter_map(|c| c.ok())
            .collect();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("parse key");

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("with_single_cert");
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn server_tls_policy() -> ferrum_edge::tls::TlsPolicy {
    ferrum_edge::tls::TlsPolicy {
        protocol_versions: vec![&rustls::version::TLS13],
        crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        prefer_server_cipher_order: true,
        session_cache_size: 4096,
        early_data_max_size: 0,
    }
}

struct H3Listener {
    addr: SocketAddr,
    state: ProxyState,
    ca: TestCa,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl H3Listener {
    async fn start(max_unvalidated_handshakes: usize) -> Self {
        ensure_crypto_provider_installed();

        let ca = TestCa::new("h3-quic-admission").expect("test CA");
        let tls_config = server_tls_config(&ca);
        let tls_policy = server_tls_policy();
        let env_config = EnvConfig {
            mode: ferrum_edge::config::env_config::OperatingMode::File,
            enable_http3: true,
            max_connections: 0,
            shutdown_drain_seconds: 0,
            ..EnvConfig::default()
        };
        let (state, _handles) = ProxyState::new(
            GatewayConfig::default(),
            DnsCache::new(DnsConfig::default()),
            env_config,
            None,
            None,
        )
        .expect("proxy state");
        let h3_config = Http3ServerConfig {
            max_unvalidated_handshakes,
            ..Http3ServerConfig::default()
        };

        let port = reserve_udp_port().await.expect("reserve udp port").drop_and_take_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let listener_state = state.clone();
        let task = tokio::spawn(async move {
            let result = start_http3_listener_with_signal(
                addr,
                listener_state,
                shutdown_rx,
                tls_config,
                h3_config,
                &tls_policy,
                Http3ListenerOptions {
                    started_tx: Some(started_tx),
                    ..Http3ListenerOptions::default()
                },
            )
            .await;
            if let Err(error) = result {
                panic!("HTTP/3 listener failed: {error}");
            }
        });
        tokio::time::timeout(Duration::from_secs(10), started_rx)
            .await
            .expect("HTTP/3 listener did not start")
            .expect("HTTP/3 listener exited before starting");

        Self {
            addr,
            state,
            ca,
            shutdown_tx,
            task,
        }
    }

    fn active_connections(&self) -> u64 {
        self.state.overload.active_connections.load(Ordering::Relaxed)
    }

    async fn wait_for_active_connections(&self, expected: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.active_connections() != expected {
            assert!(
                tokio::time::Instant::now() < deadline,
                "active_connections stayed at {} (expected {expected})",
                self.active_connections()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("HTTP/3 listener did not exit")
            .expect("HTTP/3 listener task panicked");
    }
}

/// A QUIC v1 long-header packet whose type bits are `0b11` is a Retry
/// (RFC 9000 §17.2.5): form bit, fixed bit, and type `0x3`.
fn is_quic_v1_retry(first_byte: u8) -> bool {
    (first_byte & 0xF0) == 0xF0
}

/// Client UDP socket that counts the Retry packets it receives.
#[derive(Debug)]
struct RetryCountingSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    retries: Arc<AtomicUsize>,
}

impl quinn::AsyncUdpSocket for RetryCountingSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let poll = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(received)) = &poll {
            for (buf, slot) in bufs.iter().zip(meta.iter()).take(*received) {
                let bytes: &[u8] = buf;
                for offset in (0..slot.len).step_by(slot.stride.max(1)) {
                    if bytes.get(offset).copied().is_some_and(is_quic_v1_retry) {
                        self.retries.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        poll
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct H3TestClient {
    endpoint: quinn::Endpoint,
    retries: Arc<AtomicUsize>,
}

impl H3TestClient {
    fn new(ca: &TestCa) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca.cert_pem.as_bytes()) {
            roots.add(cert.expect("CA cert")).expect("add CA cert");
        }
        let provider = rustls::crypto::ring::default_provider();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client config");

        let socket = std::net::UdpSocket::bind_test(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind client socket");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let runtime = quinn::default_runtime().expect("tokio runtime");
        let retries = Arc::new(AtomicUsize::new(0));
        let socket: Arc<dyn quinn::AsyncUdpSocket> = Arc::new(RetryCountingSocket {
            inner: runtime.wrap_udp_socket(socket).expect("wrap client socket"),
            retries: Arc::clone(&retries),
        });
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .expect("client endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        Self { endpoint, retries }
    }

    async fn connect(&self, addr: SocketAddr) -> quinn::Connection {
        let connecting = self.endpoint.connect(addr, "localhost").expect("connect");
        tokio::time::timeout(Duration::from_secs(10), connecting)
            .await
            .expect("QUIC handshake timed out")
            .expect("QUIC handshake")
    }

    fn retries_received(&self) -> usize {
        self.retries.load(Ordering::Relaxed)
    }
}

/// One HTTP/3 GET on `connection`; the listener has no routes, so a served
/// request is a 404.
async fn h3_get_status(connection: quinn::Connection, port: u16) -> http::StatusCode {
    let h3_connection = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) = h3::client::new(h3_connection).await.expect("h3 client");
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let uri = format!("https://localhost:{port}/");
    let request = http::Request::get(uri).body(()).expect("request");
    let mut stream = send_request.send_request(request).await.expect("send request");
    stream.finish().await.expect("finish request");
    let response = tokio::time::timeout(Duration::from_secs(10), stream.recv_response())
        .await
        .expect("response timed out")
        .expect("response");
    driver_task.abort();
    response.status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_listener_does_not_advertise_quic_datagrams() {
    let listener = H3Listener::start(H3_MAX_UNVALIDATED_HANDSHAKES_DEFAULT).await;
    let client = H3TestClient::new(&listener.ca);
    let connection = client.connect(listener.addr).await;

    assert_eq!(
        connection.max_datagram_size(),
        None,
        "the HTTP/3 listener must not advertise max_datagram_frame_size"
    );
    assert!(
        matches!(
            connection.send_datagram(Bytes::new()),
            Err(quinn::SendDatagramError::UnsupportedByPeer)
        ),
        "a peer must not be able to queue QUIC datagrams on the listener"
    );

    // The connection still serves HTTP/3.
    let status = h3_get_status(connection.clone(), listener.addr.port()).await;
    assert_eq!(status, http::StatusCode::NOT_FOUND);

    connection.close(0u32.into(), b"done");
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_listener_retries_unvalidated_clients_when_the_handshake_budget_is_full() {
    let listener = H3Listener::start(0).await;
    let client = H3TestClient::new(&listener.ca);
    let connection = client.connect(listener.addr).await;

    assert_eq!(
        client.retries_received(),
        1,
        "an unvalidated client must be sent exactly one stateless Retry when the budget is 0"
    );
    // The validated retried connection is charged to the shared budget once.
    listener.wait_for_active_connections(1).await;

    let status = h3_get_status(connection.clone(), listener.addr.port()).await;
    assert_eq!(status, http::StatusCode::NOT_FOUND);

    connection.close(0u32.into(), b"done");
    listener.wait_for_active_connections(0).await;
    listener.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_listener_admits_unvalidated_clients_within_the_handshake_budget() {
    let listener = H3Listener::start(H3_MAX_UNVALIDATED_HANDSHAKES_DEFAULT).await;
    let client = H3TestClient::new(&listener.ca);
    let connection = client.connect(listener.addr).await;

    assert_eq!(
        client.retries_received(),
        0,
        "a client within the unvalidated-handshake budget must not be sent a Retry"
    );
    // Charged to the shared budget once its handshake completed.
    listener.wait_for_active_connections(1).await;

    let status = h3_get_status(connection.clone(), listener.addr.port()).await;
    assert_eq!(status, http::StatusCode::NOT_FOUND);

    connection.close(0u32.into(), b"done");
    listener.wait_for_active_connections(0).await;
    listener.shutdown().await;
}
