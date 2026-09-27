//! Inbound PROXY protocol on the global HTTP/HTTPS proxy listeners (issue #5768).
//!
//! These tests drive the production accept loop
//! (`start_proxy_listener_with_bound_listener_and_proxy_protocol`) with the
//! policy the modes build from `EnvConfig`, and pin:
//!
//! * v1 and v2 headers from a trusted load balancer set the client address,
//!   over plaintext and in front of the TLS ClientHello
//! * the PROXY source replaces the socket peer, so `FERRUM_TRUSTED_PROXIES` is
//!   evaluated against the real client and never the load balancer
//! * a `LOCAL` health-check header keeps the load balancer as the peer
//! * untrusted peers, missing / malformed / wrong-version / stalled headers
//!   are closed with no response and never reach the backend
//! * a listener with the setting `off` is unchanged
//! * the bind-by-address dynamic-TLS entry point the database and DP modes use
//!   carries the policy into every accept loop

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::env_config::FrontendProxyProtocolMode as Mode;
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::frontend_proxy_protocol::{
    FrontendProxyListener, FrontendProxyProtocol, global_listener_policies,
};
use ferrum_edge::proxy::proxy_protocol::encode_v2_proxy_header;
use ferrum_edge::proxy::{
    ProxyState, start_global_proxy_listener_with_dynamic_tls_and_signal,
    start_proxy_listener_with_bound_listener_and_proxy_protocol,
};
use ferrum_edge::tls::SharedFrontendTls;

#[path = "../../scaffolding/port_registry.rs"]
#[allow(dead_code)] // shared allocator; this target uses only the lease API
mod port_registry;
#[allow(dead_code)]
#[path = "../../scaffolding/ports.rs"]
mod ports;

/// Upper bound for any single expected outcome. The header deadline is 5s, so
/// a stalled-header close must land inside this window too.
const WINDOW: Duration = Duration::from_secs(10);
const CLIENT: &str = "203.0.113.7";
const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
/// First bytes of a direct client's TLS ClientHello (handshake record, TLS 1.0
/// record version, then the ClientHello message type); not a PROXY signature.
const TLS_RECORD_PREFIX: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
/// Accept loops sharing one listen socket in the multi-loop test.
const ACCEPT_THREADS: usize = 4;
/// Connections per scenario in the multi-loop test, so each accept loop is
/// likely to take at least one of them.
const ACCEPT_LOOP_PROBES: usize = 16;

struct Backend {
    port: u16,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

/// HTTP/1.1 backend that answers `xff=<X-Forwarded-For>` and counts requests.
async fn start_echo_backend() -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let port = listener.local_addr().expect("backend addr").port();
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let xff = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>")
                        .to_string();
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from(format!("xff={xff}"))))
                                .expect("backend response"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Backend {
        port,
        requests,
        task,
    }
}

struct Gateway {
    addr: SocketAddr,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

impl Gateway {
    /// Start one global proxy listener. `mode` / `trusted_cidrs` feed the same
    /// `EnvConfig` fields the env vars do, and the policy is built exactly as
    /// the modes build it.
    async fn start(
        backend_port: u16,
        listener_kind: FrontendProxyListener,
        mode: Mode,
        trusted_cidrs: &str,
        trusted_proxies: &str,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        let env = listener_env(listener_kind, mode, trusted_cidrs, trusted_proxies);
        let policy = FrontendProxyProtocol::for_listener(&env, listener_kind)
            .expect("valid PROXY protocol policy");
        assert_eq!(
            policy.is_some(),
            mode.is_enabled(),
            "a policy exists exactly when the listener enables PROXY protocol"
        );
        let state = proxy_state(backend_port, env);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy listener");
        let addr = listener.local_addr().expect("proxy listener addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(async move {
            start_proxy_listener_with_bound_listener_and_proxy_protocol(
                listener,
                state,
                shutdown_rx,
                tls_config,
                policy,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        Self {
            addr,
            shutdown_tx,
            server,
        }
    }

    async fn plain(
        backend_port: u16,
        mode: Mode,
        trusted_cidrs: &str,
        trusted_proxies: &str,
    ) -> Self {
        Self::start(
            backend_port,
            FrontendProxyListener::Http,
            mode,
            trusted_cidrs,
            trusted_proxies,
            None,
        )
        .await
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.addr)
            .await
            .expect("connect proxy listener")
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.server).await;
    }
}

/// `EnvConfig` for one global proxy listener. `mode` / `trusted_cidrs` feed the
/// same fields the env vars do.
fn listener_env(
    listener_kind: FrontendProxyListener,
    mode: Mode,
    trusted_cidrs: &str,
    trusted_proxies: &str,
) -> EnvConfig {
    let (http_mode, https_mode) = match listener_kind {
        FrontendProxyListener::Http => (mode, Mode::Off),
        FrontendProxyListener::Https => (Mode::Off, mode),
    };
    EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "error".into(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        max_connections: 0,
        shutdown_drain_seconds: 1,
        trusted_proxies: trusted_proxies.to_string(),
        frontend_proxy_protocol_http: http_mode,
        frontend_proxy_protocol_https: https_mode,
        frontend_proxy_protocol_trusted_cidrs: trusted_cidrs.to_string(),
        ..EnvConfig::default()
    }
}

/// Proxy state with one route, `/pp`, to the echo backend on `backend_port`.
fn proxy_state(backend_port: u16, env: EnvConfig) -> ProxyState {
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "pp-listener",
        "listen_path": "/pp",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false
    }))
    .expect("test proxy");
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
        .expect("proxy state")
        .0
}

fn v1_header(src: &str) -> Vec<u8> {
    format!("PROXY TCP4 {src} 10.0.0.1 40000 443\r\n").into_bytes()
}

fn v2_header(src: &str) -> Vec<u8> {
    let src: SocketAddr = format!("{src}:40000").parse().expect("v2 src");
    let dst: SocketAddr = "10.0.0.1:443".parse().expect("v2 dst");
    encode_v2_proxy_header(src, dst)
}

/// A PROXY v2 `LOCAL` header (load-balancer health check): no address block.
fn v2_local_header() -> Vec<u8> {
    let mut header = V2_SIG.to_vec();
    header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    header
}

fn get_request(extra_headers: &str) -> Vec<u8> {
    format!("GET /pp HTTP/1.1\r\nHost: localhost\r\n{extra_headers}Connection: close\r\n\r\n")
        .into_bytes()
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
    stream.write_all(bytes).await.expect("write");
    stream.flush().await.expect("flush");
}

/// Read until the server closes, returning everything received.
async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut buf = Vec::new();
    let read = tokio::time::timeout(WINDOW, stream.read_to_end(&mut buf));
    match read.await {
        Ok(Ok(_)) => {}
        // A reset after a complete response still counts as the response.
        Ok(Err(_)) if !buf.is_empty() => {}
        Ok(Err(e)) => panic!("reading response failed: {e}"),
        Err(_) => panic!("no response within the deadline"),
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Assert the gateway closed the connection without sending a single byte.
async fn assert_closed_without_response<S: AsyncRead + Unpin>(stream: &mut S, context: &str) {
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(WINDOW, stream.read(&mut buf));
    let Ok(result) = read.await else {
        panic!("{context}: still open after the deadline");
    };
    match result {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(n) => panic!(
            "{context}: expected a silent close, got {n} bytes: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(e) => panic!("{context}: expected EOF or reset, got {e:?}"),
    }
}

/// The `X-Forwarded-For` value the echo backend reported, whether the gateway
/// relayed the body with a length or chunked.
fn backend_xff(response: &str) -> Option<&str> {
    let start = response.find("xff=")? + "xff=".len();
    response[start..].split(['\r', '\n']).next()
}

fn assert_ok_with_xff(response: &str, expected_xff: &str) {
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected a 200 through the gateway, got: {response:?}"
    );
    assert_eq!(
        backend_xff(response),
        Some(expected_xff),
        "backend must see X-Forwarded-For {expected_xff:?}, got: {response:?}"
    );
}

async fn plaintext_round_trip(gateway: &Gateway, header: &[u8], extra_headers: &str) -> String {
    let mut stream = gateway.connect().await;
    let mut opening = header.to_vec();
    opening.extend_from_slice(&get_request(extra_headers));
    send(&mut stream, &opening).await;
    read_response(&mut stream).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v1_header_from_trusted_peer_sets_client_address() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::V1, "127.0.0.1", "").await;

    let response = plaintext_round_trip(&gateway, &v1_header(CLIENT), "").await;
    assert_ok_with_xff(&response, CLIENT);

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_header_from_trusted_peer_sets_client_address() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::V2, "127.0.0.1", "").await;

    let response = plaintext_round_trip(&gateway, &v2_header(CLIENT), "").await;
    assert_ok_with_xff(&response, CLIENT);

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_mode_accepts_both_versions() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "127.0.0.0/8", "").await;

    let response = plaintext_round_trip(&gateway, &v1_header(CLIENT), "").await;
    assert_ok_with_xff(&response, CLIENT);
    let response = plaintext_round_trip(&gateway, &v2_header("198.51.100.9"), "").await;
    assert_ok_with_xff(&response, "198.51.100.9");

    gateway.shutdown().await;
    backend.task.abort();
}

/// The load balancer being in `FERRUM_TRUSTED_PROXIES` must not make a
/// client-supplied `X-Forwarded-For` believable: the PROXY source replaced the
/// socket peer, and that source is not trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_balancer_trust_never_leaks_into_forwarded_for_trust() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "127.0.0.1", "127.0.0.1").await;

    let response = plaintext_round_trip(
        &gateway,
        &v1_header(CLIENT),
        "X-Forwarded-For: 198.51.100.1\r\n",
    )
    .await;
    assert_ok_with_xff(&response, CLIENT);

    gateway.shutdown().await;
    backend.task.abort();
}

/// `FERRUM_TRUSTED_PROXIES` is evaluated against the PROXY source: when that
/// source is a trusted hop (e.g. a CDN in front of the L4 balancer), its
/// `X-Forwarded-For` is honoured exactly as for a direct connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarded_for_is_trusted_only_through_the_proxy_source() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "127.0.0.1", "203.0.113.0/24").await;

    let response = plaintext_round_trip(
        &gateway,
        &v1_header(CLIENT),
        "X-Forwarded-For: 198.51.100.1\r\n",
    )
    .await;
    assert_ok_with_xff(&response, &format!("198.51.100.1, {CLIENT}"));

    gateway.shutdown().await;
    backend.task.abort();
}

/// A v2 `LOCAL` command (load-balancer health check) carries no client, so the
/// load balancer's own socket address stays the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_command_keeps_the_socket_peer() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::V2, "127.0.0.1", "").await;

    let response = plaintext_round_trip(&gateway, &v2_local_header(), "").await;
    assert_ok_with_xff(&response, "127.0.0.1");

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_peer_is_dropped_before_any_read() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "10.0.0.0/8", "").await;

    let mut stream = gateway.connect().await;
    let mut opening = v1_header(CLIENT);
    opening.extend_from_slice(&get_request(""));
    // The write may already fail against the dropped socket; the read decides.
    let _ = stream.write_all(&opening).await;
    assert_closed_without_response(&mut stream, "untrusted peer").await;
    assert_eq!(backend.requests.load(Ordering::SeqCst), 0);

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_header_is_refused() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "127.0.0.1", "").await;

    let mut stream = gateway.connect().await;
    send(&mut stream, &get_request("")).await;
    assert_closed_without_response(&mut stream, "request without a PROXY header").await;
    assert_eq!(backend.requests.load(Ordering::SeqCst), 0);

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_header_is_refused() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "127.0.0.1", "").await;

    for header in [
        b"PROXY TCP4 not-an-ip 10.0.0.1 40000 443\r\n".to_vec(),
        b"PROXY TCP4 203.0.113.7 10.0.0.1 40000\r\n".to_vec(),
        // An address-family mismatch the spec forbids.
        b"PROXY TCP4 2001:db8::1 10.0.0.1 40000 443\r\n".to_vec(),
    ] {
        let mut stream = gateway.connect().await;
        let mut opening = header.clone();
        opening.extend_from_slice(&get_request(""));
        send(&mut stream, &opening).await;
        assert_closed_without_response(&mut stream, "malformed PROXY header").await;
    }
    assert_eq!(backend.requests.load(Ordering::SeqCst), 0);

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_pinned_listener_refuses_the_other_version() {
    let backend = start_echo_backend().await;

    let v1_only = Gateway::plain(backend.port, Mode::V1, "127.0.0.1", "").await;
    let mut stream = v1_only.connect().await;
    let mut opening = v2_header(CLIENT);
    opening.extend_from_slice(&get_request(""));
    send(&mut stream, &opening).await;
    assert_closed_without_response(&mut stream, "v2 header on a v1 listener").await;
    v1_only.shutdown().await;

    let v2_only = Gateway::plain(backend.port, Mode::V2, "127.0.0.1", "").await;
    let mut stream = v2_only.connect().await;
    let mut opening = v1_header(CLIENT);
    opening.extend_from_slice(&get_request(""));
    send(&mut stream, &opening).await;
    assert_closed_without_response(&mut stream, "v1 header on a v2 listener").await;
    v2_only.shutdown().await;

    assert_eq!(backend.requests.load(Ordering::SeqCst), 0);
    backend.task.abort();
}

/// A trusted peer that never completes its header is closed by the header
/// deadline instead of pinning a connection slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_header_is_closed_by_the_deadline() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Auto, "127.0.0.1", "").await;

    let mut stream = gateway.connect().await;
    send(&mut stream, b"PROXY TCP4 203.0.113.7").await;
    assert_closed_without_response(&mut stream, "stalled PROXY header").await;
    assert_eq!(backend.requests.load(Ordering::SeqCst), 0);

    gateway.shutdown().await;
    backend.task.abort();
}

/// With the setting `off` the listener is unchanged: a PROXY header is just a
/// malformed HTTP request line, and a plain request is served from the socket
/// peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_listener_behaviour_is_unchanged() {
    let backend = start_echo_backend().await;
    let gateway = Gateway::plain(backend.port, Mode::Off, "", "").await;

    let response = plaintext_round_trip(&gateway, &v1_header(CLIENT), "").await;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "a PROXY header on a disabled listener stays a 400, got: {response:?}"
    );

    let response = plaintext_round_trip(&gateway, b"", "").await;
    assert_ok_with_xff(&response, "127.0.0.1");

    gateway.shutdown().await;
    backend.task.abort();
}

fn frontend_tls_pair() -> (Arc<rustls::ServerConfig>, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key = KeyPair::generate_for(ecdsa).expect("PROXY test CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(ecdsa).expect("PROXY test leaf key");
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign PROXY test leaf");

    let certs = CertificateDer::pem_slice_iter(leaf_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse PROXY test leaf certificate");
    let key = PrivateKeyDer::from_pem_slice(leaf_key.serialize_pem().as_bytes())
        .expect("parse PROXY test leaf key");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("PROXY test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("PROXY test TLS server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    (Arc::new(server_config), ca_pem)
}

/// Write `header` on a fresh TCP connection, then run the TLS handshake over
/// the same socket — the order an L4 balancer uses in front of HTTPS.
async fn tls_connect_after_header(
    addr: SocketAddr,
    ca_pem: &str,
    header: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots
            .add(cert.expect("parse PROXY test CA certificate"))
            .expect("add PROXY test CA to roots");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("PROXY test client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut tcp = TcpStream::connect(addr).await.expect("connect TLS");
    send(&mut tcp, header).await;
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(name, tcp)
        .await
        .expect("frontend TLS handshake after the PROXY header")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_listener_reads_the_header_before_the_client_hello() {
    let backend = start_echo_backend().await;
    let (tls_config, ca_pem) = frontend_tls_pair();
    let gateway = Gateway::start(
        backend.port,
        FrontendProxyListener::Https,
        Mode::V2,
        "127.0.0.1",
        "",
        Some(tls_config),
    )
    .await;

    let mut tls = tls_connect_after_header(gateway.addr, &ca_pem, &v2_header(CLIENT)).await;
    send(&mut tls, &get_request("")).await;
    let response = read_response(&mut tls).await;
    assert_ok_with_xff(&response, CLIENT);

    gateway.shutdown().await;
    backend.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_listener_refuses_a_client_hello_without_a_header() {
    let backend = start_echo_backend().await;
    let (tls_config, _ca_pem) = frontend_tls_pair();
    let gateway = Gateway::start(
        backend.port,
        FrontendProxyListener::Https,
        Mode::Auto,
        "127.0.0.1",
        "",
        Some(tls_config),
    )
    .await;

    let mut stream = gateway.connect().await;
    send(&mut stream, TLS_RECORD_PREFIX).await;
    assert_closed_without_response(&mut stream, "ClientHello without a PROXY header").await;
    assert_eq!(backend.requests.load(Ordering::SeqCst), 0);

    gateway.shutdown().await;
    backend.task.abort();
}

/// Start the global HTTPS listener the way the database and DP modes do: bound
/// by address through the dynamic-TLS entry point, with [`ACCEPT_THREADS`]
/// accept loops sharing the socket and the policy from
/// `global_listener_policies`.
async fn start_dynamic_tls_gateway(
    backend_port: u16,
    trusted_cidrs: &str,
    tls_config: Arc<rustls::ServerConfig>,
) -> Gateway {
    let env = EnvConfig {
        accept_threads: ACCEPT_THREADS,
        ..listener_env(FrontendProxyListener::Https, Mode::V2, trusted_cidrs, "")
    };
    let policy = global_listener_policies(&env)
        .expect("valid PROXY protocol policies")
        .https;
    assert!(policy.is_some(), "the HTTPS listener enables PROXY protocol");
    let state = proxy_state(backend_port, env);
    let slot: SharedFrontendTls = Arc::new(ArcSwap::new(Arc::new(Some(tls_config))));

    for attempt in 1..=5 {
        let port = ports::reserve_port()
            .await
            .expect("reserve proxy port")
            .drop_and_take_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(start_global_proxy_listener_with_dynamic_tls_and_signal(
            addr,
            state.clone(),
            shutdown_rx,
            Arc::clone(&slot),
            policy.clone(),
            Some(started_tx),
        ));
        if let Ok(Ok(())) = tokio::time::timeout(WINDOW, started_rx).await {
            return Gateway {
                addr,
                shutdown_tx,
                server,
            };
        }
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
        eprintln!("dynamic-TLS listener attempt {attempt} did not start; retrying");
    }
    panic!("dynamic-TLS listener did not bind after retries");
}

/// The database and DP modes serve HTTPS through
/// `start_global_proxy_listener_with_dynamic_tls_and_signal` with several
/// accept loops. Whichever loop accepts a connection must enforce the policy:
/// a trusted balancer's header source becomes the client, and an untrusted
/// peer is dropped without a response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_tls_listener_enforces_the_policy_on_every_accept_loop() {
    let backend = start_echo_backend().await;
    let (tls_config, ca_pem) = frontend_tls_pair();

    let gateway = start_dynamic_tls_gateway(backend.port, "127.0.0.1", tls_config.clone()).await;
    for i in 0..ACCEPT_LOOP_PROBES {
        let client = format!("203.0.113.{}", i + 1);
        let header = v2_header(&client);
        let mut tls = tls_connect_after_header(gateway.addr, &ca_pem, &header).await;
        send(&mut tls, &get_request("")).await;
        let response = read_response(&mut tls).await;
        assert_ok_with_xff(&response, &client);
    }
    gateway.shutdown().await;

    let gateway = start_dynamic_tls_gateway(backend.port, "10.0.0.0/8", tls_config).await;
    for _ in 0..ACCEPT_LOOP_PROBES {
        let mut stream = gateway.connect().await;
        // The write may already fail against the dropped socket; the read decides.
        let _ = stream.write_all(&v2_header(CLIENT)).await;
        assert_closed_without_response(&mut stream, "untrusted peer, dynamic TLS").await;
    }
    gateway.shutdown().await;

    assert_eq!(
        backend.requests.load(Ordering::SeqCst),
        ACCEPT_LOOP_PROBES,
        "only the trusted balancer's connections reach the backend"
    );
    backend.task.abort();
}
