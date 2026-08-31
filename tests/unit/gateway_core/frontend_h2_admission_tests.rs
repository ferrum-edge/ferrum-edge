//! Data-plane HTTP frontend pre-request admission (issue #4152).
//!
//! HTTP/1.1 already had `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS`. The auto
//! builder's version sniff and HTTP/2 SETTINGS/header windows did not. These
//! tests drive the production accept loop (`start_proxy_listener_with_bound_listener`)
//! and pin:
//!
//! * a peer that sends nothing (or one preface byte) is closed within the bound
//! * h2c preface + SETTINGS with no request is closed
//! * an incomplete HTTP/2 HEADERS block is closed
//! * the same bound applies behind TLS after the handshake
//! * a complete request inside the window is served
//! * idle HTTP/2 keep-alive after the first request is **not** killed
//! * `0` disables the bound
//! * stalled connections release `OverloadState.active_connections`

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener};

const SHORT: u64 = 1;
const LONG: u64 = 30;
const WINDOW: Duration = Duration::from_secs(8);

struct ProxyHarness {
    addr: SocketAddr,
    state: ProxyState,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

impl ProxyHarness {
    async fn start(
        header_read_timeout_seconds: u64,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        backend_port: u16,
    ) -> Self {
        let env = ferrum_edge::config::EnvConfig {
            mode: ferrum_edge::config::env_config::OperatingMode::File,
            log_level: "error".into(),
            proxy_http_port: 0,
            proxy_https_port: 0,
            admin_http_port: 0,
            admin_https_port: 0,
            max_connections: 0,
            http_header_read_timeout_seconds: header_read_timeout_seconds,
            shutdown_drain_seconds: 2,
            ..ferrum_edge::config::EnvConfig::default()
        };
        let proxy: Proxy = serde_json::from_value(json!({
            "id": "h2-admission",
            "listen_path": "/slow",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false
        }))
        .expect("test proxy");
        let config = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![proxy],
            consumers: vec![],
            plugin_configs: vec![],
            upstreams: vec![],
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            frontend_tls_source_namespace: None,
            frontend_tls_certificate_sources: Vec::new(),
            trust_bundles: None,
            mesh: None,
            http_tls_listen_ports: Default::default(),
            mesh_revision: None,
            node_waypoint_udp_steer_destinations: Vec::new(),
            node_waypoint_udp_destination_routes: Vec::new(),
            k8s_mesh_overlay: Default::default(),
            gateway_trust_bundles: Vec::new(),
        };
        let state = ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
            .expect("proxy state")
            .0;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy listener");
        let addr = listener.local_addr().expect("proxy listener addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let listener_state = state.clone();
        let server = tokio::spawn(async move {
            start_proxy_listener_with_bound_listener(
                listener,
                listener_state,
                shutdown_rx,
                tls_config,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        Self {
            addr,
            state,
            shutdown_tx,
            server,
        }
    }

    async fn start_plain(header_read_timeout_seconds: u64, backend_port: u16) -> Self {
        Self::start(header_read_timeout_seconds, None, backend_port).await
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

async fn start_ok_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admission backend");
    let port = listener.local_addr().expect("backend addr").port();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .expect("backend response"),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (port, handle)
}

fn frontend_tls_pair() -> (Arc<rustls::ServerConfig>, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key = KeyPair::generate_for(ecdsa).expect("admission test CA key");
    let empty_names = Vec::<String>::new();
    let mut ca_params = CertificateParams::new(empty_names).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(ecdsa).expect("admission test leaf key");
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign admission test leaf");

    let certs = rustls_pemfile::certs(&mut leaf_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse admission test leaf certificate");
    let key = rustls_pemfile::private_key(&mut leaf_key.serialize_pem().as_bytes())
        .expect("parse admission test leaf key")
        .expect("admission test leaf key present");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("admission test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("admission test TLS server config");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    (Arc::new(server_config), ca_pem)
}

async fn tls_connect(
    addr: SocketAddr,
    ca_pem: &str,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        let cert = cert.expect("parse admission test CA certificate");
        roots.add(cert).expect("add admission test CA to roots");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("admission test client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let tcp = TcpStream::connect(addr).await.expect("connect TLS");
    let name = rustls::pki_types::ServerName::try_from("localhost");
    let name = name.expect("admission test server name");
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(name, tcp)
        .await
        .expect("frontend TLS handshake")
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
    stream.write_all(bytes).await.expect("write");
    stream.flush().await.expect("flush");
}

async fn assert_peer_closed<S: AsyncRead + Unpin>(stream: &mut S, context: &str) {
    let mut buf = [0u8; 1];
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
        other => panic!("{context}: expected EOF or reset, got {other:?}"),
    }
}

async fn drain_until_closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(_) => continue,
        }
    }
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_SETTINGS: u8 = 0x4;
const H2_HEADERS: u8 = 0x1;
const H2_END_STREAM: u8 = 0x1;
const HPACK_INDEXED_GET: &[u8] = &[0x82];

fn h2_frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(9 + len);
    frame.push((len >> 16) as u8);
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    frame.push(kind);
    frame.push(flags);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn h2_send_preface<S: AsyncWrite + Unpin>(stream: &mut S) {
    let settings = h2_frame(H2_SETTINGS, 0, 0, &[]);
    let mut opening = H2_PREFACE.to_vec();
    opening.extend_from_slice(&settings);
    send(stream, &opening).await;
}

async fn h2_send_incomplete_headers<S: AsyncWrite + Unpin>(stream: &mut S) {
    let frame = h2_frame(H2_HEADERS, H2_END_STREAM, 1, HPACK_INDEXED_GET);
    send(stream, &frame).await;
}

/// A peer that completes TCP accept and sends nothing must not hold a
/// connection slot forever — this is the version-sniff window hyper's HTTP/1
/// timer never reaches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_version_sniff_with_no_bytes_is_closed() {
    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(SHORT, backend_port).await;

    let mut stream = harness.connect().await;
    assert_peer_closed(&mut stream, "plaintext version sniff").await;

    harness.shutdown().await;
    backend.abort();
}

/// One preface byte (`P`) parks hyper in `ReadVersion` forever unless the
/// admission watchdog fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_version_sniff_with_one_byte_is_closed() {
    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(SHORT, backend_port).await;

    let mut stream = harness.connect().await;
    send(&mut stream, b"P").await;
    assert_peer_closed(&mut stream, "plaintext one-byte sniff").await;

    harness.shutdown().await;
    backend.abort();
}

/// h2c preface + SETTINGS with no request: the H2 window that HTTP/1
/// `header_read_timeout` cannot see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_connection_without_a_request_is_closed() {
    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(SHORT, backend_port).await;

    let mut stream = harness.connect().await;
    h2_send_preface(&mut stream).await;
    tokio::time::timeout(WINDOW, drain_until_closed(&mut stream))
        .await
        .expect("an h2c connection that sends no request must be closed");

    harness.shutdown().await;
    backend.abort();
}

/// Incomplete HTTP/2 HEADERS (no `END_HEADERS`) never reaches the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_incomplete_header_block_is_closed() {
    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(SHORT, backend_port).await;

    let mut stream = harness.connect().await;
    h2_send_preface(&mut stream).await;
    h2_send_incomplete_headers(&mut stream).await;
    tokio::time::timeout(WINDOW, drain_until_closed(&mut stream))
        .await
        .expect("an incomplete h2c header block must be closed");

    harness.shutdown().await;
    backend.abort();
}

/// TLS handshake completes, then the client sends no application bytes.
/// `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` has already elapsed its
/// job; the HTTP pre-request bound must still fire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_h2_connection_without_a_request_is_closed() {
    let (backend_port, backend) = start_ok_backend().await;
    let (tls, ca_pem) = frontend_tls_pair();
    let harness = ProxyHarness::start(SHORT, Some(tls), backend_port).await;

    let mut stream = tls_connect(harness.addr, &ca_pem, b"h2").await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "frontend HTTPS must negotiate HTTP/2 via ALPN"
    );
    tokio::time::timeout(WINDOW, drain_until_closed(&mut stream))
        .await
        .expect("a TLS h2 connection that sends no request must be closed");

    harness.shutdown().await;
    backend.abort();
}

/// A legitimate h2c client that completes a request inside the window is
/// served, proving the watchdog does not fire on progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_request_inside_deadline_is_served() {
    use hyper::client::conn::http2;

    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(LONG, backend_port).await;

    let stream = harness.connect().await;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2c handshake");
    let conn_task = tokio::spawn(conn);

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{}/slow", harness.addr))
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let resp = sender.send_request(req).await.expect("send request");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.into_body().collect().await.expect("collect body");
    assert_eq!(body.to_bytes().as_ref(), b"ok");

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
    harness.shutdown().await;
    backend.abort();
}

/// After the first request, idle HTTP/2 keep-alive must survive longer than
/// the header-read timeout. Copying the admin between-request watchdog here
/// would drop browsers, gRPC clients, and connection reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_idle_keepalive_after_first_request_is_not_closed() {
    use hyper::client::conn::http2;

    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(SHORT, backend_port).await;

    let stream = harness.connect().await;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2c handshake");
    let conn_task = tokio::spawn(conn);

    let first = Request::builder()
        .method("GET")
        .uri(format!("http://{}/slow", harness.addr))
        .body(Full::new(Bytes::new()))
        .expect("build first request");
    let resp = sender.send_request(first).await.expect("first request");
    assert_eq!(resp.status().as_u16(), 200);
    let _ = resp.into_body().collect().await;

    // Several times the one-second bound. Admin would have closed by now.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    let second = Request::builder()
        .method("GET")
        .uri(format!("http://{}/slow", harness.addr))
        .body(Full::new(Bytes::new()))
        .expect("build second request");
    let resp = tokio::time::timeout(WINDOW, sender.send_request(second))
        .await
        .expect("idle keep-alive must still accept a second request")
        .expect("second request");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "idle HTTP/2 keep-alive after the first request must not be killed"
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
    harness.shutdown().await;
    backend.abort();
}

/// `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0` must disable the pre-request
/// bound rather than collapsing to an immediate close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_timeout_does_not_close_a_silent_connection() {
    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(0, backend_port).await;

    let mut stream = harness.connect().await;
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    send(
        &mut stream,
        b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let mut buf = Vec::new();
    let read = tokio::time::timeout(WINDOW, stream.read_to_end(&mut buf));
    let _ = read.await;
    let body = String::from_utf8_lossy(&buf);
    assert!(
        body.contains("200 OK"),
        "disabled timeout must still serve a late request; got {body:?}"
    );

    harness.shutdown().await;
    backend.abort();
}

/// Stalled pre-request peers must give `ConnectionGuard` slots back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_connections_release_overload_slots() {
    let (backend_port, backend) = start_ok_backend().await;
    let harness = ProxyHarness::start_plain(SHORT, backend_port).await;
    let active = Arc::clone(&harness.state.overload);

    let mut stalled = Vec::new();
    for _ in 0..3 {
        stalled.push(harness.connect().await);
    }

    let hold = async {
        while active.active_connections.load(Ordering::Relaxed) != 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(3), hold)
        .await
        .expect("each stalled connection should hold an overload slot");

    let release = async {
        while active.active_connections.load(Ordering::Relaxed) != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(WINDOW, release)
        .await
        .expect("stalled connections must release their overload slots");
    for mut stream in stalled {
        assert_peer_closed(&mut stream, "stalled proxy peer").await;
    }

    harness.shutdown().await;
    backend.abort();
}

#[test]
fn h2_frame_header_is_encoded_big_endian() {
    let frame = h2_frame(H2_HEADERS, H2_END_STREAM, 1, HPACK_INDEXED_GET);
    assert_eq!(&frame[..3], &[0, 0, 1], "24-bit big-endian length");
    assert_eq!(frame[3], H2_HEADERS);
    assert_eq!(frame[4], H2_END_STREAM);
    assert_eq!(&frame[5..9], &[0, 0, 0, 1], "31-bit big-endian stream id");
    assert_eq!(&frame[9..], HPACK_INDEXED_GET, "payload follows the header");
}
