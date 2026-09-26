//! Functional coverage for HTTP/3 early-data classification against the real
//! gateway binary (issue #5761).
//!
//! With `FERRUM_TLS_EARLY_DATA_METHODS` set, every H3 connection is accepted
//! through quinn's 0.5-RTT path, so each request stream is classified against
//! the handshake-completion signal. A request sent after the client's
//! handshake completed used to be classifiable as early data when it arrived in
//! the same flight as the client's `Finished`, and was then answered
//! `425 Too Early` (replay-unsafe method) or forwarded with `Early-Data: 1`.
//!
//! Tests (one gateway, `FERRUM_TLS_EARLY_DATA_METHODS=GET`):
//!   1. Resumed H3 connections that send no 0-RTT data: a `PUT` written right
//!      after the handshake is never answered 425, and the backend never sees
//!      `Early-Data: 1` on any request sent after a handshake.
//!   2. A genuine 0-RTT `PUT` is still answered 425 and never reaches the
//!      backend, while a 0-RTT `GET` is forwarded with `Early-Data: 1`. A
//!      loopback relay delays every gateway-to-client datagram, so the client
//!      cannot finish the handshake before the gateway has accepted and
//!      classified the 0-RTT streams. This leg is skipped, with a message, only
//!      when the client holds no 0-RTT ticket or the gateway rejects the early
//!      data; whenever quinn reports the 0-RTT data accepted it is asserted.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && \
//!     cargo test --test functional_tests -- \
//!       functional_h3_early_data_classification --ignored --nocapture

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::clients::http3::bind_quinn_client_endpoint;

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// Resumed connections that send their request only after the handshake.
const ONE_RTT_CONNECTIONS: usize = 8;
/// Latency the relay adds to every gateway-to-client datagram in the 0-RTT
/// leg. The client can neither hold 1-RTT keys nor send its `Finished` before
/// this has passed, so it is also the window the gateway has to accept and
/// classify the 0-RTT request streams while the handshake is still pending.
const SERVER_FLIGHT_DELAY: Duration = Duration::from_millis(500);
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

// ============================================================================
// Certificates
// ============================================================================

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn generate_ca() -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "H3-EARLY-DATA-CA");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

/// Server leaf for `localhost`, as `(cert_pem, key_pem)`.
fn generate_server_cert(ca: &GeneratedCa) -> (String, String) {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate server key");
    let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let mut params = CertificateParams::new(sans).expect("server params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrum-h3-early-data");
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    (cert.pem(), key_pair.serialize_pem())
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("write PEM");
    path.to_str().expect("PEM path is UTF-8").to_string()
}

// ============================================================================
// Backend that records every proxied request
// ============================================================================

/// One request the backend received from the gateway.
#[derive(Debug, Clone)]
struct BackendRequest {
    method: String,
    path: String,
    /// The `Early-Data` header value, when present.
    early_data: Option<String>,
}

type BackendLog = Arc<Mutex<Vec<BackendRequest>>>;

fn start_recording_backend(listener: TcpListener, log: BackendLog) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let _ = timeout(Duration::from_secs(5), serve_one(stream, log)).await;
            });
        }
    })
}

async fn serve_one(mut stream: TcpStream, log: BackendLog) {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(position) = find(&buf, b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(n) if n > 0 && buf.len() < 64 * 1024 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    // Only proxied requests for this fixture's route are recorded; this also
    // skips the gateway's own backend-capability probes.
    if !path.starts_with("/early") {
        let _ = stream.shutdown().await;
        return;
    }
    let mut early_data = None;
    let mut content_length = 0usize;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("early-data") {
            early_data = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
    }

    // Drain the request body before answering.
    loop {
        let body = &buf[head_end..];
        let complete = if chunked {
            body.ends_with(b"0\r\n\r\n")
        } else {
            body.len() >= content_length
        };
        if complete {
            break;
        }
        match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }

    let request = BackendRequest {
        method,
        path,
        early_data,
    };
    log.lock().expect("backend log").push(request);
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn backend_requests(log: &BackendLog, path: &str) -> Vec<BackendRequest> {
    log.lock()
        .expect("backend log")
        .iter()
        .filter(|request| request.path == path)
        .cloned()
        .collect()
}

// ============================================================================
// Latency relay for the 0-RTT leg
// ============================================================================

/// Loopback UDP relay that forwards client datagrams immediately and delays
/// every gateway-to-client datagram by a fixed latency. Until the gateway's
/// first flight reaches the client, the client has no 1-RTT keys, so a request
/// it writes right after `into_0rtt()` travels in 0-RTT packets, and it cannot
/// send its `Finished`, so the gateway accepts that request's stream while the
/// handshake is still pending.
struct LatencyRelay {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl LatencyRelay {
    async fn spawn(upstream: SocketAddr, latency: Duration) -> Self {
        let client_side = UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("bind relay client side");
        let client_side = Arc::new(client_side);
        let upstream_side = UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("bind relay upstream side");
        upstream_side
            .connect(upstream)
            .await
            .expect("connect relay to the gateway");
        let addr = client_side.local_addr().expect("relay addr");
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut from_client = vec![0u8; 65_535];
            let mut from_upstream = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    received = client_side.recv_from(&mut from_client) => {
                        let Ok((len, peer)) = received else {
                            continue;
                        };
                        client = Some(peer);
                        let _ = upstream_side.send(&from_client[..len]).await;
                    }
                    received = upstream_side.recv(&mut from_upstream) => {
                        let (Ok(len), Some(peer)) = (received, client) else {
                            continue;
                        };
                        let datagram = from_upstream[..len].to_vec();
                        let client_side = Arc::clone(&client_side);
                        tokio::spawn(async move {
                            sleep(latency).await;
                            let _ = client_side.send_to(&datagram, peer).await;
                        });
                    }
                }
            }
        });
        Self { addr, task }
    }
}

impl Drop for LatencyRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ============================================================================
// HTTP/3 client
// ============================================================================

/// QUIC client that trusts the test CA, resumes sessions, and may send 0-RTT.
fn early_data_client(ca_pem: &str) -> quinn::Endpoint {
    let ca = CertificateDer::from_pem_slice(ca_pem.as_bytes()).expect("parse CA PEM");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).expect("trust CA");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 only")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    client_tls.enable_early_data = true;

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).expect("quic cfg");
    let mut endpoint = bind_quinn_client_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind QUIC client");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    endpoint
}

/// Start an HTTP/3 session on a QUIC connection (handshaken or 0-RTT).
async fn h3_session(connection: quinn::Connection) -> (H3Sender, JoinHandle<()>) {
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("h3 client session");
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (sender, driver_task)
}

/// Write one bodiless request and FIN it, without waiting for the response.
async fn h3_send(sender: &mut H3Sender, method: Method, url: &str) -> H3Stream {
    let request = Request::builder()
        .method(method)
        .uri(url)
        .body(())
        .expect("build request");
    let mut stream = sender
        .send_request(request)
        .await
        .expect("send request headers");
    stream.finish().await.expect("finish request");
    stream
}

/// Read one response's status and body.
async fn h3_response(stream: &mut H3Stream) -> (StatusCode, String) {
    let response = timeout(STEP_TIMEOUT, stream.recv_response())
        .await
        .expect("response timed out")
        .expect("response headers");
    let mut body = Vec::new();
    while let Some(mut chunk) = timeout(STEP_TIMEOUT, stream.recv_data())
        .await
        .expect("response body timed out")
        .expect("response body")
    {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (
        response.status(),
        String::from_utf8_lossy(&body).into_owned(),
    )
}

/// One request on a fresh, fully handshaken connection.
async fn h3_request_after_handshake(
    client: &quinn::Endpoint,
    gateway: SocketAddr,
    method: Method,
    url: &str,
) -> Result<(StatusCode, String), String> {
    let connecting = client
        .connect(gateway, "localhost")
        .map_err(|e| format!("start connect: {e}"))?;
    let connection = timeout(STEP_TIMEOUT, connecting)
        .await
        .map_err(|_| "QUIC handshake timed out".to_string())?
        .map_err(|e| format!("QUIC handshake: {e}"))?;
    // The request is written the moment the client-side handshake completes,
    // so it can ride the same flight as the client's `Finished` — the ordering
    // issue #5761 misclassified.
    let (mut sender, driver) = h3_session(connection.clone()).await;
    let mut stream = h3_send(&mut sender, method, url).await;
    let response = h3_response(&mut stream).await;
    connection.close(0u32.into(), b"done");
    driver.abort();
    Ok(response)
}

// ============================================================================
// Test
// ============================================================================

const CONFIG: &str = r#"
version: "1"
proxies:
  - id: "h3-early-data"
    listen_path: "/early"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: BACKEND_PORT
    strip_listen_path: false
    pool_enable_http2: false

consumers: []
plugin_configs: []
"#;

#[ignore]
#[tokio::test]
async fn functional_h3_early_data_classification_follows_the_handshake_state() {
    let dir = TempDir::new().expect("temp dir");
    let ca = generate_ca();
    let (server_cert_pem, server_key_pem) = generate_server_cert(&ca);
    let cert_path = write_pem(&dir, "server.crt", &server_cert_pem);
    let key_path = write_pem(&dir, "server.key", &server_key_pem);

    let backend_listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let log: BackendLog = Arc::new(Mutex::new(Vec::new()));
    let backend = start_recording_backend(backend_listener, Arc::clone(&log));

    let config = CONFIG.replace("BACKEND_PORT", &backend_port.to_string());
    let mut gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
        .env("FERRUM_TLS_EARLY_DATA_METHODS", "GET")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("HTTPS port");
    let gateway_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port));
    let url = |path: &str| format!("https://localhost:{https_port}{path}");

    let client = early_data_client(&ca.cert_pem);

    // `TestGateway` readiness already covers every listener bind. This first
    // connection is a full handshake and leaves the client holding session
    // tickets for the resumed connections below.
    let warmup_url = url("/early/warmup");
    let warmup = h3_request_after_handshake(&client, gateway_addr, Method::GET, &warmup_url);
    let (status, body) = warmup.await.expect("warm-up request");
    assert_eq!(status, StatusCode::OK, "warm-up request failed: {body}");

    // 1. Resumed connections that send no 0-RTT data.
    let put_url = url("/early/one-rtt");
    for index in 0..ONE_RTT_CONNECTIONS {
        let request = h3_request_after_handshake(&client, gateway_addr, Method::PUT, &put_url);
        let (status, body) = request.await.expect("resumed 1-RTT request");
        assert_eq!(
            status,
            StatusCode::OK,
            "connection {index}: a PUT sent after the handshake must never be answered \
             425 Too Early (body: {body})"
        );
    }
    let one_rtt = backend_requests(&log, "/early/one-rtt");
    assert_eq!(one_rtt.len(), ONE_RTT_CONNECTIONS, "{one_rtt:?}");
    assert!(one_rtt.iter().all(|request| request.method == "PUT"));
    let warmup = backend_requests(&log, "/early/warmup");
    for request in one_rtt.iter().chain(warmup.iter()) {
        assert_eq!(
            request.early_data, None,
            "a request sent after the handshake must never be forwarded with \
             Early-Data: 1: {request:?}"
        );
    }

    // 2. A genuine 0-RTT PUT and GET, sent through the latency relay.
    let relay = LatencyRelay::spawn(gateway_addr, SERVER_FLIGHT_DELAY).await;
    let connecting = client
        .connect(relay.addr, "localhost")
        .expect("start 0-RTT connect");
    let Ok((connection, zero_rtt_accepted)) = connecting.into_0rtt() else {
        eprintln!(
            "SKIP 0-RTT leg: the client holds no 0-RTT-capable session ticket from the \
             gateway, so no request can be sent as early data"
        );
        gateway.shutdown();
        backend.abort();
        return;
    };
    let (mut sender, driver) = h3_session(connection.clone()).await;
    let mut put = h3_send(&mut sender, Method::PUT, &url("/early/zero-rtt-put")).await;
    let mut get = h3_send(&mut sender, Method::GET, &url("/early/zero-rtt-get")).await;
    let accepted = timeout(STEP_TIMEOUT, zero_rtt_accepted)
        .await
        .expect("0-RTT handshake timed out");
    if !accepted {
        eprintln!(
            "SKIP 0-RTT leg: the gateway rejected the client's 0-RTT data, so the \
             requests were never delivered as early data"
        );
        driver.abort();
        gateway.shutdown();
        backend.abort();
        return;
    }

    let (put_status, put_body) = h3_response(&mut put).await;
    assert_eq!(
        put_status,
        StatusCode::TOO_EARLY,
        "a PUT sent in 0-RTT and accepted before the handshake completed must be \
         answered 425 (body: {put_body})"
    );
    assert!(
        put_body.contains("Method not allowed in 0-RTT early data"),
        "unexpected 425 body: {put_body}"
    );
    let (get_status, get_body) = h3_response(&mut get).await;
    assert_eq!(
        get_status,
        StatusCode::OK,
        "an allowed 0-RTT GET must be forwarded (body: {get_body})"
    );

    assert!(
        backend_requests(&log, "/early/zero-rtt-put").is_empty(),
        "a 0-RTT PUT answered 425 must never reach the backend"
    );
    let zero_rtt_get = backend_requests(&log, "/early/zero-rtt-get");
    assert_eq!(zero_rtt_get.len(), 1, "{zero_rtt_get:?}");
    assert_eq!(zero_rtt_get[0].method, "GET");
    assert_eq!(
        zero_rtt_get[0].early_data.as_deref(),
        Some("1"),
        "a 0-RTT GET must be forwarded with Early-Data: 1: {zero_rtt_get:?}"
    );

    connection.close(0u32.into(), b"done");
    driver.abort();
    drop(relay);
    gateway.shutdown();
    backend.abort();
}
