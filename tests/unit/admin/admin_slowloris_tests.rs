//! Admin listener slowloris coverage (issue #2404).
//!
//! The admin listener used to bound exactly one window: an HTTP/1.1 message
//! head that took too long to arrive. Request bodies were bounded in size but
//! not in time, HTTP/2 streams had no header deadline at all, and one HTTP/2
//! connection could multiplex an unbounded number of stalled streams past the
//! listener's connection cap.
//!
//! These tests drive the real `serve_admin_on_listener` accept loop over real
//! sockets — plaintext and TLS, HTTP/1.1 and HTTP/2 — and pin each bound
//! deterministically: a stalled connection or stream is released within the
//! configured deadline, a request that finishes inside the deadline is served
//! normally, and requests no handler will read never have their body collected.

use chrono::Utc;
use ferrum_edge::admin::{
    AdminConnLimiter, AdminRequestLimits, AdminState,
    jwt_auth::{JwtConfig, JwtManager},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const JWT_SECRET: &str = "test-secret-key-for-admin-slowloris-tests-32b";
const JWT_ISSUER: &str = "ferrum-edge-slowloris-tests";

/// Deadline used by tests that assert a stall is cut off. One second keeps the
/// assertion window several times longer than the deadline without making the
/// suite slow.
const SHORT: u64 = 1;
/// Deadline used by tests that assert a *fast* answer. Long enough that a
/// response inside the assertion window proves the body was never waited on,
/// rather than proving some other timer fired.
const LONG: u64 = 30;
/// How long a test waits for an expected outcome before failing.
const WINDOW: Duration = Duration::from_secs(8);

// ---------------------------------------------------------------------------
// Admin state / listener scaffolding
// ---------------------------------------------------------------------------

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn token_with_role(role: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "slowloris-test-user",
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(JWT_SECRET.as_bytes());
    let token = encode(&header, &claims, &key);
    token.expect("encode admin test token")
}

fn limits(body_read_timeout_seconds: u64) -> AdminRequestLimits {
    AdminRequestLimits {
        body_read_timeout_seconds,
        http2_max_concurrent_streams: 8,
        http2_max_header_list_size_bytes: 16_384,
    }
}

fn admin_state(header_read_timeout_seconds: u64, limits: AdminRequestLimits) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: limits,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    }
}

/// A running admin listener plus the handles needed to stop it.
struct AdminHarness {
    addr: SocketAddr,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

impl AdminHarness {
    async fn start(
        state: AdminState,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        limiter: Arc<AdminConnLimiter>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind admin listener");
        let addr = listener.local_addr().expect("admin listener addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(async move {
            ferrum_edge::admin::serve_admin_on_listener(
                listener,
                state,
                shutdown_rx,
                tls_config,
                limiter,
            )
            .await
        });
        Self {
            addr,
            shutdown_tx,
            server,
        }
    }

    async fn start_plain(state: AdminState) -> Self {
        let limiter = AdminConnLimiter::unlimited();
        Self::start(state, None, limiter).await
    }

    async fn start_tls(state: AdminState, tls: Arc<rustls::ServerConfig>) -> Self {
        let limiter = AdminConnLimiter::unlimited();
        Self::start(state, Some(tls), limiter).await
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.addr)
            .await
            .expect("connect admin listener")
    }

    async fn shutdown(self) {
        self.shutdown_tx.send(true).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .expect("admin listener task should stop")
            .expect("admin listener task join")
            .expect("admin listener should exit cleanly");
    }
}

// ---------------------------------------------------------------------------
// TLS scaffolding
// ---------------------------------------------------------------------------

/// Self-signed CA plus a `localhost` leaf. The server config advertises the
/// same ALPN list the production admin HTTPS listener does.
fn admin_tls_pair() -> (Arc<rustls::ServerConfig>, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key = KeyPair::generate_for(ecdsa).expect("admin test CA key");
    let empty_names = Vec::<String>::new();
    let mut ca_params = CertificateParams::new(empty_names).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(ecdsa).expect("admin test leaf key");
    let leaf_names = vec!["localhost".to_string()];
    let leaf_params = CertificateParams::new(leaf_names).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign admin test leaf");

    let certs = rustls_pemfile::certs(&mut leaf_cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse admin test leaf certificate");
    let key = rustls_pemfile::private_key(&mut leaf_key.serialize_pem().as_bytes())
        .expect("parse admin test leaf key")
        .expect("admin test leaf key present");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("admin test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("admin test TLS server config");
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
        let cert = cert.expect("parse admin test CA certificate");
        roots.add(cert).expect("add admin test CA to roots");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("admin test client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let tcp = TcpStream::connect(addr).await.expect("connect TLS");
    let name = rustls::pki_types::ServerName::try_from("localhost");
    let name = name.expect("admin test server name");
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(name, tcp)
        .await
        .expect("admin TLS handshake")
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
    stream.write_all(bytes).await.expect("write");
    stream.flush().await.expect("flush");
}

fn h1_head(method: &str, path: &str, token: &str, content_length: usize) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_length}\r\n\
         \r\n"
    )
}

/// Read until the response status line is complete. `None` means the peer
/// closed (or reset) before sending one.
async fn read_status<S: AsyncRead + Unpin>(stream: &mut S) -> Option<u16> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..end]);
            let mut parts = line.split_whitespace();
            return parts.nth(1).and_then(|code| code.parse().ok());
        }
    }
}

/// Assert the peer closed (EOF or reset) rather than leaving the socket open.
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

/// Drain the socket until the peer closes it.
async fn drain_until_closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(_) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP/2 raw frame helpers
// ---------------------------------------------------------------------------

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_SETTINGS: u8 = 0x4;
const H2_HEADERS: u8 = 0x1;
const H2_END_STREAM: u8 = 0x1;
const H2_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const H2_MAX_HEADER_LIST_SIZE: u16 = 0x6;
/// HPACK static-table index for `:method: GET`, used as a header-block
/// fragment that is never terminated by `END_HEADERS`.
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

/// Send the client connection preface plus an empty `SETTINGS` frame.
async fn h2_send_preface<S: AsyncWrite + Unpin>(stream: &mut S) {
    let settings = h2_frame(H2_SETTINGS, 0, 0, &[]);
    let mut opening = H2_PREFACE.to_vec();
    opening.extend_from_slice(&settings);
    send(stream, &opening).await;
}

/// Send a `HEADERS` frame that opens stream 1 and deliberately omits
/// `END_HEADERS`, promising `CONTINUATION` frames that never arrive.
async fn h2_send_incomplete_headers<S: AsyncWrite + Unpin>(stream: &mut S) {
    let frame = h2_frame(H2_HEADERS, H2_END_STREAM, 1, HPACK_INDEXED_GET);
    send(stream, &frame).await;
}

async fn h2_read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(u8, u8, Vec<u8>)> {
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await.ok()?;
    let hi = (header[0] as usize) << 16;
    let len = hi | ((header[1] as usize) << 8) | header[2] as usize;
    let kind = header[3];
    let flags = header[4];
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.ok()?;
    Some((kind, flags, payload))
}

// ---------------------------------------------------------------------------
// HTTP/1.1 — slow bodies
// ---------------------------------------------------------------------------

/// A plaintext HTTP/1.1 request that announces a body and then stops sending it
/// must be released with `408`, not held until the client gives up.
#[tokio::test]
async fn plain_http1_slow_request_body_returns_408() {
    let state = admin_state(LONG, limits(SHORT));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");

    let mut stream = harness.connect().await;
    let head = h1_head("POST", "/admin/tls/validate", &token, 4096);
    send(&mut stream, head.as_bytes()).await;
    // A fragment of the announced body, then stall forever.
    send(&mut stream, b"{\"pa").await;

    let status = tokio::time::timeout(WINDOW, read_status(&mut stream))
        .await
        .expect("a stalled body must be answered within the deadline");
    assert_eq!(
        status,
        Some(408),
        "a request body that never finishes arriving must be released with 408"
    );

    harness.shutdown().await;
}

/// The same bound over TLS: the deadline belongs to the admin request path, not
/// to the plaintext transport.
#[tokio::test]
async fn tls_http1_slow_request_body_returns_408() {
    let (tls, ca_pem) = admin_tls_pair();
    let state = admin_state(LONG, limits(SHORT));
    let harness = AdminHarness::start_tls(state, tls).await;
    let token = token_with_role("admin");

    let mut stream = tls_connect(harness.addr, &ca_pem, b"http/1.1").await;
    let head = h1_head("POST", "/admin/tls/validate", &token, 4096);
    send(&mut stream, head.as_bytes()).await;
    send(&mut stream, b"{\"pa").await;

    let status = tokio::time::timeout(WINDOW, read_status(&mut stream))
        .await
        .expect("a stalled TLS body must be answered within the deadline");
    assert_eq!(status, Some(408));

    harness.shutdown().await;
}

/// The deadline is the budget for a *1 MiB* body; a route with a larger size
/// cap scales it by that cap. `/restore` is capped at 100 MiB here, so with the
/// same one-second base that releases a stalled `/admin/tls/validate` body with
/// `408` above, a stalled `/restore` body must still be waiting well past the
/// assertion window. Without the scaling, the ~80 MB backups `/restore` exists
/// to accept would have to arrive 100x faster than every other admin body.
#[tokio::test]
async fn restore_body_deadline_scales_with_its_larger_size_cap() {
    let state = admin_state(LONG, limits(SHORT));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");

    let mut stream = harness.connect().await;
    let head = h1_head("POST", "/restore", &token, 4096);
    send(&mut stream, head.as_bytes()).await;
    // A fragment of the announced body, then stall.
    send(&mut stream, b"{\"pa").await;

    // Several times the one-second base budget, and far short of the 100s the
    // scaled deadline actually allows.
    let window = Duration::from_secs(4);
    let outcome = tokio::time::timeout(window, read_status(&mut stream)).await;
    assert!(
        outcome.is_err(),
        "the 100 MiB /restore cap must scale its body deadline past the 1 MiB \
         budget, but the request was answered with {outcome:?}"
    );

    drop(stream);
    harness.shutdown().await;
}

/// Near-boundary success: a body that arrives in pieces but *completes* inside
/// the deadline is served normally. The `400` is produced by the handler
/// parsing the exact bytes sent, so this also proves the whole body reached it.
#[tokio::test]
async fn plain_http1_body_completing_inside_deadline_is_served() {
    let state = admin_state(LONG, limits(4));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");

    let body = b"{\"not-a-valid-request\":true}";
    let mut stream = harness.connect().await;
    let head = h1_head("POST", "/admin/tls/validate", &token, body.len());
    send(&mut stream, head.as_bytes()).await;
    send(&mut stream, &body[..8]).await;
    // Well inside the 4s body deadline.
    tokio::time::sleep(Duration::from_millis(400)).await;
    send(&mut stream, &body[8..]).await;

    let status = tokio::time::timeout(WINDOW, read_status(&mut stream))
        .await
        .expect("a completed body must be answered");
    assert_eq!(
        status,
        Some(400),
        "a body that completes inside the deadline must reach the handler, not time out"
    );

    harness.shutdown().await;
}

/// `FERRUM_ADMIN_BODY_READ_TIMEOUT_SECONDS=0` must actually disable the body
/// deadline rather than collapsing to an immediate timeout.
#[tokio::test]
async fn body_deadline_of_zero_does_not_time_out_a_slow_body() {
    let state = admin_state(LONG, limits(0));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");

    let body = b"{\"not-a-valid-request\":true}";
    let mut stream = harness.connect().await;
    let head = h1_head("POST", "/admin/tls/validate", &token, body.len());
    send(&mut stream, head.as_bytes()).await;
    send(&mut stream, &body[..8]).await;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    send(&mut stream, &body[8..]).await;

    let status = tokio::time::timeout(WINDOW, read_status(&mut stream))
        .await
        .expect("the listener must still answer with the deadline disabled");
    assert_eq!(
        status,
        Some(400),
        "a zero body deadline must disable the bound rather than fire immediately"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// HTTP/1.1 — slow headers over TLS
// ---------------------------------------------------------------------------

/// The TLS handshake completes, then the request head stalls. The HTTP/1.1
/// header deadline must still apply behind TLS.
#[tokio::test]
async fn tls_http1_slow_headers_close_connection() {
    let (tls, ca_pem) = admin_tls_pair();
    let state = admin_state(SHORT, limits(LONG));
    let harness = AdminHarness::start_tls(state, tls).await;

    let mut stream = tls_connect(harness.addr, &ca_pem, b"http/1.1").await;
    let partial = b"GET /health HTTP/1.1\r\nHost: localhost\r\n";
    send(&mut stream, partial).await;

    assert_peer_closed(&mut stream, "TLS HTTP/1.1 slow headers").await;

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// HTTP/2 — slow headers
// ---------------------------------------------------------------------------

/// A plaintext h2c connection that completes the preface and then never sends a
/// request head. hyper's HTTP/1.1 header timer cannot see this window at all,
/// so the connection watchdog has to close it.
#[tokio::test]
async fn h2c_connection_without_a_request_is_closed() {
    let state = admin_state(SHORT, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;

    let mut stream = harness.connect().await;
    h2_send_preface(&mut stream).await;

    tokio::time::timeout(WINDOW, drain_until_closed(&mut stream))
        .await
        .expect("an h2c connection that sends no request must be closed");

    harness.shutdown().await;
}

/// The HTTP/2 analogue of a slowloris header block: a `HEADERS` frame without
/// `END_HEADERS`. The stream, and the connection carrying it, must be released.
#[tokio::test]
async fn h2c_incomplete_header_block_is_closed() {
    let state = admin_state(SHORT, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;

    let mut stream = harness.connect().await;
    h2_send_preface(&mut stream).await;
    h2_send_incomplete_headers(&mut stream).await;

    tokio::time::timeout(WINDOW, drain_until_closed(&mut stream))
        .await
        .expect("an incomplete h2c header block must be closed");

    harness.shutdown().await;
}

/// The same over TLS, negotiated through ALPN `h2`.
#[tokio::test]
async fn tls_h2_incomplete_header_block_is_closed() {
    let (tls, ca_pem) = admin_tls_pair();
    let state = admin_state(SHORT, limits(LONG));
    let harness = AdminHarness::start_tls(state, tls).await;

    let mut stream = tls_connect(harness.addr, &ca_pem, b"h2").await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "admin HTTPS must still negotiate HTTP/2 via ALPN"
    );
    h2_send_preface(&mut stream).await;
    h2_send_incomplete_headers(&mut stream).await;

    tokio::time::timeout(WINDOW, drain_until_closed(&mut stream))
        .await
        .expect("an incomplete TLS h2 header block must be closed");

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// HTTP/2 — advertised stream and header bounds
// ---------------------------------------------------------------------------

/// The connection cap only bounds retained request state if a single connection
/// cannot multiplex without limit, so the server must actually advertise the
/// configured `SETTINGS_MAX_CONCURRENT_STREAMS` and
/// `SETTINGS_MAX_HEADER_LIST_SIZE`.
#[tokio::test]
async fn h2c_server_settings_advertise_configured_bounds() {
    let configured = AdminRequestLimits {
        body_read_timeout_seconds: LONG,
        http2_max_concurrent_streams: 5,
        http2_max_header_list_size_bytes: 9_216,
    };
    let state = admin_state(LONG, configured);
    let harness = AdminHarness::start_plain(state).await;

    let mut stream = harness.connect().await;
    h2_send_preface(&mut stream).await;

    let mut max_streams: Option<u32> = None;
    let mut max_header_list: Option<u32> = None;
    let read_settings = async {
        while max_streams.is_none() || max_header_list.is_none() {
            let Some((kind, flags, payload)) = h2_read_frame(&mut stream).await else {
                break;
            };
            // Skip anything that is not the server's own SETTINGS frame; the
            // ACK carries flag 0x1 and an empty payload.
            if kind != H2_SETTINGS || flags & 0x1 != 0 {
                continue;
            }
            for entry in payload.chunks_exact(6) {
                let id = u16::from_be_bytes([entry[0], entry[1]]);
                let raw = [entry[2], entry[3], entry[4], entry[5]];
                let value = u32::from_be_bytes(raw);
                if id == H2_MAX_CONCURRENT_STREAMS {
                    max_streams = Some(value);
                } else if id == H2_MAX_HEADER_LIST_SIZE {
                    max_header_list = Some(value);
                }
            }
        }
    };
    tokio::time::timeout(WINDOW, read_settings)
        .await
        .expect("the admin listener must send its HTTP/2 SETTINGS");

    assert_eq!(
        max_streams,
        Some(5),
        "admin HTTP/2 must advertise FERRUM_ADMIN_HTTP2_MAX_CONCURRENT_STREAMS"
    );
    assert_eq!(
        max_header_list,
        Some(9_216),
        "admin HTTP/2 must advertise FERRUM_ADMIN_HTTP2_MAX_HEADER_LIST_SIZE_BYTES"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// HTTP/2 — multiplexed slow bodies
// ---------------------------------------------------------------------------

/// The multiplexed case the connection cap alone cannot bound: several streams
/// on one connection, each holding an open request body. Every stream must be
/// released on its own deadline and the connection must stay usable afterwards,
/// proving per-stream release rather than a connection teardown.
#[tokio::test]
async fn h2c_multiplexed_slow_bodies_time_out_and_connection_survives() {
    let state = admin_state(LONG, limits(SHORT));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");
    let uri = format!("http://{}/admin/tls/validate", harness.addr);

    let tcp = harness.connect().await;
    let handshake = h2::client::handshake(tcp).await;
    let (send_request, connection) = handshake.expect("h2c client handshake");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let make_request = || {
        hyper::Request::builder()
            .method("POST")
            .uri(uri.as_str())
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(())
            .expect("build admin request")
    };

    // Three concurrent streams that announce a body and never send it.
    let mut pending = Vec::new();
    let mut open_bodies = Vec::new();
    for _ in 0..3 {
        let ready = send_request.clone().ready().await;
        let mut ready = ready.expect("h2 client ready for a stalled stream");
        let sent = ready.send_request(make_request(), false);
        let (response, body) = sent.expect("send stalled request");
        pending.push(response);
        open_bodies.push(body);
    }

    for (index, response) in pending.into_iter().enumerate() {
        let wait = tokio::time::timeout(WINDOW, response);
        let Ok(received) = wait.await else {
            panic!("stalled stream {index} was never released");
        };
        let response = received.expect("a stalled stream must get a response");
        assert_eq!(
            response.status(),
            408,
            "every multiplexed stalled stream must be released with its own 408"
        );
    }
    drop(open_bodies);

    // The connection itself must still work: a complete request on a fresh
    // stream reaches the handler (an empty body fails the JSON parse with 400).
    let ready = send_request.clone().ready().await;
    let mut ready = ready.expect("h2 client ready after stalled streams");
    let sent = ready.send_request(make_request(), true);
    let (response, _body) = sent.expect("send complete request");
    let received = tokio::time::timeout(WINDOW, response).await;
    let received = received.expect("connection must still serve");
    let response = received.expect("a complete request must get a response");
    assert_eq!(
        response.status(),
        400,
        "the connection must remain usable after its stalled streams are released"
    );

    drop(send_request);
    let stop = tokio::time::timeout(Duration::from_secs(2), connection_task);
    let _ = stop.await;
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Body admission — routes that never read a body
// ---------------------------------------------------------------------------

/// The body deadline is deliberately long in these tests: a fast answer proves
/// the body was never collected, rather than proving some timer fired.
async fn assert_answered_without_reading_body(
    harness: &AdminHarness,
    method: &str,
    path: &str,
    token: &str,
    expected_status: u16,
    context: &str,
) {
    let mut stream = harness.connect().await;
    // Announce a body and never send a byte of it.
    let head = h1_head(method, path, token, 1_000_000);
    send(&mut stream, head.as_bytes()).await;

    let read = tokio::time::timeout(WINDOW, read_status(&mut stream));
    let Ok(status) = read.await else {
        panic!("{context}: the request body was collected");
    };
    assert_eq!(status, Some(expected_status), "{context}");
}

/// An unknown path must be rejected before its body is collected.
#[tokio::test]
async fn unknown_route_answers_without_collecting_the_body() {
    let state = admin_state(LONG, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");
    assert_answered_without_reading_body(
        &harness,
        "POST",
        "/definitely-not-an-admin-route",
        &token,
        404,
        "unknown route",
    )
    .await;
    harness.shutdown().await;
}

/// A method the path does not route must be rejected before its body is
/// collected.
#[tokio::test]
async fn disallowed_method_answers_without_collecting_the_body() {
    let state = admin_state(LONG, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");
    assert_answered_without_reading_body(
        &harness,
        "PATCH",
        "/proxies",
        &token,
        404,
        "method not routed on a known path",
    )
    .await;
    harness.shutdown().await;
}

/// A caller whose role the route would reject must get its `403` before the
/// body is collected — a low-privilege token is exactly the attacker the issue
/// describes.
#[tokio::test]
async fn insufficient_role_answers_without_collecting_the_body() {
    let state = admin_state(LONG, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("viewer");
    assert_answered_without_reading_body(
        &harness,
        "POST",
        "/admin/tls/validate",
        &token,
        403,
        "role the route rejects",
    )
    .await;
    harness.shutdown().await;
}

/// A known *read* route is the largest class of routes that never touch the
/// body, and the one an authenticated low-privilege caller can reach most
/// cheaply. `GET /proxies` must answer from its handler — `503` with no
/// database and no cached config — while the announced body is still
/// outstanding, rather than buffering it up to the size cap first.
#[tokio::test]
async fn read_route_answers_without_collecting_the_body() {
    let state = admin_state(LONG, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;
    let token = token_with_role("admin");
    assert_answered_without_reading_body(
        &harness,
        "GET",
        "/proxies",
        &token,
        503,
        "read route with an unread body",
    )
    .await;
    harness.shutdown().await;
}

/// An unauthenticated caller must not be able to pin a body-collecting task.
#[tokio::test]
async fn unauthenticated_request_answers_without_collecting_the_body() {
    let state = admin_state(LONG, limits(LONG));
    let harness = AdminHarness::start_plain(state).await;
    assert_answered_without_reading_body(
        &harness,
        "POST",
        "/admin/tls/validate",
        "not-a-valid-token",
        401,
        "invalid credentials",
    )
    .await;
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Resource release
// ---------------------------------------------------------------------------

/// Stalled connections must give their limiter permits back, otherwise a
/// handful of slowloris peers permanently consume the admin connection cap.
#[tokio::test]
async fn stalled_connections_release_their_connection_permits() {
    let limiter = Arc::new(AdminConnLimiter::new(4, 0));
    // Two seconds rather than one so the "all three permits are held" snapshot
    // below has margin over accept scheduling; the release assertion that
    // follows is unaffected.
    let state = admin_state(2, limits(LONG));
    let permits = Arc::clone(&limiter);
    let harness = AdminHarness::start(state, None, permits).await;

    // Three peers that connect and send nothing at all — the version-sniff
    // window, which no HTTP/1.1 header timer can reach.
    let mut stalled = Vec::new();
    for _ in 0..3 {
        stalled.push(harness.connect().await);
    }

    let hold = async {
        while limiter.snapshot().active_connections != 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(3), hold)
        .await
        .expect("each stalled connection should hold a permit");

    let release = async {
        while limiter.snapshot().active_connections != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(WINDOW, release)
        .await
        .expect("stalled connections must release their permits");
    for mut stream in stalled {
        assert_peer_closed(&mut stream, "stalled admin peer").await;
    }

    // The cap is genuinely reusable afterwards.
    let mut stream = harness.connect().await;
    let probe = b"GET /live HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    send(&mut stream, probe).await;
    let status = tokio::time::timeout(WINDOW, read_status(&mut stream))
        .await
        .expect("a new connection must be served after permits are released");
    assert_eq!(status, Some(200));

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Frame encoder self-check
// ---------------------------------------------------------------------------

/// The HTTP/2 assertions above are only meaningful if the hand-built frames are
/// wire-correct, so pin the encoder itself.
#[test]
fn h2_frame_header_is_encoded_big_endian() {
    let frame = h2_frame(H2_HEADERS, H2_END_STREAM, 1, HPACK_INDEXED_GET);
    assert_eq!(&frame[..3], &[0, 0, 1], "24-bit big-endian length");
    assert_eq!(frame[3], H2_HEADERS);
    assert_eq!(frame[4], H2_END_STREAM);
    assert_eq!(&frame[5..9], &[0, 0, 0, 1], "31-bit big-endian stream id");
    assert_eq!(&frame[9..], HPACK_INDEXED_GET, "payload follows the header");
}
