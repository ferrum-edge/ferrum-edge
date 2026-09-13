//! Real-path `request_mirror` pre-buffer admission across HTTP/1.1, HTTP/2, and
//! HTTP/3 (advisory `GHSA-jv66-mq44-m9v3`).
//!
//! The advisory requires that sampling and bounded mirror admission run *before*
//! the gateway collects a request body, so a percentage-zero, sampled-out, or
//! saturated request keeps streaming instead of buffering an attacker-sized body
//! that no shadow request will ever use. Plugin-unit coverage can only assert the
//! predicates; this suite drives the three real transport entry paths.
//!
//! ## How "was the body collected?" is observed from outside
//!
//! `request_mirror` publishes a positive plugin-local ceiling
//! (`max_mirrored_request_body_bytes`) that survives an unlimited global limit,
//! but the proxy applies that ceiling **only** for a request the instance
//! actually admitted (`should_buffer_request_body`). With
//! `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0` and an undeclared (chunked / H3 DATA)
//! upload larger than the ceiling, one identical client request therefore has two
//! different, externally visible outcomes:
//!
//! * admitted -> the body is collected under the mirror ceiling -> `413`
//! * not admitted -> no mirror-derived collection at all -> `200`, and the whole
//!   body reaches the primary backend
//!
//! That difference is the assertion: it is reachable only if the admission
//! decision happened before body collection. Every scenario uses unauthenticated
//! clients, because unauthenticated traffic is the advisory's threat model.
//!
//! ## Documented limitations
//!
//! The admission decision is process-internal, so these tests prove it through
//! its observable consequences (status code, primary-backend body integrity,
//! mirror dispatch) rather than by inspecting plugin state.
//!
//! The client-cancellation release scenario is HTTP/1.1 only: it needs a socket
//! that declares `Content-Length` and then aborts mid-body, which is expressible
//! on a raw H1 connection but not through the H2/H3 scaffolding clients. The
//! per-instance lease/permit lifecycle those transports share is covered by
//! `tests/unit/plugins/request_mirror_tests.rs`.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::clients::Http3Client;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Plugin-local per-request mirror ceiling for every proxy in this suite.
const CEILING: usize = 1024;
/// Undeclared upload well above the ceiling and well below both the default H2
/// initial stream window (64 KiB) and the H3 frontend stream receive window
/// (256 KiB), so a gateway that stops reading at the ceiling can never block the
/// client mid-send.
const OVERSIZE: usize = 16 * 1024;
/// Upload below the ceiling: admitted, buffered, and mirrored.
const SMALL: usize = 512;

const NOSAMPLE: &str = "/nosample/probe";
const MIRRORED: &str = "/mirrored/probe";
const SATURATED: &str = "/saturated/probe";
const CANCEL: &str = "/cancel/probe";
const CANCEL_ABORTED: &str = "/cancel/aborted";
const CANCEL_RECOVERED: &str = "/cancel/recovered";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    H1,
    H2,
    H3,
}

impl Proto {
    fn label(self) -> &'static str {
        match self {
            Proto::H1 => "HTTP/1.1",
            Proto::H2 => "HTTP/2",
            Proto::H3 => "HTTP/3",
        }
    }
}

const PROTOS: [Proto; 3] = [Proto::H1, Proto::H2, Proto::H3];

#[ignore]
#[tokio::test]
async fn request_mirror_admits_before_body_collection_on_h1_h2_and_h3() {
    let mut harness = Harness::spawn().await;

    for proto in PROTOS {
        let label = proto.label();
        harness.reset_captures();

        // 1. Sampling is quantized to zero: no admission, so no mirror-derived
        //    collection ceiling. The oversize undeclared body must stream all
        //    the way to the primary backend.
        let status = harness.post_streamed(proto, NOSAMPLE, OVERSIZE).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{label}: percentage 0 must not impose a mirror body ceiling"
        );
        let seen = harness.primary.wait_for_request().await;
        let seen = seen.unwrap_or_else(|| panic!("{label}: primary saw no upload"));
        assert_eq!(
            seen.body_bytes, OVERSIZE,
            "{label}: the unsampled upload must reach the primary intact"
        );
        assert_eq!(
            harness.nosample_mirror.request_count(),
            0,
            "{label}: percentage 0 must never dispatch a mirror"
        );

        // 2. The identical request against an admitting instance IS collected,
        //    and the collection is bounded by the plugin-local ceiling even
        //    though the global request-body limit is unlimited.
        harness.reset_captures();
        let status = harness.post_streamed(proto, MIRRORED, OVERSIZE).await;
        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{label}: an admitted mirror must bound the collected body"
        );
        assert_eq!(
            harness.admitted_mirror.request_count(),
            0,
            "{label}: a body rejected at the ceiling must not be shadowed"
        );

        // 3. An admitted request under the ceiling is buffered and mirrored,
        //    body included -- the positive control for step 2.
        harness.reset_captures();
        let status = harness.post_streamed(proto, MIRRORED, SMALL).await;
        assert_eq!(status, StatusCode::OK, "{label}: admitted upload failed");
        let shadow = harness.admitted_mirror.wait_for_request().await;
        let shadow = shadow.unwrap_or_else(|| panic!("{label}: never mirrored"));
        assert_eq!(
            shadow.body_bytes, SMALL,
            "{label}: the mirror must carry the collected body"
        );
    }

    // 4. Saturation. `/saturated` allows a single in-flight mirror and points at
    //    a backend that accepts and never answers, so the first admitted request
    //    pins the only permit for the whole mirror deadline. Every later request
    //    is refused at pre-buffer admission -- and therefore, unlike step 2,
    //    must stream its oversize undeclared body instead of collecting it.
    harness.reset_captures();
    let hold = "/saturated/hold";
    let status = harness.post_streamed(Proto::H1, hold, SMALL).await;
    assert_eq!(status, StatusCode::OK, "saturating request must succeed");
    assert!(
        harness.hanging_mirror.wait_for_connections(1).await,
        "the saturating mirror never reached the hanging shadow backend"
    );

    for proto in PROTOS {
        let label = proto.label();
        harness.primary.clear();
        let status = harness.post_streamed(proto, SATURATED, OVERSIZE).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{label}: a saturated instance must leave the request streaming"
        );
        let seen = harness.primary.wait_for_request().await;
        let seen = seen.unwrap_or_else(|| panic!("{label}: primary saw no upload"));
        assert_eq!(
            seen.body_bytes, OVERSIZE,
            "{label}: a saturated request must still deliver its whole body"
        );
    }
    assert_eq!(
        harness.hanging_mirror.connection_count(),
        1,
        "max_in_flight must admit exactly one concurrent mirror"
    );

    harness.shutdown();
}

/// Client cancellation mid-body must return the reserved aggregate capacity.
///
/// `/cancel` sizes `max_retained_request_body_bytes` to one
/// `max_mirrored_request_body_bytes` ceiling so a single admitted request
/// consumes the instance's entire aggregate budget until its lease releases.
/// If the abort leaked the lease, no later request on that instance could ever
/// be admitted again. HTTP/1.1 only -- see the module-level limitation note.
#[ignore]
#[tokio::test]
async fn request_mirror_releases_reserved_capacity_when_a_client_cancels() {
    let mut harness = Harness::spawn().await;

    // Baseline: the instance mirrors before any cancellation happens.
    let status = harness.post_declared(CANCEL, SMALL).await;
    assert_eq!(status, StatusCode::OK);
    let baseline = harness.cancel_mirror.wait_for_request().await;
    assert!(baseline.is_some(), "baseline request must be mirrored");

    // Abort mid-body after declaring the whole aggregate budget.
    harness.reset_captures();
    harness.abort_mid_body(CANCEL_ABORTED, CEILING, 64).await;

    // Retry until the aborted request's lease is observably released. A leaked
    // lease permanently exhausts the budget, so no retry could ever succeed.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut mirrored_again = false;
    while tokio::time::Instant::now() < deadline {
        let status = harness.post_declared(CANCEL_RECOVERED, SMALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the primary request must stay unaffected by mirror budget state"
        );
        if harness
            .cancel_mirror
            .wait_for_target(CANCEL_RECOVERED)
            .await
            .is_some()
        {
            mirrored_again = true;
            break;
        }
    }
    assert!(
        mirrored_again,
        "a cancelled upload must release its reserved retained-body capacity"
    );

    harness.shutdown();
}

// ── capture backends ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Captured {
    target: String,
    body_bytes: usize,
}

/// Minimal HTTP/1.1 backend that decodes either framing the gateway can emit
/// (`Content-Length` or chunked) and records the decoded body length.
struct CaptureBackend {
    port: u16,
    requests: Arc<Mutex<Vec<Captured>>>,
    handle: Option<JoinHandle<()>>,
}

impl CaptureBackend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind capture backend");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = requests.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let sink = sink.clone();
                        tokio::spawn(serve_capture(stream, sink));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Self {
            port,
            requests,
            handle: Some(handle),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("requests lock").len()
    }

    fn clear(&self) {
        self.requests.lock().expect("requests lock").clear();
    }

    fn first(&self) -> Option<Captured> {
        self.requests
            .lock()
            .expect("requests lock")
            .first()
            .cloned()
    }

    fn first_for_target(&self, target: &str) -> Option<Captured> {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .find(|request| request.target == target)
            .cloned()
    }

    async fn wait_for_request(&self) -> Option<Captured> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(first) = self.first() {
                return Some(first);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_for_target(&self, target: &str) -> Option<Captured> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(first) = self.first_for_target(target) {
                return Some(first);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for CaptureBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

async fn serve_capture(mut stream: TcpStream, sink: Arc<Mutex<Vec<Captured>>>) {
    let mut buf: Vec<u8> = Vec::new();
    let head_end = loop {
        if let Some(index) = find(&buf, b"\r\n\r\n") {
            break index + 4;
        }
        if !read_more(&mut stream, &mut buf).await {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let target = request_target(&head);
    let declared = header_value(&head, "content-length");
    let declared = declared.and_then(|value| value.parse::<usize>().ok());
    let encoding = header_value(&head, "transfer-encoding").unwrap_or_default();
    let chunked = encoding.to_ascii_lowercase().contains("chunked");

    let body_bytes = if let Some(length) = declared {
        while buf.len() - head_end < length {
            if !read_more(&mut stream, &mut buf).await {
                break;
            }
        }
        (buf.len() - head_end).min(length)
    } else if chunked {
        decode_chunked(&mut stream, &mut buf, head_end).await
    } else {
        0
    };

    let captured = Captured { target, body_bytes };
    sink.lock().expect("requests lock").push(captured);
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let _ = stream.write_all(response).await;
    let _ = stream.shutdown().await;
}

/// Decode a chunked body starting at `cursor`, returning the decoded length.
async fn decode_chunked(stream: &mut TcpStream, buf: &mut Vec<u8>, mut cursor: usize) -> usize {
    let mut decoded = 0usize;
    loop {
        let line_end = loop {
            if let Some(index) = find(&buf[cursor..], b"\r\n") {
                break cursor + index;
            }
            if !read_more(stream, buf).await {
                return decoded;
            }
        };
        let line = String::from_utf8_lossy(&buf[cursor..line_end]).to_string();
        let token = line.split(';').next().unwrap_or("").trim().to_string();
        let Ok(size) = usize::from_str_radix(&token, 16) else {
            return decoded;
        };
        cursor = line_end + 2;
        if size == 0 {
            return decoded;
        }
        while buf.len() < cursor + size + 2 {
            if !read_more(stream, buf).await {
                return decoded;
            }
        }
        decoded += size;
        cursor += size + 2;
    }
}

async fn read_more(stream: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 8192];
    match stream.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn request_target(head: &str) -> String {
    let line = head.lines().next().unwrap_or("");
    line.split_whitespace().nth(1).unwrap_or("").to_string()
}

fn header_value(head: &str, name: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Shadow backend that accepts connections and never answers, so an admitted
/// mirror pins its `max_in_flight` permit for the whole mirror deadline.
struct HangingBackend {
    port: u16,
    connections: Arc<Mutex<usize>>,
    handle: Option<JoinHandle<()>>,
}

impl HangingBackend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind hanging backend");
        let port = listener.local_addr().expect("local addr").port();
        let connections = Arc::new(Mutex::new(0usize));
        let counter = connections.clone();
        let handle = tokio::spawn(async move {
            // Hold every accepted socket open and never write a response.
            let mut held = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        *counter.lock().expect("connections lock") += 1;
                        held.push(stream);
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Self {
            port,
            connections,
            handle: Some(handle),
        }
    }

    fn connection_count(&self) -> usize {
        *self.connections.lock().expect("connections lock")
    }

    async fn wait_for_connections(&self, want: usize) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if self.connection_count() >= want {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for HangingBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

// ── harness ─────────────────────────────────────────────────────────────────

struct Harness {
    gateway: TestGateway,
    primary: CaptureBackend,
    nosample_mirror: CaptureBackend,
    admitted_mirror: CaptureBackend,
    cancel_mirror: CaptureBackend,
    hanging_mirror: HangingBackend,
    https_port: u16,
}

impl Harness {
    async fn spawn() -> Self {
        let primary = CaptureBackend::spawn().await;
        let nosample_mirror = CaptureBackend::spawn().await;
        let admitted_mirror = CaptureBackend::spawn().await;
        let cancel_mirror = CaptureBackend::spawn().await;
        let hanging_mirror = HangingBackend::spawn().await;

        let config = admission_config(
            primary.port,
            nosample_mirror.port,
            admitted_mirror.port,
            cancel_mirror.port,
            hanging_mirror.port,
        );
        let gateway = TestGateway::builder()
            .mode_file(config)
            .log_level("warn")
            // Unlimited global request-body limit: the only bound left is the
            // plugin-local mirror ceiling, and it must apply to admitted
            // requests only.
            .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .spawn()
            .await
            .expect("start request_mirror admission gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");
        let https_port = gateway
            .env_port("FERRUM_PROXY_HTTPS_PORT")
            .expect("harness-allocated HTTPS port");

        Self {
            gateway,
            primary,
            nosample_mirror,
            admitted_mirror,
            cancel_mirror,
            hanging_mirror,
            https_port,
        }
    }

    fn reset_captures(&self) {
        self.primary.clear();
        self.nosample_mirror.clear();
        self.admitted_mirror.clear();
        self.cancel_mirror.clear();
    }

    /// POST `size` bytes with no declared length: chunked on H1, a DATA-only
    /// stream on H2 (no exact `size_hint`, so hyper cannot synthesize
    /// `content-length`), and DATA frames on H3.
    async fn post_streamed(&self, proto: Proto, path: &str, size: usize) -> StatusCode {
        match proto {
            Proto::H1 => self.h1_chunked(path, size).await,
            Proto::H2 => self.h2_post(path, size).await,
            Proto::H3 => self.h3_post(path, size).await,
        }
    }

    /// POST `size` bytes with an explicit `Content-Length` over HTTP/1.1.
    async fn post_declared(&self, path: &str, size: usize) -> StatusCode {
        let mut stream = self.connect_h1().await;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n",
            self.gateway.proxy_port
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(&vec![b'x'; size]).await;
        read_h1_status(&mut stream).await
    }

    async fn h1_chunked(&self, path: &str, size: usize) -> StatusCode {
        let mut stream = self.connect_h1().await;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            self.gateway.proxy_port
        );
        let mut wire = head.into_bytes();
        wire.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        wire.extend_from_slice(&vec![b'x'; size]);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        // A rejected upload can make the gateway respond and close while the
        // remaining bytes are still in flight; the status line is what matters.
        let _ = stream.write_all(&wire).await;
        read_h1_status(&mut stream).await
    }

    async fn h2_post(&self, path: &str, size: usize) -> StatusCode {
        let stream = self.connect_h1().await;
        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);
        let exec = TokioExecutor::new();
        let (mut sender, conn) = hyper::client::conn::http2::handshake(exec, io)
            .await
            .expect("h2 handshake");
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let uri = format!("http://127.0.0.1:{}{path}", self.gateway.proxy_port);
        // `Full` exposes an exact size_hint; hyper's H2 client then inserts
        // Content-Length, which makes request_mirror skip admission for an
        // oversize declared body (intentional — stays streaming, no 413). Use
        // StreamBody so the upload stays DATA-only and exercises the admitted
        // plugin-local ceiling path that H1 chunked / H3 DATA already cover.
        let body = StreamBody::new(futures_util::stream::iter([
            Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from(vec![b'x'; size]))),
        ]));
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/octet-stream")
            .body(body)
            .expect("build h2 request");
        let response = sender.send_request(request).await.expect("send h2");
        let status = response.status();
        let _ = response.into_body().collect().await;
        drop(sender);
        conn_task.abort();
        status
    }

    async fn h3_post(&self, path: &str, size: usize) -> StatusCode {
        let client = Http3Client::insecure().expect("h3 client");
        let url = format!("https://localhost:{}{path}", self.https_port);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            match client.post_bytes(&url, vec![b'x'; size]).await {
                Ok(response) => return response.status,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("H3 admission request did not complete: {error}"),
            }
        }
    }

    /// Declare `declared` bytes, send only `sent`, then abort the connection.
    async fn abort_mid_body(&self, path: &str, declared: usize, sent: usize) {
        let mut stream = self.connect_h1().await;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared}\r\n\r\n",
            self.gateway.proxy_port
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(&vec![b'x'; sent]).await;
        let _ = stream.flush().await;
        // Let the gateway admit the request and start collecting the body.
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(stream);
    }

    async fn connect_h1(&self) -> TcpStream {
        TcpStream::connect(("127.0.0.1", self.gateway.proxy_port))
            .await
            .expect("connect to proxy port")
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.primary.abort();
        self.nosample_mirror.abort();
        self.admitted_mirror.abort();
        self.cancel_mirror.abort();
        self.hanging_mirror.abort();
    }
}

async fn read_h1_status(stream: &mut TcpStream) -> StatusCode {
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while find(&buf, b"\r\n").is_none() {
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out reading HTTP/1.1 status line");
        }
        let read = read_more(stream, &mut buf);
        match tokio::time::timeout(Duration::from_secs(5), read).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => panic!("timed out reading HTTP/1.1 status line"),
        }
    }
    let line = String::from_utf8_lossy(&buf).to_string();
    let first = line.lines().next().unwrap_or("");
    let code = first.split_whitespace().nth(1).unwrap_or("");
    let code = code
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("no status line in response: {line:?}"));
    StatusCode::from_u16(code).expect("valid status code")
}

fn mirror_proxy(id: &str, listen_path: &str, primary_port: u16) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": primary_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": [{"plugin_config_id": format!("{id}-plugin")}]
    })
}

fn mirror_plugin(proxy_id: &str, config: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": format!("{proxy_id}-plugin"),
        "plugin_name": "request_mirror",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": config
    })
}

fn admission_config(
    primary_port: u16,
    nosample_port: u16,
    admitted_port: u16,
    cancel_port: u16,
    hanging_port: u16,
) -> String {
    let nosample = serde_json::json!({
        "mirror_host": "127.0.0.1",
        "mirror_port": nosample_port,
        "mirror_protocol": "http",
        "percentage": 0.0,
        "mirror_request_body": true,
        "max_mirrored_request_body_bytes": CEILING
    });
    let admitted = serde_json::json!({
        "mirror_host": "127.0.0.1",
        "mirror_port": admitted_port,
        "mirror_protocol": "http",
        "percentage": 100.0,
        "mirror_request_body": true,
        "max_mirrored_request_body_bytes": CEILING
    });
    // Maximum permitted deadline: the single permit stays pinned for the whole
    // test rather than recycling on a mirror timeout.
    let saturated = serde_json::json!({
        "mirror_host": "127.0.0.1",
        "mirror_port": hanging_port,
        "mirror_protocol": "http",
        "percentage": 100.0,
        "mirror_request_body": true,
        "max_in_flight": 1,
        "mirror_timeout_ms": 300000,
        "max_mirrored_request_body_bytes": CEILING
    });
    // One full-ceiling admission consumes the entire aggregate budget, so a
    // leaked lease is immediately visible.
    let cancel = serde_json::json!({
        "mirror_host": "127.0.0.1",
        "mirror_port": cancel_port,
        "mirror_protocol": "http",
        "percentage": 100.0,
        "mirror_request_body": true,
        "max_retained_request_body_bytes": CEILING,
        "max_mirrored_request_body_bytes": CEILING
    });

    let config = serde_json::json!({
        "version": "1",
        "proxies": [
            mirror_proxy("mirror-nosample", "/nosample", primary_port),
            mirror_proxy("mirror-admitted", "/mirrored", primary_port),
            mirror_proxy("mirror-saturated", "/saturated", primary_port),
            mirror_proxy("mirror-cancel", "/cancel", primary_port),
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            mirror_plugin("mirror-nosample", nosample),
            mirror_plugin("mirror-admitted", admitted),
            mirror_plugin("mirror-saturated", saturated),
            mirror_plugin("mirror-cancel", cancel),
        ]
    });
    serde_yaml::to_string(&config).expect("serialize admission config")
}
