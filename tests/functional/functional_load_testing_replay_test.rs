//! End-to-end replay fidelity for `load_testing` across H1 and H3 ingress.
//!
//! Issue #4164: replays are dialed at `127.0.0.1`, which operators routinely
//! list in `FERRUM_TRUSTED_PROXIES`, so a client-supplied `X-Real-IP` carried
//! into the synthetic header snapshot would be honored by
//! `client_ip::resolve_client_ip` on backend-bound traffic. Every trigger below
//! therefore sends a spoofed `X-Real-IP` that must appear in NO capture.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{Method, StatusCode};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const TRIGGER_KEY: &str = "functional-load-key-0123456789abcdef";
const RAW_QUERY: &str = "tag=red&tag=blue&q=a+b&prefix=a%2Fb&flag&empty=";
const MAX_REQUEST_BYTES: usize = 128 * 1024;
/// Client-asserted source address the gateway must refuse on both the original
/// request and every synthetic replay (issue #4164). The harness dials from
/// loopback, so this value can only have come from the trigger's header.
const SPOOFED_REAL_IP: &str = "10.0.0.7";

#[derive(Debug)]
struct CapturedRequest {
    request_target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct ReplayBackend {
    port: u16,
    receiver: mpsc::Receiver<CapturedRequest>,
    handle: Option<JoinHandle<()>>,
}

impl ReplayBackend {
    async fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind_test("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (sender, receiver) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let sender = sender.clone();
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    let _ = sender.try_send(request);

                    // Keep the single load worker bounded to roughly ten
                    // requests per second so a fidelity test cannot create an
                    // unbounded capture backlog on a fast runner.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let body = b"ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self {
            port,
            receiver,
            handle: Some(handle),
        })
    }

    async fn collect(&mut self, expected_target: &str, count: usize) -> Vec<CapturedRequest> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut captures = Vec::with_capacity(count);
        while captures.len() < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out after {} matching captures for {expected_target}",
                captures.len()
            );
            let request = tokio::time::timeout(remaining, self.receiver.recv())
                .await
                .expect("capture timeout")
                .expect("capture backend stopped");
            if request.request_target == expected_target {
                captures.push(request);
            }
        }
        captures
    }

    fn drain(&mut self) {
        while self.receiver.try_recv().is_ok() {}
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for ReplayBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

struct ReplayHarness {
    gateway: TestGateway,
    backend: ReplayBackend,
    https_port: u16,
}

impl ReplayHarness {
    async fn spawn() -> Self {
        let mut backend = ReplayBackend::spawn()
            .await
            .expect("spawn replay capture backend");
        let config = replay_config(backend.port);
        let mut last_error = String::new();

        for _ in 0..5 {
            let reservation = reserve_port().await.expect("reserve HTTPS port");
            let https_port = reservation.drop_and_take_port();
            match TestGateway::builder()
                .mode_file(config.clone())
                .log_level("warn")
                .max_attempts(1)
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                .spawn()
                .await
            {
                Ok(mut gateway) => {
                    match gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        Ok(()) => {
                            return Self {
                                gateway,
                                backend,
                                https_port,
                            };
                        }
                        Err(error) => {
                            last_error = error.to_string();
                            gateway.shutdown();
                        }
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
        }

        backend.abort();
        panic!("start load-testing replay gateway after retries: {last_error}");
    }

    fn h3_url(&self, target: &str) -> String {
        format!("https://localhost:{}{target}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.backend.abort();
    }
}

#[ignore]
#[tokio::test]
async fn functional_load_testing_replays_exact_body_query_and_framing_from_h1_and_h3() {
    let mut harness = ReplayHarness::spawn().await;

    let h1_target = format!("/load-replay-h1?{RAW_QUERY}");
    let h1_body = Bytes::from_static(br#"{"sku":"A-123","note":"+"}"#);
    send_raw_h1_trigger(harness.gateway.proxy_port, &h1_target, &h1_body).await;

    let h1_captures = harness.backend.collect(&h1_target, 2).await;
    assert_replay_captures(&h1_captures, &h1_body);

    // The first cohort has an absolute one-second lifetime. Let it finish and
    // discard any extra bounded captures before starting the independent H3
    // plugin identity.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    harness.backend.drain();

    let h3_target = format!("/load-replay-h3?{RAW_QUERY}");
    let h3_body = Bytes::from_static(&[0x00, 0xff, b'a', b'+', b'%', b'2', b'F']);
    let h3_client = Http3Client::insecure().expect("H3 client");
    let h3_options = GetOptions::default()
        .method(Method::POST)
        .header("x-loadtesting-key", TRIGGER_KEY)
        .header("x-real-ip", SPOOFED_REAL_IP)
        .body(h3_body.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    let h3_response = loop {
        match h3_client
            .get_with_options(&harness.h3_url(&h3_target), h3_options.clone())
            .await
        {
            Ok(response) => break response,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 trigger request did not complete: {error}"),
        }
    };
    assert_eq!(h3_response.status, StatusCode::OK);
    assert_eq!(h3_response.body_bytes, Bytes::from_static(b"ok"));
    assert!(h3_response.body_error.is_none());

    let h3_captures = harness.backend.collect(&h3_target, 2).await;
    assert_replay_captures(&h3_captures, &h3_body);

    harness.shutdown();
}

fn assert_replay_captures(captures: &[CapturedRequest], expected_body: &[u8]) {
    assert!(
        captures.len() >= 2,
        "original plus synthetic request required"
    );
    let expected_content_length = expected_body.len().to_string();
    for capture in captures {
        assert_eq!(capture.body, expected_body);
        assert_eq!(
            capture.headers.get("content-length").map(String::as_str),
            Some(expected_content_length.as_str()),
            "framing must match replay bytes: {capture:?}"
        );
        assert!(!capture.headers.contains_key("transfer-encoding"));
        assert!(!capture.headers.contains_key("x-loadtesting-key"));
        assert!(!capture.headers.contains_key("x-loadtesting-fanout"));
        // Issue #4164: neither the original request nor the synthetic replay
        // may carry the untrusted peer's client-asserted source address.
        assert!(
            !capture.headers.contains_key("x-real-ip"),
            "client-asserted X-Real-IP survived into a load-test capture: {capture:?}"
        );
    }
}

async fn send_raw_h1_trigger(port: u16, target: &str, body: &[u8]) {
    let request_head = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost\r\nX-Loadtesting-Key: {TRIGGER_KEY}\r\nX-Real-IP: {SPOOFED_REAL_IP}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect H1 gateway");
        stream
            .write_all(request_head.as_bytes())
            .await
            .expect("write H1 request head");
        stream.write_all(body).await.expect("write H1 request body");
        stream.flush().await.expect("flush H1 request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read H1 response");
        response
    })
    .await
    .expect("H1 trigger deadline");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "unexpected H1 response: {}",
        String::from_utf8_lossy(&response)
    );
}

async fn read_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
        if request.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
    };

    let header_text = std::str::from_utf8(&request[..header_end]).ok()?;
    let mut lines = header_text.split("\r\n");
    let request_target = lines.next()?.split_whitespace().nth(1)?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if header_end.checked_add(content_length)? > MAX_REQUEST_BYTES {
        return None;
    }
    while request.len() < header_end + content_length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
    }

    Some(CapturedRequest {
        request_target,
        headers,
        body: request[header_end..header_end + content_length].to_vec(),
    })
}

fn replay_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [
            replay_proxy("load-replay-h1", "/load-replay-h1", backend_port, "load-plugin-h1"),
            replay_proxy("load-replay-h3", "/load-replay-h3", backend_port, "load-plugin-h3")
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            replay_plugin("load-plugin-h1", "load-replay-h1"),
            replay_plugin("load-plugin-h3", "load-replay-h3")
        ]
    });
    serde_yaml::to_string(&config).expect("serialize load-testing replay config")
}

fn replay_proxy(
    id: &str,
    listen_path: &str,
    backend_port: u16,
    plugin_config_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": [{"plugin_config_id": plugin_config_id}]
    })
}

fn replay_plugin(id: &str, proxy_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "plugin_name": "load_testing",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {
            "key": TRIGGER_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "request_timeout_ms": 1000,
            "max_response_body_bytes": 1024
        }
    })
}

// ---------------------------------------------------------------------------
// A declared oversized trigger body is forwarded without a run (PR #6856)
// ---------------------------------------------------------------------------

/// The plugin's 10 MiB replay ceiling (`MAX_REPLAY_REQUEST_BODY_BYTES`).
const REPLAY_CEILING_BYTES: usize = 10 * 1024 * 1024;

/// One application request a [`spawn_draining_backend`] observed.
#[derive(Debug)]
struct DrainedRequest {
    method: String,
    target: String,
    body_len: usize,
}

/// A backend that drains each HTTP/1.1 request body (Content-Length or
/// chunked), reports it, and answers `200`.
///
/// The gateway's startup capability refresh dials every plaintext HTTP
/// backend with the h2c connection preface (`PRI * HTTP/2.0`) regardless of
/// `pool_enable_http2`. Such a probe is closed without being reported, so it
/// can never be mistaken for the primary request or a synthetic replay.
async fn spawn_draining_backend() -> (u16, mpsc::Receiver<DrainedRequest>, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind draining backend");
    let port = listener.local_addr().expect("backend address").port();
    let (sender, receiver) = mpsc::channel(64);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let sender = sender.clone();
            tokio::spawn(async move {
                let Some(observed) = drain_request(&mut stream).await else {
                    return;
                };
                let _ = sender.try_send(observed);
                let response =
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, receiver, handle)
}

/// `true` for the HTTP/2 connection-preface request line, which is a
/// transport capability probe, never an application request.
fn is_h2c_preface_request_line(request_line: &str) -> bool {
    request_line.starts_with("PRI * HTTP/2.0")
}

async fn drain_request(stream: &mut TcpStream) -> Option<DrainedRequest> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 65536];
    let header_end = loop {
        if let Some(offset) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
    };
    let header_text = std::str::from_utf8(&buf[..header_end]).ok()?.to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    if is_h2c_preface_request_line(request_line) {
        return None;
    }
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts.next()?.to_string();
    let target = request_line_parts.next()?.to_string();
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let mut body = buf[header_end..].to_vec();
    let body_len = if let Some(length) = content_length {
        while body.len() < length {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        length
    } else if chunked {
        // Minimal chunked decoder: sum chunk sizes until the zero-size chunk.
        let mut total = 0usize;
        let mut cursor = 0usize;
        loop {
            let line_end = loop {
                if let Some(offset) = body[cursor..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                {
                    break cursor + offset;
                }
                let read = stream.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                body.extend_from_slice(&chunk[..read]);
            };
            let size_text = std::str::from_utf8(&body[cursor..line_end]).ok()?;
            let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
            let data_start = line_end + 2;
            if size == 0 {
                break total;
            }
            while body.len() < data_start + size + 2 {
                let read = stream.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            total += size;
            cursor = data_start + size + 2;
        }
    } else {
        0
    };
    Some(DrainedRequest {
        method,
        target,
        body_len,
    })
}

/// The startup capability refresh sends the h2c preface to a plaintext
/// backend. The draining backend must close that probe unreported, while a
/// real upload on the same backend still counts.
#[tokio::test]
async fn draining_backend_ignores_the_h2c_capability_probe() {
    let (port, mut observed, backend) = spawn_draining_backend().await;

    let mut probe = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect probe");
    probe
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("write h2c preface");
    let mut closed = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), probe.read_to_end(&mut closed)).await;
    assert!(closed.is_empty(), "the probe must be closed unanswered");

    let mut upload = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect upload");
    upload
        .write_all(b"POST /probe-check HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest")
        .await
        .expect("write upload");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), upload.read_to_end(&mut response)).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let first = tokio::time::timeout(Duration::from_secs(5), observed.recv())
        .await
        .expect("upload observation")
        .expect("draining backend stopped");
    assert_eq!(
        first.method, "POST",
        "the probe must not be reported: {first:?}"
    );
    assert_eq!(first.target, "/probe-check");
    assert_eq!(first.body_len, 4);
    assert!(
        observed.try_recv().is_err(),
        "exactly one observation expected"
    );
    backend.abort();
}

/// Send an HTTP/1.1 trigger that declares its `Content-Length` and return the
/// status line of the gateway's response.
async fn send_declared_h1_trigger(port: u16, target: &str, body_len: usize) -> String {
    let request_head = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost\r\nX-Loadtesting-Key: {TRIGGER_KEY}\r\nContent-Type: application/octet-stream\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
    );
    let response = tokio::time::timeout(Duration::from_secs(30), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect H1 gateway");
        stream
            .write_all(request_head.as_bytes())
            .await
            .expect("write H1 request head");
        let piece = vec![b'x'; 64 * 1024];
        let mut remaining = body_len;
        while remaining > 0 {
            let size = remaining.min(piece.len());
            // The gateway may answer early (for example a 413) and close;
            // stop writing then and read whatever it answered.
            if stream.write_all(&piece[..size]).await.is_err() {
                break;
            }
            remaining -= size;
        }
        let _ = stream.flush().await;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        response
    })
    .await
    .expect("declared H1 trigger deadline");
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[ignore]
#[tokio::test]
async fn functional_load_testing_declared_oversized_trigger_is_forwarded_without_a_run() {
    const TARGET: &str = "/load-oversize/upload";
    let (backend_port, mut observed, backend) = spawn_draining_backend().await;
    let config = serde_json::json!({
        "version": "1",
        "proxies": [replay_proxy(
            "load-oversize",
            "/load-oversize",
            backend_port,
            "load-plugin-oversize"
        )],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [replay_plugin("load-plugin-oversize", "load-oversize")]
    });
    let config = serde_yaml::to_string(&config).expect("serialize oversize config");
    let mut gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        // The route admits uploads larger than the replay ceiling.
        .env(
            "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
            (32 * 1024 * 1024).to_string(),
        )
        .spawn()
        .await
        .expect("start oversize gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("oversize gateway proxy port");

    let body_len = REPLAY_CEILING_BYTES + 1;
    let status_line = send_declared_h1_trigger(gateway.proxy_port, TARGET, body_len).await;
    assert!(
        status_line.starts_with("HTTP/1.1 200"),
        "a declared oversized trigger body must not block the primary request: {status_line}"
    );

    // Only application POSTs to the route count; anything else the backend
    // might see is not the behavior under test.
    let deadline = Instant::now() + Duration::from_secs(10);
    let primary = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let request = tokio::time::timeout(remaining, observed.recv())
            .await
            .expect("primary request must reach the backend")
            .expect("draining backend stopped");
        if request.method == "POST" && request.target == TARGET {
            break request;
        }
    };
    assert_eq!(
        primary.body_len, body_len,
        "the backend must receive the complete body"
    );

    // No cohort starts for a body that cannot be replayed: no further POST to
    // the route arrives during (and just after) the one-second run window.
    let window_end = Instant::now() + Duration::from_millis(1500);
    loop {
        let remaining = window_end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, observed.recv()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(request)) => assert!(
                !(request.method == "POST" && request.target == TARGET),
                "an oversized trigger must start no synthetic requests: {request:?}"
            ),
        }
    }

    gateway.shutdown();
    backend.abort();
}
