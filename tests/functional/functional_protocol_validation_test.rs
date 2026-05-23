//! Functional tests for protocol-level request validation.
//!
//! Launches a real `ferrum-edge` binary in file mode against a raw-TCP echo backend
//! that reflects headers as JSON, then exercises:
//!
//! - HTTP/1.0 + `Transfer-Encoding` rejection (RFC 9112 §6.2)
//! - `Content-Length` + `Transfer-Encoding` smuggling conflict (RFC 9112 §6.1)
//! - Multiple `Content-Length` with conflicting values
//! - Non-numeric `Content-Length` (negative, decimal, hex, alpha)
//! - Multiple `Host` headers (HTTP/1.1)
//! - `Host` trailing-dot normalization
//! - `FERRUM_MAX_HEADER_SIZE_BYTES` total-header rejection on H1
//! - Configured request header count limits and `0` disable semantics
//! - `TRACE` method rejection (XST) on H1 and H2
//! - `FERRUM_MAX_HEADER_SIZE_BYTES` total-header rejection on H2
//! - `Transfer-Encoding` rejection on H3
//! - Empty query segments are ignored by HTTP/3 query-param limit counting
//! - Query parameter counting parity on H3
//! - `CONNECT` method rejection on H1 (non-WebSocket)
//! - HTTP/1.1 slow/incomplete header timeout, including `0` disable semantics
//! - Request-side hop-by-hop header stripping (backend must not see `Transfer-Encoding`)
//! - Response-side hop-by-hop header stripping (client must not see `Proxy-Authenticate`,
//!   `Keep-Alive`, `Trailer`, etc. from the backend) on H1, H2, and H3
//!
//! HTTP/3 validation is covered by unit tests in `tests/unit/gateway_core/protocol_validation_tests.rs`
//! plus targeted functional QUIC/H3 checks here.
//!
//! Run: `cargo test --test functional_tests -- --ignored functional_protocol_validation --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use bytes::Bytes;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

// ============================================================================
// Header-echo TCP backend
// ============================================================================

/// Raw-TCP HTTP server that reflects request headers as a JSON body.
///
/// The backend is intentionally raw so tests can exercise the *unmodified*
/// behavior the gateway observes (no reqwest/hyper normalization on the
/// server side).
async fn start_header_echo_server_on(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);

            let mut headers_json = serde_json::Map::new();
            for line in request.lines().skip(1) {
                if line.is_empty() {
                    break;
                }
                if let Some((key, value)) = line.split_once(": ") {
                    let key_lc = key.to_lowercase();
                    match headers_json.get_mut(&key_lc) {
                        Some(serde_json::Value::Array(arr)) => {
                            arr.push(serde_json::Value::String(value.to_string()));
                        }
                        Some(existing) => {
                            let prev = existing.as_str().unwrap_or("").to_string();
                            *existing = serde_json::Value::Array(vec![
                                serde_json::Value::String(prev),
                                serde_json::Value::String(value.to_string()),
                            ]);
                        }
                        None => {
                            headers_json
                                .insert(key_lc, serde_json::Value::String(value.to_string()));
                        }
                    }
                }
            }

            let body = serde_json::to_string(&headers_json).unwrap_or_default();
            // Include hop-by-hop-ish headers in the response so we can assert the
            // gateway strips them before handing the response to the client.
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {len}\r\n\
                 Content-Type: application/json\r\n\
                 X-Backend-Marker: echoed\r\n\
                 Connection: keep-alive, Upgrade, Keep-Alive\r\n\
                 Keep-Alive: timeout=5\r\n\
                 Proxy-Authenticate: Basic realm=\"test\"\r\n\
                 Proxy-Connection: keep-alive\r\n\
                 Trailer: X-Custom-Trailer\r\n\
                 TE: trailers\r\n\
                 Upgrade: websocket\r\n\
                 \r\n\
                 {body}",
                len = body.len(),
                body = body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

// ============================================================================
// Raw H1 request helper
// ============================================================================

/// Response parsed from a raw HTTP/1.x exchange. Kept minimal — only what the
/// assertions need.
struct RawResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// Send a pre-built raw HTTP request over a fresh TCP connection and parse the
/// status line, headers, and body. Used when the request itself must violate
/// HTTP framing (CL+TE, multi-Host, etc.) — `reqwest` refuses to emit these.
async fn send_raw_h1(proxy_port: u16, raw: &[u8]) -> RawResponse {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to gateway");
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(raw).await.expect("send raw request");
    write_half.flush().await.expect("flush");
    // NOTE: intentionally NOT calling write_half.shutdown() — a half-close can
    // cause hyper to drop the connection before writing the error response.
    // Reading with a timeout is enough to keep the test bounded.

    let mut reader = BufReader::new(read_half);

    // Status line (with timeout so malformed requests that the gateway silently
    // drops still fail fast instead of hanging)
    let mut status_line = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        reader.read_until(b'\n', &mut status_line),
    )
    .await;
    let status_str = String::from_utf8_lossy(&status_line);
    let status_code = status_str
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // Headers
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut transfer_chunked = false;
    loop {
        let mut line = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut line)).await;
        let n = match read_result {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        if n == 0 {
            break;
        }
        let line_str = String::from_utf8_lossy(&line);
        let trimmed = line_str.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().ok();
            }
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                transfer_chunked = true;
            }
            headers.push((key, val));
        }
    }

    // Body: if Content-Length is known, read exactly that; otherwise fall
    // back to read-to-end. All reads are bounded by a short timeout so the test
    // never hangs when the gateway closes the connection after the error response.
    let body = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        let _ = tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), reader.read_to_end(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    let _ = transfer_chunked;

    RawResponse {
        status_code,
        headers,
        body,
    }
}

fn header_value<'a>(hdrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hdrs.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn assert_hop_by_hop_response_headers_stripped(hdrs: &HeaderMap) {
    for banned in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        // `connection` is one the gateway may emit itself to manage client
        // keep-alive — allow it to exist as long as it wasn't the backend's
        // comma-list value containing "Upgrade".
        if banned == "connection" {
            if let Some(v) = hdrs.get("connection") {
                let vs = v.to_str().unwrap_or("").to_ascii_lowercase();
                assert!(
                    !vs.contains("upgrade"),
                    "backend's Connection: Upgrade leaked to client: {vs:?}"
                );
            }
            continue;
        }
        assert!(
            hdrs.get(banned).is_none(),
            "hop-by-hop header `{banned}` should be stripped from client response; \
             all_headers={hdrs:?}"
        );
    }

    // Sanity: the gateway kept at least one backend application header.
    assert!(
        hdrs.get("x-backend-marker").is_some(),
        "non-hop-by-hop backend header should pass through; headers={hdrs:?}"
    );
fn parse_status_from_response_prefix(bytes: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(bytes);
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
async fn send_h2_with_headers(proxy_port: u16, headers: &[(&str, &str)]) -> (u16, String) {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method("GET").uri("http://example.com/");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("send h2 request");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body).into_owned();

    drop(sender);
    conn_task.abort();
    (status, body)
}

// ============================================================================
// Config + test harness
// ============================================================================

/// Build a minimal FILE-mode YAML config pointing to the echo backend.
/// When `with_host` is true, the proxy is restricted to `example.com` so the
/// trailing-dot test can exercise host-based routing.
fn build_config(echo_port: u16, with_host: bool) -> String {
    let hosts_line = if with_host {
        "    hosts:\n      - \"example.com\"\n"
    } else {
        ""
    };
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"echo-http\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {echo_port}\n\
         \x20   strip_listen_path: false\n\
         {hosts}\
         consumers: []\n\
         plugin_configs: []\n",
        hosts = hosts_line,
    )
}

/// Harness that spins up an echo backend + gateway in file mode.
struct Harness {
    _gateway: TestGateway,
    echo_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
}

impl Harness {
    async fn new(with_host: bool) -> Self {
        Self::new_with_env(with_host, &[]).await
    }

    async fn new_with_env(with_host: bool, extra_env: &[(&str, &str)]) -> Self {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
        sleep(Duration::from_millis(150)).await;

        let mut builder = TestGateway::builder()
            .mode_file(build_config(echo_port, with_host))
            .log_level("warn");
        for (key, value) in extra_env {
            builder = builder.env(*key, *value);
        }

        let gateway = builder.spawn().await.expect("start gateway");
        // `wait_for_health` only verifies the admin port. The proxy listener
        // is bound on a separate spawned task; on a loaded CI runner there is
        // a brief window where `/health` is green but raw `TcpStream::connect`
        // to the proxy port hits `ConnectionRefused`. This test file bypasses
        // `reqwest` (raw HTTP framing + hyper H2 prior knowledge), so we wait
        // for the proxy port explicitly before any test exercises it.
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port did not become ready");
        Harness {
            proxy_port: gateway.proxy_port,
            _gateway: gateway,
            echo_task,
        }
    }

    fn cleanup(self) {
        self.echo_task.abort();
    }
}

async fn start_h3_validation_gateway(
    echo_port: u16,
    extra_env: &[(&str, &str)],
) -> (TestGateway, u16) {
    let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_reservation.local_addr().unwrap().port();
    drop(https_reservation);

    let mut builder = TestGateway::builder()
        .mode_file(build_config(echo_port, false))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key");

    for (key, value) in extra_env {
        builder = builder.env(*key, *value);
    }

    let gateway = builder.spawn().await.expect("start gateway with h3");
    (gateway, https_port)
}

async fn h3_get_with_startup_retry(
    client: &Http3Client,
    url: &str,
    options: GetOptions,
) -> Http3Response {
    let mut last_err = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(resp) => return resp,
            Err(err) if std::time::Instant::now() < deadline => {
                last_err = Some(err.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 request did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

// --- 1. HTTP/1.0 + Transfer-Encoding ---------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_http10_plus_te_rejected() {
    let h = Harness::new(false).await;

    let req = b"GET / HTTP/1.0\r\n\
                Host: example.com\r\n\
                Transfer-Encoding: chunked\r\n\
                \r\n";
    let resp = send_raw_h1(h.proxy_port, req).await;

    // Either hyper rejects this at parse time (empty body) or the gateway's
    // check_protocol_headers() produces its JSON body. In both cases status
    // must be 4xx (never 2xx).
    assert!(
        resp.status_code >= 400 && resp.status_code < 500,
        "expected 4xx rejection, got status={} body={}",
        resp.status_code,
        resp.body
    );

    h.cleanup();
}

// --- 2. CL + TE conflict on H1 ---------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_cl_and_te_rejected() {
    let h = Harness::new(false).await;

    let req = b"POST / HTTP/1.1\r\n\
                Host: example.com\r\n\
                Content-Length: 5\r\n\
                Transfer-Encoding: chunked\r\n\
                \r\n\
                0\r\n\r\n";
    let resp = send_raw_h1(h.proxy_port, req).await;

    assert_eq!(resp.status_code, 400, "body={}", resp.body);
    assert!(
        resp.body
            .contains("Request contains both Content-Length and Transfer-Encoding"),
        "unexpected body: {}",
        resp.body
    );

    h.cleanup();
}

// --- 3. Multiple Content-Length (conflicting values) -----------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_multiple_content_length_conflicting() {
    let h = Harness::new(false).await;

    let req = b"POST / HTTP/1.1\r\n\
                Host: example.com\r\n\
                Content-Length: 5\r\n\
                Content-Length: 7\r\n\
                \r\n\
                hello";
    let resp = send_raw_h1(h.proxy_port, req).await;

    // hyper may reject malformed CL framing before the gateway's handler runs,
    // producing an empty-bodied 4xx response. Either way the request MUST NOT
    // be forwarded as a valid 2xx.
    assert!(
        resp.status_code >= 400 && resp.status_code < 500,
        "expected 4xx rejection, got status={} body={}",
        resp.status_code,
        resp.body
    );

    h.cleanup();
}

// --- 4. Non-numeric Content-Length -----------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_non_numeric_content_length() {
    let h = Harness::new(false).await;

    for bad_cl in ["abc", "-1", "1.5", "0x10"] {
        let req = format!(
            "POST / HTTP/1.1\r\n\
             Host: example.com\r\n\
             Content-Length: {bad_cl}\r\n\
             \r\n"
        );
        let resp = send_raw_h1(h.proxy_port, req.as_bytes()).await;
        assert!(
            resp.status_code >= 400 && resp.status_code < 500,
            "Content-Length={bad_cl} should yield 4xx, got {} body={}",
            resp.status_code,
            resp.body
        );
    }

    h.cleanup();
}

// --- 5. Multiple Host headers ----------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_multiple_host_headers_rejected() {
    let h = Harness::new(false).await;

    let req = b"GET / HTTP/1.1\r\n\
                Host: example.com\r\n\
                Host: evil.com\r\n\
                \r\n";
    let resp = send_raw_h1(h.proxy_port, req).await;

    assert_eq!(resp.status_code, 400, "body={}", resp.body);
    assert!(
        resp.body.to_lowercase().contains("multiple host"),
        "unexpected body: {}",
        resp.body
    );

    h.cleanup();
}

// --- 6. Host trailing dot normalizes ---------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_host_trailing_dot_normalized() {
    // This proxy is scoped to host `example.com` — both `example.com` and
    // `example.com.` must route to it and reach the backend.
    let h = Harness::new(true).await;

    let req_dot = b"GET / HTTP/1.1\r\n\
                    Host: example.com.\r\n\
                    \r\n";
    let resp_dot = send_raw_h1(h.proxy_port, req_dot).await;
    assert_eq!(
        resp_dot.status_code, 200,
        "example.com. should route; body={}",
        resp_dot.body
    );
    // Backend reflects its marker so we know we actually hit it.
    let body_lc = resp_dot.body.to_lowercase();
    assert!(
        body_lc.contains("x-backend-marker")
            || header_value(&resp_dot.headers, "x-backend-marker").is_some(),
        "trailing-dot request should reach backend; body={}",
        resp_dot.body
    );

    let req_plain = b"GET / HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      \r\n";
    let resp_plain = send_raw_h1(h.proxy_port, req_plain).await;
    assert_eq!(
        resp_plain.status_code, 200,
        "example.com should route; body={}",
        resp_plain.body
    );

    h.cleanup();
}

// --- 7. Header count limit env ---------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h1_header_count_env_rejects_excess_headers() {
    let h = Harness::new_with_env(false, &[("FERRUM_MAX_HEADER_COUNT", "2")]).await;

    let req = b"GET / HTTP/1.1\r\n\
                Host: example.com\r\n\
                X-One: 1\r\n\
                X-Two: 2\r\n\
                \r\n";
    let resp = send_raw_h1(h.proxy_port, req).await;

    assert_eq!(resp.status_code, 431, "body={}", resp.body);
    assert!(
        resp.body.contains("Request header count"),
        "unexpected body: {}",
        resp.body
    );

    h.cleanup();
}

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h1_header_count_zero_disables_limit() {
    let h = Harness::new_with_env(false, &[("FERRUM_MAX_HEADER_COUNT", "0")]).await;

    let mut req = String::from("GET / HTTP/1.1\r\nHost: example.com\r\n");
    for i in 0..16 {
        req.push_str(&format!("X-Extra-{i}: {i}\r\n"));
    }
    req.push_str("\r\n");

    let resp = send_raw_h1(h.proxy_port, req.as_bytes()).await;
    assert_eq!(
        resp.status_code, 200,
        "header count 0 should disable the gateway count limit; body={}",
        resp.body
    );
    let reflected: serde_json::Value = serde_json::from_str(&resp.body)
        .unwrap_or_else(|e| panic!("backend body not JSON: {} ({e})", resp.body));
    assert!(
        reflected.get("x-extra-15").is_some(),
        "backend should receive the high-count request when count limit is disabled; reflected={reflected}"
    );

    h.cleanup();
}

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h2_header_count_env_rejects_excess_headers() {
    let h = Harness::new_with_env(false, &[("FERRUM_MAX_HEADER_COUNT", "1")]).await;

    let (status, body) =
        send_h2_with_headers(h.proxy_port, &[("x-one", "1"), ("x-two", "2")]).await;

    assert_eq!(status, 431, "body={body}");
    assert!(
        body.contains("Request header count"),
        "unexpected body: {body}"
    );

    h.cleanup();
}

// --- 8. TRACE on H1 and H2 -------------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_trace_rejected_http1() {
    let h = Harness::new(false).await;

    let req = b"TRACE / HTTP/1.1\r\n\
                Host: example.com\r\n\
                \r\n";
    let resp = send_raw_h1(h.proxy_port, req).await;

    assert_eq!(resp.status_code, 405, "body={}", resp.body);
    assert!(
        resp.body.contains("TRACE"),
        "unexpected body: {}",
        resp.body
    );

    h.cleanup();
}

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_trace_rejected_http2() {
    let h = Harness::new(false).await;

    // Speak HTTP/2 with prior knowledge (no ALPN/TLS).
    let stream = TcpStream::connect(("127.0.0.1", h.proxy_port))
        .await
        .expect("connect");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("TRACE")
        .uri("http://example.com/")
        .header("host", "example.com")
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let resp = sender.send_request(req).await.expect("send TRACE");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body);

    assert_eq!(status, 405, "body={body_str}");
    assert!(body_str.contains("TRACE"), "unexpected body: {body_str}");

    drop(sender);
    conn_task.abort();
    h.cleanup();
}

// --- 8. Total header size on H2 -------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h2_total_header_size_limit_rejects_from_env() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
    sleep(Duration::from_millis(150)).await;

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(echo_port, false))
        .log_level("warn")
        .env("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "8192")
        .env("FERRUM_MAX_HEADER_SIZE_BYTES", "9000")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port did not become ready");

    let stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .expect("connect");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("http://example.com/")
        .header("host", "example.com")
        .header("x-one", "1".repeat(5000))
        .header("x-two", "2".repeat(5000))
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let resp = sender
        .send_request(req)
        .await
        .expect("send total-header request");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body);

    assert_eq!(status, 431, "body={body_str}");
    assert!(
        body_str.contains("Total request headers exceed maximum size"),
        "unexpected body: {body_str}"
    );

    drop(sender);
    conn_task.abort();
    gateway.shutdown();
    echo_task.abort();
}

// --- 9. Transfer-Encoding on H3 -------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h3_transfer_encoding_rejected() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
    sleep(Duration::from_millis(150)).await;

    let (mut gateway, https_port) = start_h3_validation_gateway(echo_port, &[]).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/");
    let options = GetOptions::default().header("transfer-encoding", "chunked");
    let resp = h3_get_with_startup_retry(&client, &url, options).await;

    assert_eq!(resp.status.as_u16(), 400, "body={}", resp.body_text());
    assert!(
        resp.body_text().contains("Transfer-Encoding"),
        "unexpected body: {}",
        resp.body_text()
    );

    gateway.shutdown();
    echo_task.abort();
}

// --- 9. Empty query segments on H3 query-param limits ----------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h3_empty_query_segments_do_not_count_against_limit() {
#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h3_query_param_limit_ignores_empty_segments() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
    sleep(Duration::from_millis(150)).await;

    let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_reservation.local_addr().unwrap().port();
    drop(https_reservation);

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(echo_port, false))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env("FERRUM_MAX_QUERY_PARAMS", "2")
        .spawn()
        .await
        .expect("start gateway with h3");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/?a=1&&b=2");
    let mut last_err = None;
    let resp = {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match client.get(&url).await {
                Ok(resp) => break resp,
                Err(err) if std::time::Instant::now() < deadline => {
                    last_err = Some(err.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => {
                    panic!(
                        "H3 request with empty query segment did not complete; last startup error={last_err:?}; final error={err}"
                    );
                }
            }
        }
    };

    assert_eq!(resp.status.as_u16(), 200, "body={}", resp.body_text());

    gateway.shutdown();
    echo_task.abort();
}

// --- 10. Total header size on H1 -------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h1_total_header_size_limit_rejects_from_env() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
    sleep(Duration::from_millis(150)).await;

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(echo_port, false))
        .log_level("warn")
        .env("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "64")
        .env("FERRUM_MAX_HEADER_SIZE_BYTES", "20")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port did not become ready");

    let req = b"GET / HTTP/1.1\r\n\
                Host: x\r\n\
                X-One: 1234567890\r\n\
                X-Two: abcdefghij\r\n\
                \r\n";
    let resp = send_raw_h1(gateway.proxy_port, req).await;

    assert_eq!(resp.status_code, 431, "body={}", resp.body);
    assert!(
        resp.body
            .contains("Total request headers exceed maximum size"),
        "unexpected body: {}",
        resp.body
    let (mut gateway, https_port) =
        start_h3_validation_gateway(echo_port, &[("FERRUM_MAX_QUERY_PARAMS", "2")]).await;

    let client = Http3Client::insecure().expect("H3 client");
    let allowed_url = format!("https://localhost:{https_port}/?a=1&&b=2&");
    let allowed = h3_get_with_startup_retry(&client, &allowed_url, GetOptions::default()).await;
    assert_eq!(
        allowed.status.as_u16(),
        200,
        "empty query segments must not count as params; body={}",
        allowed.body_text()
    );

    let rejected_url = format!("https://localhost:{https_port}/?a=1&b=2&c=3");
    let rejected = h3_get_with_startup_retry(&client, &rejected_url, GetOptions::default()).await;
    assert_eq!(
        rejected.status.as_u16(),
        400,
        "three non-empty params should exceed FERRUM_MAX_QUERY_PARAMS=2; body={}",
        rejected.body_text()
    );
    assert!(
        rejected
            .body_text()
            .contains("Query parameter count (3) exceeds maximum of 2"),
        "unexpected body: {}",
        rejected.body_text()
    );

    gateway.shutdown();
    echo_task.abort();
}

// --- 11. CONNECT on H1 ------------------------------------------------------
// --- 10. CONNECT on H1 ------------------------------------------------------
// --- 9. CONNECT on H1 -------------------------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_connect_rejected_http1() {
    let h = Harness::new(false).await;

    let req = b"CONNECT example.com:443 HTTP/1.1\r\n\
                Host: example.com:443\r\n\
                \r\n";
    let resp = send_raw_h1(h.proxy_port, req).await;

    // Hyper may refuse malformed CONNECT before the handler ever runs; accept
    // any 4xx with a CONNECT-y body. In practice the gateway returns 405.
    assert!(
        (400..500).contains(&resp.status_code),
        "unexpected status: {} body={}",
        resp.status_code,
        resp.body
    );
    if resp.status_code == 405 {
        assert!(
            resp.body.contains("CONNECT"),
            "unexpected body: {}",
            resp.body
        );
    }

    h.cleanup();
}

// --- 11. Backend sees sanitized request (hop-by-hop headers stripped) ------
// --- 10. H1 slow header timeout env ----------------------------------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h1_header_timeout_closes_incomplete_request() {
    let h = Harness::new_with_env(false, &[("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "1")]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", h.proxy_port))
        .await
        .expect("connect to gateway");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Slow:")
        .await
        .expect("write partial request headers");
    stream.flush().await.expect("flush partial request");

    let mut first = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(4), stream.read(&mut first)).await {
        Err(_) => panic!("gateway kept incomplete H1 headers open past configured timeout"),
        Ok(Ok(0)) => {}
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(Err(err)) => panic!("unexpected read error after header timeout: {err}"),
        Ok(Ok(n)) => {
            let mut response = first[..n].to_vec();
            let _ = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
                .await;
            let status = parse_status_from_response_prefix(&response).unwrap_or(0);
            assert!(
                (400..500).contains(&status),
                "slow incomplete headers should be rejected, got status={status} body={}",
                String::from_utf8_lossy(&response)
            );
        }
    }

    let resp = send_raw_h1(h.proxy_port, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(
        resp.status_code, 200,
        "gateway should continue serving valid H1 requests after timing out a slow header; body={}",
        resp.body
    );

    h.cleanup();
}

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_h1_header_timeout_zero_disables_timer() {
    let h = Harness::new_with_env(false, &[("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "0")]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", h.proxy_port))
        .await
        .expect("connect to gateway");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Slow:")
        .await
        .expect("write partial request headers");
    stream.flush().await.expect("flush partial request");

    let mut one = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(1400), stream.read(&mut one)).await;
    assert!(
        read.is_err(),
        "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 should leave incomplete H1 headers open; read result={read:?}"
    );
    drop(stream);

    let resp = send_raw_h1(h.proxy_port, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert_eq!(
        resp.status_code, 200,
        "gateway should still accept valid H1 requests when header timeout is disabled; body={}",
        resp.body
    );

    h.cleanup();
}

// --- 12. Backend sees sanitized request (hop-by-hop headers stripped) ------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_request_te_stripped_before_backend() {
    let h = Harness::new(false).await;

    // Hop-by-hop request headers (per RFC 9110 §7.6.1) MUST NOT reach the
    // backend. We use reqwest here because raw H1.1 Transfer-Encoding without
    // chunked is itself a framing violation; instead send Connection, Upgrade,
    // Keep-Alive via reqwest and verify the backend doesn't see them.
    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("reqwest client");
    let resp = client
        .get(format!("http://127.0.0.1:{}/", h.proxy_port))
        .header("Upgrade", "h2c")
        .header("Proxy-Connection", "keep-alive")
        .send()
        .await
        .expect("request through gateway");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.expect("body");
    // Backend reflects headers it saw as JSON.
    let reflected: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("backend body not JSON: {body} ({e})"));
    for hop in ["upgrade", "proxy-connection"] {
        assert!(
            reflected.get(hop).is_none(),
            "backend MUST NOT see hop-by-hop header '{hop}'; reflected={reflected}"
        );
    }

    h.cleanup();
}

// --- 12. Response hop-by-hop headers stripped before client ----------------
// --- 13. Response hop-by-hop headers stripped before client ----------------

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_response_hop_by_hop_stripped() {
    // Backend emits Connection/Keep-Alive/Proxy-Authenticate/Trailer/TE/Upgrade.
    // Client-visible response must have all of these stripped per RFC 9110 §7.6.1.
    let h = Harness::new(false).await;

    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("reqwest client");
    let resp = client
        .get(format!("http://127.0.0.1:{}/", h.proxy_port))
        .header("Host", "example.com")
        .send()
        .await
        .expect("request through gateway");

    assert_eq!(resp.status().as_u16(), 200);
    let hdrs = resp.headers().clone();

    assert_hop_by_hop_response_headers_stripped(&hdrs);

    h.cleanup();
}

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_response_hop_by_hop_stripped_http2() {
    let h = Harness::new(false).await;

    let stream = TcpStream::connect(("127.0.0.1", h.proxy_port))
        .await
        .expect("connect h2 gateway");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("http://example.com/")
        .header("host", "example.com")
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("send h2 request");
    assert_eq!(resp.status().as_u16(), 200);
    let hdrs = resp.headers().clone();
    let _ = resp
        .into_body()
        .collect()
        .await
        .expect("collect h2 body")
        .to_bytes();

    assert_hop_by_hop_response_headers_stripped(&hdrs);

    drop(sender);
    conn_task.abort();
    h.cleanup();
}

#[ignore]
#[tokio::test]
async fn functional_protocol_validation_response_hop_by_hop_stripped_http3() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
    sleep(Duration::from_millis(150)).await;

    let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_reservation.local_addr().unwrap().port();
    drop(https_reservation);

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(echo_port, false))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start gateway with h3");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/");
    let response = {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match client.get(&url).await {
                Ok(resp) => break resp,
                Err(err) if std::time::Instant::now() < deadline => {
                    let _ = err;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => panic!("H3 request did not complete: {err}"),
            }
        }
    };

    assert_eq!(
        response.status.as_u16(),
        200,
        "body={}",
        response.body_text()
    );
    assert_hop_by_hop_response_headers_stripped(&response.headers);

    gateway.shutdown();
    echo_task.abort();
}
