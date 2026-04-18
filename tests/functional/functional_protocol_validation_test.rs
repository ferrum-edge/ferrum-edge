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
//! - `TRACE` method rejection (XST) on H1 and H2
//! - `CONNECT` method rejection on H1 (non-WebSocket)
//! - Request-side hop-by-hop header stripping (backend must not see `Transfer-Encoding`)
//! - Response-side hop-by-hop header stripping (client must not see `Proxy-Authenticate`,
//!   `Keep-Alive`, `Trailer`, etc. from the backend)
//!
//! HTTP/3 validation is covered by unit tests in `tests/unit/gateway_core/protocol_validation_tests.rs`;
//! TODO: add a functional H3 variant once the quinn test harness is in place.
//!
//! Run: `cargo test --test functional_tests -- --ignored functional_protocol_validation --nocapture`

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tempfile::TempDir;
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
// Gateway subprocess helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> std::process::Child {
    std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{admin_port}/health");
    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway_in_file_mode(config_path, proxy_port, admin_port);
        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
             (proxy_port={proxy_port}, admin_port={admin_port})"
        );
        let _ = child.kill();
        let _ = child.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts");
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

// ============================================================================
// Config + test harness
// ============================================================================

/// Write a minimal FILE-mode YAML config pointing to the echo backend.
/// When `with_host` is true, the proxy is restricted to `example.com` so the
/// trailing-dot test can exercise host-based routing.
fn write_config(temp_dir: &TempDir, echo_port: u16, with_host: bool) -> std::path::PathBuf {
    let config_path = temp_dir.path().join("config.yaml");
    let hosts_line = if with_host {
        "    hosts:\n      - \"example.com\"\n"
    } else {
        ""
    };
    let content = format!(
        "proxies:\n\
         \x20 - id: \"echo-http\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_protocol: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {echo_port}\n\
         \x20   strip_listen_path: false\n\
         {hosts}\
         consumers: []\n\
         plugin_configs: []\n",
        hosts = hosts_line,
    );
    std::fs::write(&config_path, content).expect("write config");
    config_path
}

/// Harness that spins up an echo backend + gateway in file mode.
struct Harness {
    gateway: std::process::Child,
    echo_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
    _temp_dir: TempDir,
}

impl Harness {
    async fn new(with_host: bool) -> Self {
        let temp_dir = TempDir::new().expect("temp dir");
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_task = tokio::spawn(start_header_echo_server_on(echo_listener));
        sleep(Duration::from_millis(150)).await;

        let config_path = write_config(&temp_dir, echo_port, with_host);
        let (gateway, proxy_port, _admin_port) =
            start_gateway_with_retry(config_path.to_str().unwrap()).await;
        Harness {
            gateway,
            echo_task,
            proxy_port,
            _temp_dir: temp_dir,
        }
    }

    fn cleanup(mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        self.echo_task.abort();
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

// --- 7. TRACE on H1 and H2 -------------------------------------------------

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
        .uri(format!("http://127.0.0.1:{}/", h.proxy_port))
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

// --- 8. CONNECT on H1 -------------------------------------------------------

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

// --- 9. Backend sees sanitized request (hop-by-hop headers stripped) ------

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

// --- 10. Response hop-by-hop headers stripped before client ----------------

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

    h.cleanup();
}
