//! Functional tests for request-size limits on unknown-length request bodies.
//!
//! These cover `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` when the inbound request
//! has no `Content-Length` and must be limited while the body is read, and the
//! `request_size_limiting` route ceiling for HTTP/2 `GET`/`HEAD`/`OPTIONS`
//! uploads that carry DATA without `Content-Length` toward an HTTP/1.1 backend.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;

use bytes::Bytes;
use futures_util::stream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct ChunkedRequestHarness {
    _gateway: TestGateway,
    backend_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
}

/// Which size policy the harness gateway enforces.
enum SizePolicy {
    /// `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` only, no plugin.
    Global(String),
    /// A `request_size_limiting` route ceiling, with the direct HTTP/1.1 pool
    /// on or off (`FERRUM_POOL_HTTP1_DIRECT`).
    Route {
        max_bytes: u64,
        pool_http1_direct: bool,
    },
}

impl ChunkedRequestHarness {
    async fn new(max_request_bytes: &str) -> Self {
        Self::spawn(SizePolicy::Global(max_request_bytes.to_string())).await
    }

    async fn with_route_limit(max_bytes: u64, pool_http1_direct: bool) -> Self {
        Self::spawn(SizePolicy::Route {
            max_bytes,
            pool_http1_direct,
        })
        .await
    }

    async fn spawn(policy: SizePolicy) -> Self {
        let mut last_error = None;
        for attempt in 1..=3 {
            match Self::try_new(&policy).await {
                Ok(harness) => return harness,
                Err(error) => {
                    eprintln!("chunked request harness attempt {attempt}/3 failed: {error}");
                    last_error = Some(error);
                }
            }
        }
        panic!(
            "chunked request harness did not start after 3 fresh-port attempts: {}",
            last_error.unwrap_or_else(|| "no startup error recorded".to_string())
        );
    }

    async fn try_new(policy: &SizePolicy) -> Result<Self, String> {
        let backend_listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .map_err(|error| format!("bind backend: {error}"))?;
        let backend_port = backend_listener
            .local_addr()
            .map_err(|error| format!("backend addr: {error}"))?
            .port();

        let builder = match policy {
            SizePolicy::Global(max_request_bytes) => TestGateway::builder()
                .mode_file(build_config(backend_port))
                .env(
                    "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
                    max_request_bytes.as_str(),
                ),
            SizePolicy::Route {
                max_bytes,
                pool_http1_direct,
            } => TestGateway::builder()
                .mode_file(build_route_limit_config(backend_port, *max_bytes))
                .env(
                    "FERRUM_POOL_HTTP1_DIRECT",
                    if *pool_http1_direct { "true" } else { "false" },
                )
                .env("FERRUM_POOL_WARMUP_ENABLED", "false"),
        };
        let gateway = builder
            .log_level("warn")
            .capture_output()
            .spawn()
            .await
            .map_err(|error| format!("start gateway: {error}"))?;
        let backend_task = tokio::spawn(run_body_len_backend(backend_listener));
        let harness = Self {
            proxy_port: gateway.proxy_port,
            _gateway: gateway,
            backend_task,
        };
        if let Err(error) = harness
            ._gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
        {
            let output = harness
                ._gateway
                .read_combined_captured_output()
                .unwrap_or_else(|read_error| format!("<failed to read output: {read_error}>"));
            return Err(format!(
                "proxy port ready: {error}\n--- captured gateway output ---\n{output}"
            ));
        }
        Ok(harness)
    }
}

impl Drop for ChunkedRequestHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "chunked-request-size-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    )
}

/// One route to the body-length backend with only `request_size_limiting`
/// attached, so no plugin buffers the body and the default streaming
/// dispatcher is the one under test.
fn build_route_limit_config(backend_port: u16, max_bytes: u64) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "route-limit-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "route-limit"

consumers: []
plugin_configs:
  - id: "route-limit"
    proxy_id: "route-limit-proxy"
    plugin_name: "request_size_limiting"
    scope: "proxy"
    enabled: true
    config:
      max_bytes: {max_bytes}
"#
    )
}

async fn run_body_len_backend(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let request = read_http_request(&mut stream).await;
            let body_len = request_body_len(&request);
            let framing = request_framing(&request);
            let body = format!(r#"{{"body_len":{body_len}}}"#);
            // The observations are echoed as headers too, so a HEAD request,
            // whose response carries no body, can still be checked.
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/json\r\n\
                 X-Observed-Body-Len: {body_len}\r\n\
                 X-Observed-Request-Framing: {framing}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let mut header_end = None;

    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none() {
            header_end = find_header_end(&buf);
        }
        if let Some(end) = header_end
            && request_body_complete(&buf, end)
        {
            break;
        }
        if buf.len() > 128 * 1024 {
            break;
        }
    }

    buf
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn request_body_complete(buf: &[u8], header_end: usize) -> bool {
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    if let Some(value) = header_value(&headers, "content-length") {
        let Ok(len) = value.parse::<usize>() else {
            return true;
        };
        return buf.len() >= header_end + len;
    }
    if header_value(&headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return decode_chunked_body(&buf[header_end..]).is_some();
    }
    true
}

/// Which body framing the backend saw on the request head: `content-length`,
/// `chunked`, or `none`.
fn request_framing(request: &[u8]) -> &'static str {
    let Some(header_end) = find_header_end(request) else {
        return "none";
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    if header_value(&headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        "chunked"
    } else if header_value(&headers, "content-length").is_some() {
        "content-length"
    } else {
        "none"
    }
}

fn request_body_len(request: &[u8]) -> usize {
    let Some(header_end) = find_header_end(request) else {
        return 0;
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    if let Some(value) = header_value(&headers, "content-length")
        && let Ok(len) = value.parse::<usize>()
    {
        return request.len().saturating_sub(header_end).min(len);
    }
    if header_value(&headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return decode_chunked_body(&request[header_end..])
            .map(|body| body.len())
            .unwrap_or(0);
    }
    request.len().saturating_sub(header_end)
}

fn decode_chunked_body(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = data.windows(2).position(|window| window == b"\r\n")?;
        let size_line = std::str::from_utf8(&data[..line_end]).ok()?;
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        data = &data[line_end + 2..];
        if data.len() < size + 2 {
            return None;
        }
        if size == 0 {
            return Some(body);
        }
        body.extend_from_slice(&data[..size]);
        if &data[size..size + 2] != b"\r\n" {
            return None;
        }
        data = &data[size + 2..];
    }
}

fn streaming_body(chunks: &'static [&'static [u8]]) -> reqwest::Body {
    let chunks = chunks
        .iter()
        .map(|chunk| Ok::<Bytes, std::io::Error>(Bytes::from_static(chunk)));
    reqwest::Body::wrap_stream(stream::iter(chunks))
}

#[ignore]
#[tokio::test]
async fn functional_chunked_request_size_limit_http1_streaming_body_rejected() {
    let harness = ChunkedRequestHarness::new("8").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .post(format!("http://127.0.0.1:{}/upload", harness.proxy_port))
        .body(streaming_body(&[b"abcdefgh", b"ijklmnop"]))
        .send()
        .await
        .expect("send chunked request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 413, "body={body}");
    assert!(
        body.contains("Request body exceeds maximum size"),
        "unexpected body: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_chunked_request_size_limit_http1_boundary_body_allowed() {
    let harness = ChunkedRequestHarness::new("16").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .post(format!("http://127.0.0.1:{}/upload", harness.proxy_port))
        .body(streaming_body(&[b"abcdefgh", b"ijklmnop"]))
        .send()
        .await
        .expect("send chunked request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, r#"{"body_len":16}"#);
}

#[ignore]
#[tokio::test]
async fn functional_chunked_request_size_limit_http1_zero_disables_limit() {
    let harness = ChunkedRequestHarness::new("0").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .post(format!("http://127.0.0.1:{}/upload", harness.proxy_port))
        .body(streaming_body(&[b"abcdefgh", b"ijklmnop", b"qrstuvwx"]))
        .send()
        .await
        .expect("send chunked request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, r#"{"body_len":24}"#);
}

/// What the client received for one HTTP/2 upload, plus what the backend
/// reported observing (echoed back as response headers).
struct H2UploadOutcome {
    status: u16,
    body: String,
    backend_body_len: Option<String>,
    backend_framing: Option<String>,
}

/// Send one HTTP/2 prior-knowledge request with no `Content-Length` or
/// `Transfer-Encoding`. With `Some(body)` the HEADERS frame leaves the stream
/// open and `body` follows as DATA carrying END_STREAM; with `None` END_STREAM
/// rides the HEADERS frame (a transport-proven empty body). The response body
/// is read except for `HEAD`, whose response carries no DATA.
async fn send_h2_upload(proxy_port: u16, method: &str, body: Option<&[u8]>) -> H2UploadOutcome {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect H2 upload");
    let _ = stream.set_nodelay(true);
    let (mut sender, connection) = h2::client::handshake(stream)
        .await
        .expect("H2 upload handshake");
    let connection_task = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://127.0.0.1:{proxy_port}/upload"))
        .body(())
        .expect("build H2 upload request");
    let (response, mut request_body) = sender
        .send_request(request, body.is_none())
        .expect("send H2 upload headers");
    if let Some(body) = body {
        request_body
            .send_data(Bytes::copy_from_slice(body), true)
            .expect("send H2 upload DATA");
    }
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("H2 upload response timed out")
        .expect("receive H2 upload response");
    let status = response.status().as_u16();
    let observed = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    let backend_body_len = observed("x-observed-body-len");
    let backend_framing = observed("x-observed-request-framing");
    let mut response_bytes = Vec::new();
    if method != "HEAD" {
        let mut response_body = response.into_body();
        while let Some(chunk) = response_body.data().await {
            let chunk = chunk.expect("read H2 upload response DATA");
            let _ = response_body.flow_control().release_capacity(chunk.len());
            response_bytes.extend_from_slice(&chunk);
        }
    }
    drop(sender);
    connection_task.abort();
    H2UploadOutcome {
        status,
        body: String::from_utf8_lossy(&response_bytes).into_owned(),
        backend_body_len,
        backend_framing,
    }
}

/// An HTTP/2 `GET`/`HEAD`/`OPTIONS` may carry DATA without `Content-Length`.
/// The HTTP/1.1 dispatchers used to infer "no body" from the method and
/// missing framing headers and send an empty backend body instead: a permitted
/// upload lost its payload, and an oversized one never reached the
/// size-limited adapter, so the route ceiling never produced its `413`. Even
/// with the body attached, hyper's HTTP/1.1 encoder sends an unknown-length
/// `GET`/`HEAD` body as zero-length unless the request is explicitly chunked,
/// so the backend's own observation of the payload and its framing is checked
/// too. A transport-proven empty request must stay bodyless with no
/// `Transfer-Encoding`.
async fn assert_h2_open_stream_uploads_honor_route_limit(pool_http1_direct: bool) {
    let harness = ChunkedRequestHarness::with_route_limit(8, pool_http1_direct).await;
    let transport = if pool_http1_direct {
        "direct HTTP/1.1 pool"
    } else {
        "reqwest"
    };

    // END_STREAM on HEADERS: the empty-body fast path, no framing upstream.
    for method in ["GET", "HEAD", "OPTIONS"] {
        let outcome = send_h2_upload(harness.proxy_port, method, None).await;
        assert_eq!(
            outcome.status, 200,
            "{transport}: empty {method}: body={}",
            outcome.body
        );
        assert_eq!(
            outcome.backend_body_len.as_deref(),
            Some("0"),
            "{transport}: empty {method}"
        );
        assert_eq!(
            outcome.backend_framing.as_deref(),
            Some("none"),
            "{transport}: an empty {method} must reach the backend without Transfer-Encoding"
        );
    }

    // Open stream, then DATA: below and exactly at the ceiling.
    let payloads: [&[u8]; 2] = [b"1234", b"12345678"];
    for method in ["GET", "HEAD", "OPTIONS"] {
        for payload in payloads {
            let outcome = send_h2_upload(harness.proxy_port, method, Some(payload)).await;
            let len = payload.len();
            assert_eq!(
                outcome.status, 200,
                "{transport}: {method} with {len} DATA bytes: body={}",
                outcome.body
            );
            let expected_len = len.to_string();
            assert_eq!(
                outcome.backend_body_len.as_deref(),
                Some(expected_len.as_str()),
                "{transport}: {method} must forward its {len}-byte payload"
            );
            assert_eq!(
                outcome.backend_framing.as_deref(),
                Some("chunked"),
                "{transport}: {method} with an unknown-length payload must be chunked upstream"
            );
            if method != "HEAD" {
                assert_eq!(
                    outcome.body,
                    format!(r#"{{"body_len":{len}}}"#),
                    "{transport}: {method}"
                );
            }
        }
    }

    // Open stream with an empty DATA frame: whatever framing the dispatcher
    // picks, the backend sees no payload.
    for method in ["GET", "OPTIONS"] {
        let outcome = send_h2_upload(harness.proxy_port, method, Some(&b""[..])).await;
        assert_eq!(outcome.status, 200, "{transport}: {method}");
        assert_eq!(
            outcome.body, r#"{"body_len":0}"#,
            "{transport}: {method} with an empty DATA frame"
        );
    }

    for method in ["GET", "HEAD", "OPTIONS"] {
        let outcome = send_h2_upload(harness.proxy_port, method, Some(&b"123456789"[..])).await;
        assert_eq!(
            outcome.status, 413,
            "{transport}: {method} with 9 DATA bytes over an 8-byte route limit: body={}",
            outcome.body
        );
        if method != "HEAD" {
            assert_eq!(
                outcome.body, r#"{"error":"Request body exceeds maximum size"}"#,
                "{transport}: {method} overrun must carry the shared 413 body"
            );
        }
    }
}

#[ignore]
#[tokio::test]
async fn functional_route_limit_h2_bodyless_method_upload_direct_h1_pool() {
    assert_h2_open_stream_uploads_honor_route_limit(true).await;
}

#[ignore]
#[tokio::test]
async fn functional_route_limit_h2_bodyless_method_upload_reqwest_path() {
    assert_h2_open_stream_uploads_honor_route_limit(false).await;
}
