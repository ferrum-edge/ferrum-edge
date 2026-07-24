//! Functional tests for request-size limits on HTTP/1 chunked request bodies.
//!
//! These cover `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` when the inbound request
//! has no `Content-Length` and must be limited while the body is read.

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

impl ChunkedRequestHarness {
    async fn new(max_request_bytes: &str) -> Self {
        let mut last_error = None;
        for attempt in 1..=3 {
            match Self::try_new(max_request_bytes).await {
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

    async fn try_new(max_request_bytes: &str) -> Result<Self, String> {
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| format!("bind backend: {error}"))?;
        let backend_port = backend_listener
            .local_addr()
            .map_err(|error| format!("backend addr: {error}"))?
            .port();

        let gateway = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", max_request_bytes)
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
    backend_port: {backend_port: ''}
    strip_listen_path: false
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
            let body = format!(r#"{{"body_len":{body_len}}}"#);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/json\r\n\
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
