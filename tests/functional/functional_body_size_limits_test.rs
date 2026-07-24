//! Functional tests for global request/response body-size env limits.
//!
//! These spawn the real gateway in file mode and verify that the protocol
//! proxying path honors `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` and
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, including `0` as unlimited.

use crate::common::TestGateway;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone)]
enum BackendMode {
    EchoRequestBodyLen,
    FixedResponse { body: Vec<u8> },
}

struct BodyLimitHarness {
    _gateway: TestGateway,
    backend_task: tokio::task::JoinHandle<()>,
    backend_hits: Arc<AtomicUsize>,
    proxy_port: u16,
}

impl BodyLimitHarness {
    async fn new(mode: BackendMode, env: &[(&str, &str)]) -> Self {
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().expect("backend addr").port();
        let backend_hits = Arc::new(AtomicUsize::new(0));
        let backend_task = tokio::spawn(run_body_backend(
            backend_listener,
            mode,
            Arc::clone(&backend_hits),
        ));

        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .capture_output();
        for (key, value) in env {
            builder = builder.env(*key, *value);
        }

        let gateway = builder.spawn().await.expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self {
            proxy_port: gateway.proxy_port,
            _gateway: gateway,
            backend_task,
            backend_hits,
        }
    }

    fn backend_hit_count(&self) -> usize {
        self.backend_hits.load(Ordering::SeqCst)
    }
}

impl Drop for BodyLimitHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "body-size-proxy"
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

async fn run_body_backend(listener: TcpListener, mode: BackendMode, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        hits.fetch_add(1, Ordering::SeqCst);
        let mode = mode.clone();
        tokio::spawn(async move {
            let request = read_http_request(&mut stream).await;
            let response_body = match mode {
                BackendMode::EchoRequestBodyLen => {
                    let body_len = request_body_len(&request);
                    format!(r#"{{"body_len":{body_len}}}"#).into_bytes()
                }
                BackendMode::FixedResponse { body } => body,
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Connection: close\r\n\
                 \r\n",
                response_body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&response_body).await;
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
        if let Some(end) = header_end {
            let content_length = content_length(&buf[..end]);
            if buf.len() >= end + content_length {
                break;
            }
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

fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn request_body_len(request: &[u8]) -> usize {
    let Some(end) = find_header_end(request) else {
        return 0;
    };
    let len = content_length(&request[..end]);
    request.len().saturating_sub(end).min(len)
}

/// Send an H2 request and return `(Some(status), body)`, or `(None, "")` when
/// the proxy resets the stream instead of delivering a response. A reset is a
/// valid way for the proxy to reject an over-limit request body, so callers
/// that exercise rejection must tolerate it (a genuine hang does not resolve
/// here and surfaces as a test timeout instead).
async fn send_h2_request(request: Request<Full<Bytes>>, proxy_port: u16) -> (Option<u16>, String) {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let outcome = match sender.send_request(request).await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .unwrap_or_default();
            (Some(status), String::from_utf8_lossy(&body).into_owned())
        }
        Err(_reset) => (None, String::new()),
    };

    drop(sender);
    conn_task.abort();

    outcome
}

#[ignore]
#[tokio::test]
async fn functional_body_size_limit_http1_request_content_length_rejected() {
    let harness = BodyLimitHarness::new(
        BackendMode::EchoRequestBodyLen,
        &[("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "8")],
    )
    .await;

    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("http1 client");
    let hits_before = harness.backend_hit_count();
    let response = client
        .post(format!("http://127.0.0.1:{}/upload", harness.proxy_port))
        .body("0123456789abcdef")
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 413, "body={body}");
    assert!(
        body.contains("Request body exceeds maximum size"),
        "unexpected body: {body}"
    );
    assert_eq!(
        harness.backend_hit_count(),
        hits_before,
        "Content-Length fast-path rejection must not reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_body_size_limit_http2_request_body_rejected_without_content_length() {
    let harness = BodyLimitHarness::new(
        BackendMode::EchoRequestBodyLen,
        &[("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "8")],
    )
    .await;

    let request = Request::builder()
        .method("POST")
        .uri("http://example.com/upload")
        .header("host", "example.com")
        .body(Full::new(Bytes::from_static(b"0123456789abcdef")))
        .expect("build h2 request");
    let hits_before = harness.backend_hit_count();
    let (status, body) = send_h2_request(request, harness.proxy_port).await;

    // A delivered response must be the 413; a stream reset (None) is an equally
    // valid rejection of the over-limit upload. The backend-hit guard below is
    // the authoritative check that the body never reached the backend.
    if let Some(status) = status {
        assert_eq!(status, 413, "body={body}");
        assert!(
            body.contains("Request body exceeds maximum size"),
            "unexpected body: {body}"
        );
    }
    assert_eq!(
        harness.backend_hit_count(),
        hits_before,
        "streamed request-body rejection must not reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_body_size_limit_http1_request_zero_disables_limit() {
    let harness = BodyLimitHarness::new(
        BackendMode::EchoRequestBodyLen,
        &[("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")],
    )
    .await;

    let payload = "0123456789abcdef0123456789abcdef";
    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("http1 client");
    let hits_before = harness.backend_hit_count();
    let response = client
        .post(format!("http://127.0.0.1:{}/upload", harness.proxy_port))
        .body(payload)
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, format!(r#"{{"body_len":{}}}"#, payload.len()));
    assert_eq!(harness.backend_hit_count(), hits_before + 1);
}

#[ignore]
#[tokio::test]
async fn functional_body_size_limit_http1_response_content_length_rejected() {
    let harness = BodyLimitHarness::new(
        BackendMode::FixedResponse {
            body: b"0123456789abcdef".to_vec(),
        },
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "8")],
    )
    .await;

    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("http1 client");
    let hits_before = harness.backend_hit_count();
    let response = client
        .get(format!("http://127.0.0.1:{}/download", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 502, "body={body}");
    assert!(
        body.contains("Backend response body exceeds maximum size"),
        "unexpected body: {body}"
    );
    assert_eq!(harness.backend_hit_count(), hits_before + 1);
}

#[ignore]
#[tokio::test]
async fn functional_body_size_limit_http2_response_content_length_rejected() {
    let harness = BodyLimitHarness::new(
        BackendMode::FixedResponse {
            body: b"0123456789abcdef".to_vec(),
        },
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "8")],
    )
    .await;

    let request = Request::builder()
        .method("GET")
        .uri("http://example.com/download")
        .header("host", "example.com")
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let hits_before = harness.backend_hit_count();
    let (status, body) = send_h2_request(request, harness.proxy_port).await;

    // The over-limit response is rejected via the Content-Length fast path,
    // which returns a complete buffered 502 (no streaming, so no reset race).
    assert_eq!(status, Some(502), "body={body}");
    assert!(
        body.contains("Backend response body exceeds maximum size"),
        "unexpected body: {body}"
    );
    assert_eq!(harness.backend_hit_count(), hits_before + 1);
}

#[ignore]
#[tokio::test]
async fn functional_body_size_limit_http1_response_zero_disables_limit() {
    let backend_body = "0123456789abcdef0123456789abcdef";
    let harness = BodyLimitHarness::new(
        BackendMode::FixedResponse {
            body: backend_body.as_bytes().to_vec(),
        },
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")],
    )
    .await;

    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("http1 client");
    let hits_before = harness.backend_hit_count();
    let response = client
        .get(format!("http://127.0.0.1:{}/download", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, backend_body);
    assert_eq!(harness.backend_hit_count(), hits_before + 1);
}
