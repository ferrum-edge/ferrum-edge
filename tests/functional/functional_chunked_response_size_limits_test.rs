//! Functional tests for response-size limits on unknown-length backend bodies.
//!
//! These cover backend responses without `Content-Length`, where the gateway
//! must enforce `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` while streaming or while
//! buffering due to `response_body_mode: buffer`.

use crate::common::TestGateway;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct ChunkedHarness {
    _gateway: TestGateway,
    backend_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
}

impl ChunkedHarness {
    async fn new(response_body_mode: Option<&str>, max_response_bytes: &str) -> Self {
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().expect("backend addr").port();
        let backend_task = tokio::spawn(run_chunked_backend(backend_listener));

        let gateway = TestGateway::builder()
            .mode_file(build_config(backend_port, response_body_mode))
            .log_level("warn")
            .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", max_response_bytes)
            .capture_output()
            .spawn()
            .await
            .expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self {
            proxy_port: gateway.proxy_port,
            _gateway: gateway,
            backend_task,
        }
    }
}

impl Drop for ChunkedHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

fn build_config(backend_port: u16, response_body_mode: Option<&str>) -> String {
    let response_body_mode = response_body_mode
        .map(|mode| format!("    response_body_mode: {mode}\n"))
        .unwrap_or_default();
    format!(
        r#"
version: "1"
proxies:
  - id: "chunked-response-size-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
{response_body_mode}
consumers: []
plugin_configs: []
"#
    )
}

async fn run_chunked_backend(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = b"HTTP/1.1 200 OK\r\n\
                Transfer-Encoding: chunked\r\n\
                Content-Type: text/plain\r\n\
                Connection: close\r\n\
                \r\n\
                8\r\nabcdefgh\r\n\
                8\r\nijklmnop\r\n\
                0\r\n\r\n";
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn send_h2_get(proxy_port: u16) -> (u16, Result<String, String>) {
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

    let request = Request::builder()
        .method("GET")
        .uri("http://example.com/chunked")
        .header("host", "example.com")
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
        .map_err(|err| err.to_string());

    drop(sender);
    conn_task.abort();

    (status, body)
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_http1_streaming_body_errors_after_limit() {
    let harness = ChunkedHarness::new(None, "8").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/chunked", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");

    assert_eq!(response.status().as_u16(), 200);
    let body = response.bytes().await;
    assert!(
        body.is_err(),
        "streaming unknown-length response over the limit must fail the body read"
    );
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_http2_streaming_body_resets_after_limit() {
    let harness = ChunkedHarness::new(None, "8").await;

    let (status, body) = send_h2_get(harness.proxy_port).await;

    assert_eq!(status, 200);
    assert!(
        body.is_err(),
        "H2 downstream body should reset when unknown-length backend body exceeds limit"
    );
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_buffer_mode_returns_502() {
    let harness = ChunkedHarness::new(Some("buffer"), "8").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/chunked", harness.proxy_port))
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
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_zero_streams_full_body() {
    let harness = ChunkedHarness::new(None, "0").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/chunked", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "abcdefghijklmnop");
}
