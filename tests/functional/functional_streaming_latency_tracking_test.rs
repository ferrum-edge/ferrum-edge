//! Functional tests for the streaming latency tracking response-body path.
//!
//! `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true` wraps the same streaming
//! body chosen by the normal response builder. These tests prove the tracked
//! path still preserves unknown-length response size limiting and unlimited
//! direct streaming behavior.

use crate::common::TestGateway;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct TrackingHarness {
    _gateway: TestGateway,
    backend_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
}

impl TrackingHarness {
    async fn new(extra_env: &[(&str, &str)]) -> Self {
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().expect("backend addr").port();
        let backend_task = tokio::spawn(run_chunked_backend(backend_listener));

        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .env("FERRUM_ENABLE_STREAMING_LATENCY_TRACKING", "true")
            .capture_output();
        for (key, value) in extra_env {
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
        }
    }
}

impl Drop for TrackingHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "tracked-streaming-proxy"
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

#[ignore]
#[tokio::test]
async fn functional_streaming_latency_tracking_preserves_response_size_limit() {
    let harness = TrackingHarness::new(&[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "8")]).await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/tracked", harness.proxy_port))
        .send()
        .await
        .expect("send request");

    assert_eq!(response.status().as_u16(), 200);
    let body = response.bytes().await;
    assert!(
        body.is_err(),
        "tracked unknown-length response over the size limit must fail the body read"
    );
}

#[ignore]
#[tokio::test]
async fn functional_streaming_latency_tracking_zero_limit_streams_full_body() {
    let harness = TrackingHarness::new(&[
        ("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0"),
        ("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0"),
    ])
    .await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/tracked", harness.proxy_port))
        .send()
        .await
        .expect("send request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "abcdefghijklmnop");
}
