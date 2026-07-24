//! Functional coverage for client-IP ENV handling on the HTTP proxy path.
//!
//! Unit tests cover the resolver algorithms directly. These tests drive a real
//! file-mode gateway and prove the resolved client IP is actually used by
//! gateway admission, via `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP`.

use crate::common::TestGateway;
use crate::scaffolding::ports::reserve_port;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

struct ClientIpHarness {
    gateway: TestGateway,
    backend_task: tokio::task::JoinHandle<()>,
    backend_get_count: Arc<AtomicUsize>,
}

impl ClientIpHarness {
    async fn new(env: &[(&str, &str)]) -> Self {
        let reservation = reserve_port().await.expect("reserve backend port");
        let backend_port = reservation.port;
        let backend_get_count = Arc::new(AtomicUsize::new(0));
        let backend_task = tokio::spawn(run_holding_backend(
            reservation.into_listener(),
            Arc::clone(&backend_get_count),
        ));

        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .env("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP", "1")
            .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
            .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0");
        for (key, value) in env {
            builder = builder.env(*key, *value);
        }

        let gateway = builder.spawn().await.expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self {
            gateway,
            backend_task,
            backend_get_count,
        }
    }

    fn proxy_url(&self) -> String {
        self.gateway.proxy_url("/hold")
    }

    async fn backend_get_count(&self) -> usize {
        self.backend_get_count.load(Ordering::SeqCst)
    }
}

impl Drop for ClientIpHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

async fn run_holding_backend(listener: TcpListener, get_count: Arc<AtomicUsize>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let count = Arc::clone(&get_count);
        tokio::spawn(async move {
            handle_holding_backend_connection(stream, count).await;
        });
    }
}

async fn handle_holding_backend_connection(mut stream: TcpStream, get_count: Arc<AtomicUsize>) {
    let mut request_bytes = Vec::with_capacity(1024);
    let read = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            request_bytes.extend_from_slice(&buf[..n]);
            if request_bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        std::io::Result::Ok(())
    })
    .await;
    if !matches!(read, Ok(Ok(()))) {
        let _ = stream.shutdown().await;
        return;
    }

    let request = String::from_utf8_lossy(&request_bytes);
    if !request.starts_with("GET /hold ") {
        let _ = stream.shutdown().await;
        return;
    }

    get_count.fetch_add(1, Ordering::SeqCst);
    let headers = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\no";
    if stream.write_all(headers.as_bytes()).await.is_err() {
        let _ = stream.shutdown().await;
        return;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let _ = stream.write_all(b"k").await;
    let _ = stream.shutdown().await;
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "client-ip-env"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: false
    pool_enable_http2: false
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

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
}

async fn wait_until_backend_get_count(harness: &ClientIpHarness, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if harness.backend_get_count().await >= expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "backend did not observe {expected} GET request(s)"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn open_holding_get(
    harness: &ClientIpHarness,
    headers: &[(&str, &str)],
) -> BufReader<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", harness.gateway.proxy_port))
        .await
        .expect("connect to gateway");
    let mut request = String::from("GET /hold HTTP/1.1\r\nHost: example.com\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write holding request");
    stream.flush().await.expect("flush holding request");

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut status_line))
        .await
        .expect("status timeout")
        .expect("read status");
    assert!(
        status_line.contains(" 200 "),
        "expected first request to be admitted, got {status_line:?}"
    );

    loop {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("header timeout")
            .expect("read header");
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
    }

    let mut first_body_byte = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(5),
        reader.read_exact(&mut first_body_byte),
    )
    .await
    .expect("body byte timeout")
    .expect("read first body byte");
    assert_eq!(first_body_byte, *b"o");

    reader
}

#[ignore]
#[tokio::test]
async fn functional_client_ip_no_trusted_proxies_ignores_x_forwarded_for_for_limits() {
    let harness = ClientIpHarness::new(&[]).await;

    let _first_conn = open_holding_get(&harness, &[("x-forwarded-for", "198.51.100.10")]).await;
    wait_until_backend_get_count(&harness, 1).await;

    let second = client()
        .get(harness.proxy_url())
        .header("x-forwarded-for", "198.51.100.11")
        .send()
        .await
        .expect("second response");
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    assert_eq!(
        harness.backend_get_count().await,
        1,
        "rejected request must not reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_client_ip_trusted_xff_splits_per_ip_limits() {
    let harness = ClientIpHarness::new(&[("FERRUM_TRUSTED_PROXIES", "127.0.0.1")]).await;

    let _first_conn = open_holding_get(&harness, &[("x-forwarded-for", "198.51.100.20")]).await;
    wait_until_backend_get_count(&harness, 1).await;

    let same_client = client()
        .get(harness.proxy_url())
        .header("x-forwarded-for", "198.51.100.20")
        .send()
        .await
        .expect("same client response");
    assert_eq!(same_client.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let different_client = client()
        .get(harness.proxy_url())
        .header("x-forwarded-for", "198.51.100.21")
        .send()
        .await
        .expect("different client response");
    assert_eq!(different_client.status(), reqwest::StatusCode::OK);
    assert_eq!(different_client.text().await.expect("body"), "ok");

    assert_eq!(
        harness.backend_get_count().await,
        2,
        "only admitted requests should reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_client_ip_real_ip_header_takes_precedence_over_xff_for_limits() {
    let harness = ClientIpHarness::new(&[
        ("FERRUM_TRUSTED_PROXIES", "127.0.0.1"),
        ("FERRUM_REAL_IP_HEADER", "X-Real-IP"),
    ])
    .await;

    let _first_conn = open_holding_get(
        &harness,
        &[
            ("x-real-ip", "198.51.100.30"),
            ("x-forwarded-for", "203.0.113.200"),
        ],
    )
    .await;
    wait_until_backend_get_count(&harness, 1).await;

    let same_real_ip_different_xff = client()
        .get(harness.proxy_url())
        .header("x-real-ip", "198.51.100.30")
        .header("x-forwarded-for", "203.0.113.201")
        .send()
        .await
        .expect("same real IP response");
    assert_eq!(
        same_real_ip_different_xff.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS
    );

    let different_real_ip_same_xff = client()
        .get(harness.proxy_url())
        .header("x-real-ip", "198.51.100.31")
        .header("x-forwarded-for", "203.0.113.200")
        .send()
        .await
        .expect("different real IP response");
    assert_eq!(different_real_ip_same_xff.status(), reqwest::StatusCode::OK);
    assert_eq!(different_real_ip_same_xff.text().await.expect("body"), "ok");

    assert_eq!(
        harness.backend_get_count().await,
        2,
        "only admitted requests should reach backend"
    );
}
