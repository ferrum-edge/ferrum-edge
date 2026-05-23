//! Functional coverage for the HTTP/1 header-read timeout.
//!
//! `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` protects the HTTP proxy listener
//! from clients that open a connection and then drip-feed request headers.
//! Setting it to `0` intentionally disables the guard.

use crate::common::{TestGateway, TestGatewayBuilder};

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

#[ignore]
#[tokio::test]
async fn functional_header_read_timeout_closes_slow_http1_headers() {
    let (backend_port, backend_hits, backend_task) = spawn_header_backend().await;
    let mut gateway = timeout_gateway_builder(backend_port, "1")
        .spawn()
        .await
        .expect("start header-timeout gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let response = send_slow_header_request(gateway.proxy_port, Duration::from_millis(1_500))
        .await
        .expect("slow header exchange");

    assert!(
        !response.contains("200 OK"),
        "timed-out slow request unexpectedly reached backend: {response:?}"
    );
    assert_backend_hits(&backend_hits, 0).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_header_read_timeout_zero_allows_delayed_http1_headers() {
    let (backend_port, backend_hits, backend_task) = spawn_header_backend().await;
    let mut gateway = timeout_gateway_builder(backend_port, "0")
        .spawn()
        .await
        .expect("start disabled header-timeout gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let response = send_slow_header_request(gateway.proxy_port, Duration::from_millis(1_500))
        .await
        .expect("slow header exchange");

    assert!(
        response.contains("200 OK"),
        "disabled timeout should allow delayed headers; response={response:?}"
    );
    assert!(
        response.ends_with("ok"),
        "backend response body should be delivered; response={response:?}"
    );
    assert_backend_hits(&backend_hits, 1).await;

    gateway.shutdown();
    backend_task.abort();
}

fn timeout_gateway_builder(backend_port: u16, timeout_seconds: &str) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(header_timeout_config(backend_port))
        .log_level("warn")
        .env("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", timeout_seconds)
}

fn header_timeout_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "header-timeout",
            "listen_path": "/slow",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize header-timeout config")
}

async fn send_slow_header_request(
    proxy_port: u16,
    delay: Duration,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHo")
        .await
        .map_err(|e| format!("write partial request: {e}"))?;
    sleep(delay).await;

    let _ = stream
        .write_all(b"st: example.com\r\nConnection: close\r\n\r\n")
        .await;

    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes)).await;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

async fn spawn_header_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind header backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_header_backend(listener, Arc::clone(&hits)));
    (port, hits, task)
}

async fn run_header_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            if request.starts_with("GET /slow ") {
                hits.fetch_add(1, Ordering::SeqCst);
            }
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn assert_backend_hits(hits: &AtomicUsize, expected: usize) {
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        expected,
        "unexpected backend hit count for slow-header request"
    );
}
