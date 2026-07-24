//! Functional tests for global proxy request-header limits.
//!
//! Env parsing is covered by unit tests. These tests exercise the live H1/H2/H3
//! admission paths that turn those limits into protocol responses before
//! routing or backend dispatch.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

async fn start_counting_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            if !request.starts_with("GET /limited ") {
                let _ = stream.shutdown().await;
                return;
            }

            hits.fetch_add(1, Ordering::SeqCst);
            let response = "HTTP/1.1 200 OK\r\n\
                            Content-Length: 2\r\n\
                            Content-Type: text/plain\r\n\
                            Connection: close\r\n\
                            \r\n\
                            ok";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "header-limits"
    listen_path: "/limited"
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

struct HeaderLimitBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl HeaderLimitBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(start_counting_backend(listener, Arc::clone(&hits)));
        sleep(Duration::from_millis(100)).await;

        Self { port, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for HeaderLimitBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct HeaderLimitHarness {
    gateway: TestGateway,
    backend: HeaderLimitBackend,
}

impl HeaderLimitHarness {
    async fn new(env: &[(&str, &str)]) -> Self {
        let backend = HeaderLimitBackend::start().await;
        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend.port))
            .log_level("warn");
        for (key, value) in env {
            builder = builder.env(*key, *value);
        }
        let gateway = builder.spawn().await.expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self { gateway, backend }
    }

    fn url(&self) -> String {
        self.gateway.proxy_url("/limited")
    }

    fn hits(&self) -> usize {
        self.backend.hits()
    }
}

fn assert_431_body(body: &str, needle: &str) {
    assert!(
        body.contains(needle),
        "expected 431 body to contain `{needle}`, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_header_limits_http1_rejects_single_large_header_before_backend() {
    let h = HeaderLimitHarness::new(&[("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "32")]).await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");

    let response = client
        .get(h.url())
        .header("x-too-large", "a".repeat(64))
        .send()
        .await
        .expect("oversized H1 header request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    let body = response.text().await.expect("body");
    assert_431_body(&body, "exceeds maximum size");
    assert_eq!(h.hits(), 0, "oversized H1 header must not reach backend");
}

#[ignore]
#[tokio::test]
async fn functional_header_limits_h2_rejects_single_large_header_before_backend() {
    let h = HeaderLimitHarness::new(&[("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "32")]).await;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");

    let response = client
        .get(h.url())
        .header("x-too-large", "a".repeat(64))
        .send()
        .await
        .expect("oversized H2 header request");

    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        response.status(),
        reqwest::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    let body = response.text().await.expect("body");
    assert_431_body(&body, "exceeds maximum size");
    assert_eq!(h.hits(), 0, "oversized H2 header must not reach backend");
}

#[ignore]
#[tokio::test]
async fn functional_header_limits_h3_rejects_header_count_before_backend() {
    let backend = HeaderLimitBackend::start().await;
    let https_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve https port");
    let https_port = https_listener.local_addr().expect("https addr").port();
    drop(https_listener);

    let _gateway = TestGateway::builder()
        .mode_file(build_config(backend.port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env("FERRUM_MAX_HEADER_COUNT", "1")
        .spawn()
        .await
        .expect("start h3 gateway");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/limited");
    let options = GetOptions::default()
        .header("x-one", "1")
        .header("x-two", "2");
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        match client.get_with_options(&url, options.clone()).await {
            Ok(response) => break response,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 header-count request did not complete: {err}"),
        }
    };

    assert_eq!(
        response.status,
        http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert_431_body(&response.body_text(), "Request header count");
    assert_eq!(
        backend.hits(),
        0,
        "H3 header-count rejection must not reach backend"
    );
}
