//! Functional tests for route-level `allowed_methods` admission.
//!
//! These tests exercise the live gateway frontend paths, not just config
//! validation, so method allowlists are checked on HTTP/1.1, h2c HTTP/2, and
//! HTTP/3 requests before backend dispatch.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use http::{HeaderMap, Method};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

async fn start_counting_http1_backend(
    listener: TcpListener,
    target_path: &'static str,
    target_hits: Arc<AtomicUsize>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&target_hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let target_prefix = format!("GET {target_path} ");
            if !request.starts_with(&target_prefix) {
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

fn build_config(backend_port: u16, allowed_methods: &[&str]) -> String {
    let allowed_methods_yaml = allowed_methods
        .iter()
        .map(|method| format!("      - \"{method}\"\n"))
        .collect::<String>();
    format!(
        r#"version: "1"
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 1
proxies:
  - id: "allowed-methods"
    listen_path: "/allowed"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods:
{allowed_methods_yaml}

consumers: []
plugin_configs:
  - id: "allowed-methods-security"
    plugin_name: security_headers
    scope: global
    enabled: true
    config:
      set:
        X-Synthetic-Policy: "enforced"
        Allow: "DELETE"
      remove: ["Content-Type"]
"#
    )
}

struct CountingBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(start_counting_http1_backend(
            listener,
            "/allowed",
            Arc::clone(&hits),
        ));
        sleep(Duration::from_millis(100)).await;

        Self { port, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for CountingBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct AllowedMethodsHarness {
    gateway: TestGateway,
    backend: CountingBackend,
}

impl AllowedMethodsHarness {
    async fn new(config_allowed_methods: &[&str]) -> Self {
        let backend = CountingBackend::start().await;
        let gateway = TestGateway::builder()
            .mode_file(build_config(backend.port, config_allowed_methods))
            .log_level("warn")
            .spawn()
            .await
            .expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self { gateway, backend }
    }

    fn hits(&self) -> usize {
        self.backend.hits()
    }
}

fn assert_allow_header(headers: &HeaderMap, expected: &[&str]) {
    assert_eq!(
        headers.get_all(http::header::ALLOW).iter().count(),
        1,
        "405 response must carry exactly one authoritative Allow field"
    );
    let actual = headers
        .get(http::header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .expect("Allow header");
    let actual_methods = actual
        .split(',')
        .map(|method| method.trim().to_ascii_uppercase())
        .collect::<Vec<_>>();
    let expected_methods = expected
        .iter()
        .map(|method| method.to_ascii_uppercase())
        .collect::<Vec<_>>();
    assert_eq!(actual_methods, expected_methods, "Allow header: {actual}");
}

#[ignore]
#[tokio::test]
async fn functional_allowed_methods_http1_and_h2_enforced_before_backend() {
    // Lowercase config value verifies route-level matching is case-insensitive.
    let h = AllowedMethodsHarness::new(&["get", "HEAD"]).await;

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");
    let url = h.gateway.proxy_url("/allowed");

    let h1_allowed = h1.get(&url).send().await.expect("h1 allowed GET");
    assert_eq!(h1_allowed.status(), reqwest::StatusCode::OK);
    assert_eq!(h1_allowed.text().await.expect("h1 body"), "ok");
    assert_eq!(h.hits(), 1, "allowed HTTP/1.1 GET should reach backend");

    let h1_blocked = h1.post(&url).send().await.expect("h1 blocked POST");
    assert_eq!(h1_blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(h1_blocked.headers(), &["GET", "HEAD"]);
    assert!(
        !h1_blocked
            .headers()
            .contains_key(http::header::CONTENT_TYPE)
    );
    assert_eq!(
        h1_blocked
            .headers()
            .get("x-synthetic-policy")
            .and_then(|value| value.to_str().ok()),
        Some("enforced")
    );
    let h1_body = h1_blocked.text().await.expect("h1 blocked body");
    assert!(
        h1_body.contains("Method Not Allowed"),
        "unexpected H1 body: {h1_body}"
    );
    assert_eq!(h.hits(), 1, "blocked HTTP/1.1 POST must not reach backend");

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let h2_allowed = h2.get(&url).send().await.expect("h2 allowed GET");
    assert_eq!(h2_allowed.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_allowed.status(), reqwest::StatusCode::OK);
    assert_eq!(h2_allowed.text().await.expect("h2 body"), "ok");
    assert_eq!(h.hits(), 2, "allowed HTTP/2 GET should reach backend");

    let h2_blocked = h2.delete(&url).send().await.expect("h2 blocked DELETE");
    assert_eq!(h2_blocked.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(h2_blocked.headers(), &["GET", "HEAD"]);
    assert!(
        !h2_blocked
            .headers()
            .contains_key(http::header::CONTENT_TYPE)
    );
    assert_eq!(
        h2_blocked
            .headers()
            .get("x-synthetic-policy")
            .and_then(|value| value.to_str().ok()),
        Some("enforced")
    );
    let h2_body = h2_blocked.text().await.expect("h2 blocked body");
    assert!(
        h2_body.contains("Method Not Allowed"),
        "unexpected H2 body: {h2_body}"
    );
    assert_eq!(h.hits(), 2, "blocked HTTP/2 DELETE must not reach backend");
}

#[ignore]
#[tokio::test]
async fn functional_allowed_methods_http3_rejects_before_backend() {
    let backend = CountingBackend::start().await;

    let https_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve https port");
    let https_port = https_listener.local_addr().expect("https addr").port();
    drop(https_listener);

    let _gateway = TestGateway::builder()
        .mode_file(build_config(backend.port, &["GET", "HEAD"]))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/allowed");
    let options = GetOptions::default().method(Method::POST);
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        match client.get_with_options(&url, options.clone()).await {
            Ok(response) => break response,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 POST did not complete: {err}"),
        }
    };

    assert_eq!(response.status, http::StatusCode::METHOD_NOT_ALLOWED);
    assert_allow_header(&response.headers, &["GET", "HEAD"]);
    assert!(!response.headers.contains_key(http::header::CONTENT_TYPE));
    assert_eq!(
        response
            .headers
            .get("x-synthetic-policy")
            .and_then(|value| value.to_str().ok()),
        Some("enforced")
    );
    let body = response.body_text();
    assert!(
        body.contains("Method Not Allowed"),
        "unexpected H3 body: {body}"
    );
    assert_eq!(
        backend.hits(),
        0,
        "blocked HTTP/3 POST must not reach backend"
    );
}
