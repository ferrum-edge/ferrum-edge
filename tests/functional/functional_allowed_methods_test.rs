//! Functional tests for route-level admission that runs before any plugin:
//! `allowed_methods`, and the refusal of a client-selected native-gRPC or
//! WebSocket flavor whose plugin view omits the route's admission policy.
//!
//! These tests exercise the live gateway frontend paths, not just config
//! validation, so both gates are checked on HTTP/1.1, h2c HTTP/2, and HTTP/3
//! requests before backend dispatch.

use crate::scaffolding::port_registry::TestSocket;

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
        let listener = TcpListener::bind_test("127.0.0.1:0")
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

    let gateway = TestGateway::builder()
        .mode_file(build_config(backend.port, &["GET", "HEAD"]))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

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

// ---------------------------------------------------------------------------
// Client-selected flavors that cannot run the route's admission policy
// ---------------------------------------------------------------------------

/// A route whose only plugin is an HTTP-only admission policy (a
/// timestamp-only `soap_ws_security`), so its native-gRPC and WebSocket plugin
/// views omit it and the gateway must refuse those flavors before any plugin
/// runs.
fn build_route_protocol_admission_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "protocol-admission"
    listen_path: "/allowed"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "freshness"

consumers: []
plugin_configs:
  - id: "freshness"
    plugin_name: soap_ws_security
    scope: proxy
    proxy_id: "protocol-admission"
    enabled: true
    config:
      timestamp:
        require: true
        max_age_seconds: 300
        clock_skew_seconds: 300
      reject_missing_security_header: true
"#
    )
}

const ROUTE_PROTOCOL_REFUSAL_BODY: &str = "Request protocol not permitted on this route";

/// One length-prefixed, uncompressed gRPC message.
fn grpc_message_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Send an HTTP/1.1 WebSocket upgrade and return everything the gateway wrote
/// until the refusal body arrived, the connection closed, or 10s elapsed.
async fn http1_websocket_upgrade(port: u16, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to gateway");
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write upgrade request");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline
        && !String::from_utf8_lossy(&received).contains(ROUTE_PROTOCOL_REFUSAL_BODY)
    {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&received).into_owned()
}

#[ignore]
#[tokio::test]
async fn functional_route_protocol_admission_refuses_h1_websocket_and_h2_grpc() {
    let backend = CountingBackend::start().await;
    let gateway = TestGateway::builder()
        .mode_file(build_route_protocol_admission_config(backend.port))
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let upgrade = http1_websocket_upgrade(gateway.proxy_port, "/allowed").await;
    assert!(
        upgrade.starts_with("HTTP/1.1 403"),
        "a WebSocket upgrade the route's policy cannot run on must be refused: {upgrade}"
    );
    assert!(
        upgrade.contains(ROUTE_PROTOCOL_REFUSAL_BODY),
        "unexpected refusal: {upgrade}"
    );

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let grpc = h2
        .post(gateway.proxy_url("/allowed/pkg.Service/Method"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(grpc_message_frame(b"ping"))
        .send()
        .await
        .expect("h2 gRPC request");
    assert_eq!(grpc.version(), reqwest::Version::HTTP_2);
    assert_eq!(grpc.status(), reqwest::StatusCode::OK);
    assert_eq!(
        grpc.headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("7"),
        "native gRPC is refused trailers-only with PERMISSION_DENIED"
    );

    assert_eq!(
        backend.hits(),
        0,
        "a refused flavor must not reach the backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_route_protocol_admission_refuses_h3_grpc() {
    let backend = CountingBackend::start().await;
    let gateway = TestGateway::builder()
        .mode_file(build_route_protocol_admission_config(backend.port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/allowed/pkg.Service/Method");
    let options = GetOptions::default()
        .method(Method::POST)
        .header("content-type", "application/grpc")
        .body(bytes::Bytes::from(grpc_message_frame(b"ping")));
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        match client.get_with_options(&url, options.clone()).await {
            Ok(response) => break response,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 gRPC request did not complete: {err}"),
        }
    };

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(
        response.grpc_status(),
        Some(7),
        "native gRPC over HTTP/3 is refused with PERMISSION_DENIED"
    );
    assert!(response.body_bytes.is_empty());
    assert_eq!(
        backend.hits(),
        0,
        "a refused flavor must not reach the backend"
    );
}
