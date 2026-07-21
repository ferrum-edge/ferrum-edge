//! Issue #2445: response_mock HEAD / no-body status wire parity across H1/H2/H3.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{Method, StatusCode, header};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

const FORBIDDEN_BODY: &str = "must-not-be-sent";

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "mock-semantics"
    listen_path: "/mock"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: true
    plugins:
      - plugin_config_id: "mock-semantics-plugin"

consumers: []
plugin_configs:
  - id: "mock-semantics-plugin"
    plugin_name: response_mock
    scope: proxy
    proxy_id: "mock-semantics"
    enabled: true
    config:
      rules:
        - path: /repr
          status_code: 200
          headers:
            content-type: text/plain
          body: "{FORBIDDEN_BODY}"
        - method: HEAD
          path: /head
          status_code: 200
          headers:
            content-type: text/plain
          body: "{FORBIDDEN_BODY}"
        - path: /empty
          status_code: 204
          body: "{FORBIDDEN_BODY}"
        - path: /reset
          status_code: 205
          body: "{FORBIDDEN_BODY}"
        - path: /not-modified
          status_code: 304
          body: "{FORBIDDEN_BODY}"
"#
    )
}

async fn h3_request_until_ready(client: &Http3Client, url: &str, method: Method) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client
            .get_with_options(url, GetOptions::default().method(method.clone()))
            .await
        {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 {method} {url} did not complete: {error}"),
        }
    }
}

async fn spawn_mock_gateway(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!(
        "failed to spawn response_mock semantics gateway after {MAX_ATTEMPTS} attempts: {last_error}"
    );
}

fn content_length(headers: &reqwest::header::HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

fn h3_content_length(headers: &http::HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

async fn assert_h1_h2_no_body_path(
    client: &reqwest::Client,
    url: &str,
    expected_status: reqwest::StatusCode,
    protocol: &str,
) {
    let response = client.get(url).send().await.unwrap_or_else(|e| {
        panic!("{protocol} GET {url} failed: {e}");
    });
    assert_eq!(
        response.status(),
        expected_status,
        "{protocol} {url} status"
    );
    // Contract: 204/205/304 must not advertise Content-Length on any frontend.
    // H1 is the sharp edge for 205 — Hyper would otherwise synthesize
    // `Content-Length: 0` for ordinary empty bodies (it special-cases only
    // 204/304), so this assertion guards the status-aware empty body path.
    assert!(
        response.headers().get(header::CONTENT_LENGTH).is_none(),
        "{protocol} {url} must not advertise Content-Length (got {:?})",
        response.headers().get(header::CONTENT_LENGTH)
    );
    let body = response
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("{protocol} {url} body read failed: {e}"));
    assert!(
        body.is_empty(),
        "{protocol} {url} must omit configured body bytes, got {} bytes",
        body.len()
    );
}

#[ignore]
#[tokio::test]
async fn functional_response_mock_head_and_no_body_statuses_across_h1_h2_h3() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind idle backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();

    let (mut gateway, https_port) = spawn_mock_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H1 client");
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H2 client");

    let repr_url = gateway.proxy_url("/mock/repr");
    let head_url = gateway.proxy_url("/mock/head");
    let empty_url = gateway.proxy_url("/mock/empty");
    let reset_url = gateway.proxy_url("/mock/reset");
    let not_modified_url = gateway.proxy_url("/mock/not-modified");

    // --- H1 ---
    let h1_get = h1.get(&repr_url).send().await.expect("H1 GET /repr");
    assert_eq!(h1_get.status(), reqwest::StatusCode::OK);
    let h1_repr = h1_get.bytes().await.expect("H1 GET body");
    assert_eq!(&h1_repr[..], FORBIDDEN_BODY.as_bytes());
    let representation_len = h1_repr.len();

    let h1_head = h1.head(&repr_url).send().await.expect("H1 HEAD /repr");
    assert_eq!(h1_head.status(), reqwest::StatusCode::OK);
    assert_eq!(content_length(h1_head.headers()), Some(representation_len));
    assert!(h1_head.bytes().await.expect("H1 HEAD body").is_empty());

    let h1_head_rule = h1.head(&head_url).send().await.expect("H1 HEAD /head");
    assert_eq!(h1_head_rule.status(), reqwest::StatusCode::OK);
    assert_eq!(
        content_length(h1_head_rule.headers()),
        Some(FORBIDDEN_BODY.len())
    );
    assert!(
        h1_head_rule
            .bytes()
            .await
            .expect("H1 HEAD /head body")
            .is_empty()
    );

    assert_h1_h2_no_body_path(&h1, &empty_url, reqwest::StatusCode::NO_CONTENT, "H1").await;
    assert_h1_h2_no_body_path(&h1, &reset_url, reqwest::StatusCode::RESET_CONTENT, "H1").await;
    assert_h1_h2_no_body_path(
        &h1,
        &not_modified_url,
        reqwest::StatusCode::NOT_MODIFIED,
        "H1",
    )
    .await;

    // --- H2 (h2c prior knowledge on the plaintext proxy port) ---
    let h2_get = h2.get(&repr_url).send().await.expect("H2 GET /repr");
    assert_eq!(h2_get.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_get.status(), reqwest::StatusCode::OK);
    let h2_repr = h2_get.bytes().await.expect("H2 GET body");
    assert_eq!(&h2_repr[..], FORBIDDEN_BODY.as_bytes());

    let h2_head = h2.head(&repr_url).send().await.expect("H2 HEAD /repr");
    assert_eq!(h2_head.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_head.status(), reqwest::StatusCode::OK);
    assert_eq!(content_length(h2_head.headers()), Some(representation_len));
    assert!(h2_head.bytes().await.expect("H2 HEAD body").is_empty());

    assert_h1_h2_no_body_path(&h2, &empty_url, reqwest::StatusCode::NO_CONTENT, "H2").await;
    assert_h1_h2_no_body_path(&h2, &reset_url, reqwest::StatusCode::RESET_CONTENT, "H2").await;
    assert_h1_h2_no_body_path(
        &h2,
        &not_modified_url,
        reqwest::StatusCode::NOT_MODIFIED,
        "H2",
    )
    .await;

    // --- H3 ---
    let h3 = Http3Client::insecure().expect("H3 client");
    let h3_repr = format!("https://localhost:{https_port}/mock/repr");
    let h3_empty = format!("https://localhost:{https_port}/mock/empty");
    let h3_reset = format!("https://localhost:{https_port}/mock/reset");
    let h3_not_modified = format!("https://localhost:{https_port}/mock/not-modified");
    let h3_head_path = format!("https://localhost:{https_port}/mock/head");

    let h3_get = h3_request_until_ready(&h3, &h3_repr, Method::GET).await;
    assert_eq!(h3_get.status, StatusCode::OK);
    assert_eq!(h3_get.body_bytes.as_ref(), FORBIDDEN_BODY.as_bytes());

    let h3_head = h3_request_until_ready(&h3, &h3_repr, Method::HEAD).await;
    assert_eq!(h3_head.status, StatusCode::OK);
    assert!(
        h3_head.body_bytes.is_empty(),
        "H3 HEAD must not receive DATA/content bytes"
    );
    assert_eq!(
        h3_content_length(&h3_head.headers),
        Some(representation_len)
    );

    let h3_head_rule = h3_request_until_ready(&h3, &h3_head_path, Method::HEAD).await;
    assert_eq!(h3_head_rule.status, StatusCode::OK);
    assert!(h3_head_rule.body_bytes.is_empty());
    assert_eq!(
        h3_content_length(&h3_head_rule.headers),
        Some(FORBIDDEN_BODY.len())
    );

    for (url, status) in [
        (h3_empty.as_str(), StatusCode::NO_CONTENT),
        (h3_reset.as_str(), StatusCode::RESET_CONTENT),
        (h3_not_modified.as_str(), StatusCode::NOT_MODIFIED),
    ] {
        let response = h3_request_until_ready(&h3, url, Method::GET).await;
        assert_eq!(response.status, status, "H3 {url}");
        assert!(
            response.body_bytes.is_empty(),
            "H3 {url} must omit configured body"
        );
        assert!(
            response.headers.get(header::CONTENT_LENGTH).is_none(),
            "H3 {url} must strip Content-Length (got {:?})",
            response.headers.get(header::CONTENT_LENGTH)
        );
    }

    assert!(
        backend_listener.local_addr().is_ok(),
        "idle backend must remain bound (mock short-circuits)"
    );

    gateway.shutdown();
}
