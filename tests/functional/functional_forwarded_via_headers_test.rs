//! Functional coverage for proxy-generated forwarding metadata.
//!
//! These tests launch the real gateway in file mode and assert the backend
//! sees the protocol headers the gateway is responsible for synthesizing:
//! X-Forwarded-*, Via, and RFC 7239 Forwarded. They also assert Via on the
//! response path, because that is generated separately from request forwarding.

use crate::common::TestGateway;
use crate::scaffolding::backends::{Http1Request, HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::ports::reserve_port;

use std::time::Duration;

struct HeaderHarness {
    gateway: TestGateway,
    backend: ScriptedHttp1Backend,
}

impl HeaderHarness {
    async fn new(add_via: bool, via_pseudonym: &str, add_forwarded: bool) -> Self {
        let reservation = reserve_port().await.expect("reserve backend port");
        let backend_port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .step(HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "2".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "X-Backend-Marker".into(),
                value: "forwarded-via".into(),
            })
            .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn backend");

        let gateway = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .env("FERRUM_ADD_VIA_HEADER", add_via.to_string())
            .env("FERRUM_VIA_PSEUDONYM", via_pseudonym)
            .env("FERRUM_ADD_FORWARDED_HEADER", add_forwarded.to_string())
            .spawn()
            .await
            .expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self { gateway, backend }
    }

    fn proxy_url(&self) -> String {
        self.gateway.proxy_url("/metadata")
    }

    async fn assert_backend_ok(&self) -> Http1Request {
        self.backend.assert_no_matcher_mismatches().await;
        let request = self
            .backend
            .received_requests()
            .await
            .into_iter()
            .find(|request| request.method == "GET" && request.path == "/metadata")
            .expect("backend received metadata request");

        let step_errors = self.backend.step_errors().await;
        let unexpected_step_errors: Vec<_> = step_errors
            .iter()
            // The client response was already asserted complete; a late peer
            // close while the scripted backend finishes writing is not a
            // forwarding-header failure.
            .filter(|error| !is_late_response_peer_close(error))
            .collect();
        assert!(
            unexpected_step_errors.is_empty(),
            "{} unexpected script step error(s): {:?}",
            unexpected_step_errors.len(),
            unexpected_step_errors
        );

        request
    }
}

fn is_late_response_peer_close(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("broken pipe") || error.contains("connection reset by peer")
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "forwarded-via"
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

fn header_values<'a>(request: &'a Http1Request, name: &str) -> Vec<&'a str> {
    request
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

fn only_header<'a>(request: &'a Http1Request, name: &str) -> &'a str {
    let values = header_values(request, name);
    assert_eq!(
        values.len(),
        1,
        "expected exactly one {name} header, got {values:?}"
    );
    values[0]
}

fn no_header(request: &Http1Request, name: &str) {
    let values = header_values(request, name);
    assert!(
        values.is_empty(),
        "expected no {name} header, got {values:?}"
    );
}

fn response_header<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn http1_client() -> reqwest::Client {
    reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
}

#[ignore]
#[tokio::test]
async fn functional_forwarded_via_default_adds_x_forwarded_and_via() {
    let harness = HeaderHarness::new(true, "ferrum-edge", false).await;
    let client = http1_client();

    let response = client
        .get(harness.proxy_url())
        .header("host", "example.com")
        .header("x-forwarded-for", "198.51.100.9")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "attacker.example")
        .send()
        .await
        .expect("gateway response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_header(response.headers(), "via"),
        Some("1.1 ferrum-edge")
    );
    assert_eq!(response.text().await.expect("body"), "ok");

    let request = harness.assert_backend_ok().await;
    assert_eq!(
        only_header(&request, "x-forwarded-for"),
        "198.51.100.9, 127.0.0.1"
    );
    assert_eq!(only_header(&request, "x-forwarded-proto"), "http");
    assert_eq!(only_header(&request, "x-forwarded-host"), "example.com");
    assert_eq!(only_header(&request, "via"), "1.1 ferrum-edge");
    no_header(&request, "forwarded");
}

#[ignore]
#[tokio::test]
async fn functional_forwarded_via_custom_pseudonym_and_forwarded_enabled() {
    let harness = HeaderHarness::new(true, "edge-under-test", true).await;
    let client = http1_client();

    let response = client
        .get(harness.proxy_url())
        .header("host", "example.com")
        .send()
        .await
        .expect("gateway response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_header(response.headers(), "via"),
        Some("1.1 edge-under-test")
    );
    assert_eq!(response.text().await.expect("body"), "ok");

    let request = harness.assert_backend_ok().await;
    assert_eq!(only_header(&request, "x-forwarded-for"), "127.0.0.1");
    assert_eq!(only_header(&request, "x-forwarded-proto"), "http");
    assert_eq!(only_header(&request, "x-forwarded-host"), "example.com");
    assert_eq!(only_header(&request, "via"), "1.1 edge-under-test");
    assert_eq!(
        only_header(&request, "forwarded"),
        "for=127.0.0.1;proto=http;host=example.com"
    );
}

#[ignore]
#[tokio::test]
async fn functional_forwarded_via_can_disable_via_without_disabling_forwarded_headers() {
    let harness = HeaderHarness::new(false, "edge-disabled", true).await;
    let client = http1_client();

    let response = client
        .get(harness.proxy_url())
        .header("host", "example.com")
        .send()
        .await
        .expect("gateway response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response_header(response.headers(), "via"), None);
    assert_eq!(response.text().await.expect("body"), "ok");

    let request = harness.assert_backend_ok().await;
    no_header(&request, "via");
    assert_eq!(only_header(&request, "x-forwarded-for"), "127.0.0.1");
    assert_eq!(only_header(&request, "x-forwarded-proto"), "http");
    assert_eq!(only_header(&request, "x-forwarded-host"), "example.com");
    assert_eq!(
        only_header(&request, "forwarded"),
        "for=127.0.0.1;proto=http;host=example.com"
    );
}
