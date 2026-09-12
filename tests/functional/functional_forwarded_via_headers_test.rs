//! Functional coverage for proxy-generated forwarding metadata.
//!
//! These tests launch the real gateway in file mode and assert the backend
//! sees the protocol headers the gateway is responsible for synthesizing:
//! X-Forwarded-*, Via, and RFC 7239 Forwarded. They also assert Via on the
//! response path, because that is generated separately from request forwarding.

use crate::common::TestGateway;
use crate::scaffolding::backends::{Http1Request, HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

use std::time::Duration;

struct HeaderHarness {
    gateway: TestGateway,
    backend: ScriptedHttp1Backend,
}

impl HeaderHarness {
    async fn new(add_via: bool, via_pseudonym: &str, add_forwarded: bool) -> Self {
        Self::spawn(add_via, via_pseudonym, add_forwarded, None).await
    }

    async fn spawn(
        add_via: bool,
        via_pseudonym: &str,
        add_forwarded: bool,
        trusted_proxies: Option<&str>,
    ) -> Self {
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

        let mut gateway = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .env("FERRUM_ADD_VIA_HEADER", add_via.to_string())
            .env("FERRUM_VIA_PSEUDONYM", via_pseudonym)
            .env("FERRUM_ADD_FORWARDED_HEADER", add_forwarded.to_string());
        if let Some(trusted) = trusted_proxies {
            gateway = gateway.env("FERRUM_TRUSTED_PROXIES", trusted);
        }
        let gateway = gateway.spawn().await.expect("start gateway");
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
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
consumers: []
plugin_configs: []
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
        .header("x-real-ip", "8.8.8.8")
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
    assert_eq!(only_header(&request, "x-forwarded-for"), "127.0.0.1");
    no_header(&request, "x-real-ip");
    assert_eq!(only_header(&request, "x-forwarded-proto"), "http");
    assert_eq!(only_header(&request, "x-forwarded-host"), "example.com");
    assert_eq!(only_header(&request, "via"), "1.1 ferrum-edge");
    no_header(&request, "forwarded");
}

/// Issue #4034: when the connecting peer is in `FERRUM_TRUSTED_PROXIES`, the
/// inbound XFF chain is still honored and the peer appended. `X-Real-IP`
/// from a trusted peer is passed through (Ferrum does not regenerate it).
#[ignore]
#[tokio::test]
async fn functional_forwarded_via_trusted_peer_appends_inbound_xff() {
    let harness = HeaderHarness::spawn(true, "ferrum-edge", false, Some("127.0.0.1")).await;
    let client = http1_client();

    let response = client
        .get(harness.proxy_url())
        .header("host", "example.com")
        .header("x-forwarded-for", "1.1.1.1, 198.51.100.9")
        .header("x-real-ip", "1.1.1.1")
        .send()
        .await
        .expect("gateway response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "ok");

    let request = harness.assert_backend_ok().await;
    assert_eq!(
        only_header(&request, "x-forwarded-for"),
        "1.1.1.1, 198.51.100.9, 127.0.0.1"
    );
    assert_eq!(only_header(&request, "x-real-ip"), "1.1.1.1");
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

/// Issue #2952: with `FERRUM_ADD_FORWARDED_HEADER=true`, the reqwest primary
/// builder must strip a spoofed client `Forwarded` before writing the
/// gateway-owned element. `pool_enable_http2: false` keeps this on the
/// reqwest arm (the historical append-after-client-value failure mode).
#[ignore]
#[tokio::test]
async fn functional_forwarded_via_reqwest_path_strips_spoofed_client_forwarded() {
    let harness = HeaderHarness::new(false, "ferrum-edge", true).await;
    let client = http1_client();

    let response = client
        .get(harness.proxy_url())
        .header("host", "example.com")
        .header("forwarded", "for=10.0.0.1;proto=https")
        .send()
        .await
        .expect("gateway response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "ok");

    let request = harness.assert_backend_ok().await;
    let forwarded = header_values(&request, "forwarded");
    assert_eq!(
        forwarded,
        vec!["for=127.0.0.1;proto=http;host=example.com"],
        "reqwest path must emit exactly one gateway-owned Forwarded derived from \
         the real client/scheme/Host; got {forwarded:?} (headers={:?})",
        request.headers
    );
    assert!(
        forwarded.iter().all(|v| !v.contains("10.0.0.1")),
        "spoofed client Forwarded must not reach the reqwest-path backend: {forwarded:?}"
    );
}

// ── Byte-preserving X-Forwarded-For (advisory GHSA-73ff-frj6-cpmp) ──────────
//
// `Forwarded: for=` is the backend-visible read-out of `ctx.client_ip`, so it
// is the discriminator for which chain element resolution selected. The inbound
// `X-Forwarded-For` chain the gateway regenerates for backends is deliberately
// NOT asserted here: rebuilding it from the materialized header map is a
// separate, already-tracked concern.

/// An `X-Forwarded-For` field-line carrying obs-text alongside the address the
/// trusted proxy appended must still resolve to that appended address. `é` is a
/// valid header value on the wire and valid UTF-8, yet `HeaderValue::to_str()`
/// refuses it — so this is the end-to-end proof that resolution reads the
/// field-line as bytes rather than through a text view.
#[ignore]
#[tokio::test]
async fn functional_forwarded_obs_text_xff_still_resolves_the_appended_client() {
    let harness = HeaderHarness::spawn(false, "ferrum-edge", true, Some("127.0.0.1")).await;
    let client = http1_client();

    // The leading element is `é` (bytes C3 A9): accepted by `HeaderValue`,
    // accepted on the wire, and refused by `HeaderValue::to_str()`.
    let response = client
        .get(harness.proxy_url())
        .header("host", "example.com")
        .header("x-forwarded-for", "é, 203.0.113.50")
        .send()
        .await
        .expect("gateway response");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "ok");

    let request = harness.assert_backend_ok().await;
    assert_eq!(
        only_header(&request, "forwarded"),
        "for=203.0.113.50;proto=http;host=example.com",
        "the appended boundary address must survive an unrepresentable field-line"
    );
}

/// Native HTTP/3 parity for the same advisory: the H3 ingress reads the chain
/// through the same byte-preserving accessor and must resolve the same
/// identity. `TestGateway` has no HTTPS port, so the H3 frontend is started
/// through `GatewayHarness` the way `functional_h3_soap_utf16_test` does.
#[ignore]
#[tokio::test]
async fn functional_forwarded_h3_obs_text_xff_still_resolves_the_appended_client() {
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
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let (_gateway, https_port, _scratch) = spawn_h3_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/metadata");
    let response = h3_request_with_retry(
        &client,
        &url,
        GetOptions::default().header("x-forwarded-for", "é, 203.0.113.50"),
    )
    .await;

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body_bytes.as_ref(), b"ok");

    let request = backend
        .received_requests()
        .await
        .into_iter()
        .find(|request| request.method == "GET" && request.path == "/metadata")
        .expect("backend received the H3-bridged request");
    let forwarded = only_header(&request, "forwarded");
    assert!(
        forwarded.starts_with("for=203.0.113.50;"),
        "H3 must resolve the appended boundary address, got {forwarded:?}"
    );
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("forwarded-h3-gateway").expect("gateway CA");
    let (cert, key) = ca.valid().expect("gateway leaf");
    let cert_path = scratch.join("gateway.cert.pem");
    let key_path = scratch.join("gateway.key.pem");
    std::fs::write(&cert_path, cert).expect("write gateway cert");
    std::fs::write(&key_path, key).expect("write gateway key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_h3_gateway(backend_port: u16) -> (GatewayHarness, u16, tempfile::TempDir) {
    let yaml = build_config(backend_port);
    let mut last_error = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve H3 port");
        let https_port = reservation.port;
        drop(reservation);
        let scratch = tempfile::tempdir().expect("gateway scratch dir");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        match GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("warn")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_TRUSTED_PROXIES", "127.0.0.1")
            .env("FERRUM_ADD_VIA_HEADER", "false")
            .env("FERRUM_ADD_FORWARDED_HEADER", "true")
            .spawn()
            .await
        {
            Ok(gateway) => return (gateway, https_port, scratch),
            Err(error) => last_error = error.to_string(),
        }
    }
    panic!("failed to spawn H3 forwarded-metadata gateway: {last_error}");
}

async fn h3_request_with_retry(
    client: &Http3Client,
    url: &str,
    options: GetOptions,
) -> Http3Response {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return response,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(error) => panic!("H3 forwarded-metadata request never completed: {error}"),
        }
    }
}
