//! Functional Tests for Prometheus Metrics Plugin (E2E)
//!
//! Tests:
//! - `/metrics` endpoint on admin port returns Prometheus exposition format after traffic
//! - Request count metrics reflect actual traffic volume
//!
//! Uses file mode with the shared `TestGateway` harness + shared echo server
//! (no bind-drop-rebind race).
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_prometheus

use crate::common::{TestGateway, spawn_http_echo};
use std::time::Duration;
use tokio::time::sleep;

/// Test that the `/metrics` endpoint returns Prometheus-format data after traffic
/// flows through the gateway.
#[ignore]
#[tokio::test]
async fn test_prometheus_metrics_endpoint_returns_data() {
    let backend = spawn_http_echo().await.expect("spawn echo");

    let config = format!(
        r#"
proxies:
  - id: "test-proxy"
    listen_path: "/test"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "prom-1"

consumers: []
upstreams: []

plugin_configs:
  - id: "prom-1"
    proxy_id: "test-proxy"
    plugin_name: "prometheus_metrics"
    scope: "proxy"
    enabled: true
    config:
      render_cache_ttl_seconds: 0
"#,
        backend_port = backend.port,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();

    // Send a request through the proxy to generate metrics
    let proxy_resp = client
        .get(gateway.proxy_url("/test/hello"))
        .send()
        .await
        .expect("Failed to send proxy request");
    assert_eq!(proxy_resp.status(), 200, "Proxy request should succeed");

    // Small delay for async log/metrics recording
    sleep(Duration::from_secs(1)).await;

    // Scrape /metrics on admin port
    let metrics_resp = client
        .get(gateway.admin_url("/metrics"))
        .send()
        .await
        .expect("Failed to scrape /metrics");

    assert_eq!(
        metrics_resp.status(),
        200,
        "/metrics endpoint should return 200"
    );

    let body = metrics_resp
        .text()
        .await
        .expect("Failed to read /metrics body");

    // Verify Prometheus exposition format markers
    assert!(
        body.contains("# HELP ferrum_requests_total"),
        "/metrics should contain ferrum_requests_total HELP line. Body:\n{}",
        body
    );
    assert!(
        body.contains("# TYPE ferrum_requests_total counter"),
        "/metrics should contain ferrum_requests_total TYPE line. Body:\n{}",
        body
    );
    assert!(
        body.contains("ferrum_requests_total{"),
        "/metrics should contain ferrum_requests_total data. Body:\n{}",
        body
    );
    assert!(
        body.contains("ferrum_request_duration_ms"),
        "/metrics should contain ferrum_request_duration_ms. Body:\n{}",
        body
    );
}

/// Test that metrics reflect actual traffic volume.
#[ignore]
#[tokio::test]
async fn test_prometheus_metrics_reflect_traffic() {
    let backend = spawn_http_echo().await.expect("spawn echo");

    let config = format!(
        r#"
proxies:
  - id: "traffic-proxy"
    listen_path: "/traffic"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "prom-traffic"

consumers: []
upstreams: []

plugin_configs:
  - id: "prom-traffic"
    proxy_id: "traffic-proxy"
    plugin_name: "prometheus_metrics"
    scope: "proxy"
    enabled: true
    config:
      render_cache_ttl_seconds: 0
"#,
        backend_port = backend.port,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();

    // Send 3 requests through the proxy
    for i in 0..3 {
        let resp = client
            .get(gateway.proxy_url(&format!("/traffic/req{}", i)))
            .send()
            .await
            .expect("Failed to send proxy request");
        assert_eq!(resp.status(), 200, "Request {} should succeed", i);
    }

    // Wait for async metrics recording
    sleep(Duration::from_secs(1)).await;

    // Scrape /metrics
    let metrics_resp = client
        .get(gateway.admin_url("/metrics"))
        .send()
        .await
        .expect("Failed to scrape /metrics");

    assert_eq!(metrics_resp.status(), 200);

    let body = metrics_resp
        .text()
        .await
        .expect("Failed to read /metrics body");

    // Find the ferrum_requests_total line for our proxy and verify count >= 3
    let mut found_counter = false;
    for line in body.lines() {
        if line.starts_with("ferrum_requests_total{")
            && line.contains("proxy_id=\"traffic-proxy\"")
            && line.contains("status_code=\"200\"")
        {
            found_counter = true;
            let count_str = line.rsplit(' ').next().unwrap_or("0");
            let count: u64 = count_str
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse count from line: {}", line));
            assert!(
                count >= 3,
                "Expected request count >= 3, got {}. Full /metrics:\n{}",
                count,
                body
            );
        }
    }

    assert!(
        found_counter,
        "Did not find ferrum_requests_total counter for traffic-proxy with status 200. Full /metrics:\n{}",
        body
    );

    // Also verify histogram count reflects traffic
    let mut found_histogram_count = false;
    for line in body.lines() {
        if line.starts_with("ferrum_request_duration_ms_count{")
            && line.contains("proxy_id=\"traffic-proxy\"")
        {
            found_histogram_count = true;
            let count_str = line.rsplit(' ').next().unwrap_or("0");
            let count: u64 = count_str
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse histogram count: {}", line));
            assert!(
                count >= 3,
                "Expected histogram count >= 3, got {}. Full /metrics:\n{}",
                count,
                body
            );
        }
    }

    assert!(
        found_histogram_count,
        "Did not find ferrum_request_duration_ms_count for traffic-proxy. Full /metrics:\n{}",
        body
    );
}
