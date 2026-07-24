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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

async fn spawn_ai_usage_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind AI usage backend");
    let port = listener.local_addr().expect("AI backend address").port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let body = br#"{"id":"resp_1","object":"response","model":"gpt-5","usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    (port, task)
}

/// Test that the `/metrics` endpoint returns Prometheus-format data after traffic
/// flows through the gateway.
#[ignore]
#[tokio::test]
async fn test_prometheus_metrics_endpoint_returns_data() {
    let backend = spawn_http_echo().await.expect("spawn echo");

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "test-proxy"
    listen_path: "/test"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
consumers: []
upstreams: []
plugin_configs:
  - id: "prom-1"
    plugin_name: "prometheus_metrics"
    scope: "global"
    enabled: true
    config:
      render_cache_ttl_seconds: 0
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 1
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
        .header("Authorization", gateway.auth_header())
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
version: "1"
proxies:
  - id: "traffic-proxy"
    listen_path: "/traffic"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
consumers: []
upstreams: []
plugin_configs:
  - id: "prom-traffic"
    plugin_name: "prometheus_metrics"
    scope: "global"
    enabled: true
    config:
      render_cache_ttl_seconds: 0
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 1
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
        .header("Authorization", gateway.auth_header())
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

#[ignore]
#[tokio::test]
async fn test_ai_token_metrics_are_exported_to_prometheus() {
    let (backend_port, backend_task) = spawn_ai_usage_backend().await;
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ai-metrics-proxy"
    listen_path: "/ai-metrics"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ai-usage"
consumers: []
upstreams: []
plugin_configs:
  - id: "ai-usage"
    proxy_id: "ai-metrics-proxy"
    plugin_name: "ai_token_metrics"
    scope: "proxy"
    enabled: true
    config:
      provider: auto
      metadata_prefix: "custom.ai"
      cost_per_prompt_token: 0.000001
      cost_per_completion_token: 0.000002
  - id: "prom-ai"
    plugin_name: "prometheus_metrics"
    scope: "global"
    enabled: true
    config:
      render_cache_ttl_seconds: 0
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 2
"#
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .spawn()
        .await
        .expect("start AI metrics gateway");
    let client = reqwest::Client::new();
    let response = client
        .post(gateway.proxy_url("/ai-metrics/v1/responses"))
        .send()
        .await
        .expect("send AI response request");
    assert_eq!(response.status(), 200);
    response
        .bytes()
        .await
        .expect("read AI response body before scraping metrics");
    sleep(Duration::from_secs(1)).await;

    let metrics = client
        .get(gateway.admin_url("/metrics"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .expect("scrape AI metrics")
        .text()
        .await
        .expect("read AI metrics");
    assert!(metrics.contains(
        "ferrum_ai_prompt_tokens_total{proxy_id=\"ai-metrics-proxy\",provider=\"openai\",namespace=\"ferrum\"} 11"
    ));
    assert!(metrics.contains(
        "ferrum_ai_completion_tokens_total{proxy_id=\"ai-metrics-proxy\",provider=\"openai\",namespace=\"ferrum\"} 7"
    ));
    assert!(
        metrics.contains(
            "ferrum_ai_tokens_total{proxy_id=\"ai-metrics-proxy\",provider=\"openai\",namespace=\"ferrum\"} 18"
        )
    );
    assert!(metrics.contains(
        "ferrum_ai_estimated_cost_currency_units_total{proxy_id=\"ai-metrics-proxy\",provider=\"openai\",namespace=\"ferrum\"} 0.000025"
    ));
    backend_task.abort();
}
