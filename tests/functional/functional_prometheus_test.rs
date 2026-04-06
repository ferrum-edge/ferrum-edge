//! Functional Tests for Prometheus Metrics Plugin (E2E)
//!
//! Tests:
//! - `/metrics` endpoint on admin port returns Prometheus exposition format after traffic
//! - Request count metrics reflect actual traffic volume
//!
//! Uses file mode with ephemeral ports and an echo backend.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_prometheus

use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Helpers
// ============================================================================

/// Start a simple HTTP echo backend.
async fn start_echo_backend(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind echo backend");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Detect the gateway binary path (debug preferred, fallback to release).
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

/// Start the gateway in file mode with the given config and ports.
fn start_gateway(config_path: &str, proxy_port: u16, admin_port: u16) -> std::process::Child {
    let binary_path = gateway_binary_path();

    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

/// Wait for the gateway admin health endpoint to respond.
async fn wait_for_gateway(admin_port: u16) {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);

    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return;
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("Gateway did not become healthy within 15 seconds");
}

/// Allocate an ephemeral port by binding to port 0 and returning the assigned port.
async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

// ============================================================================
// Functional Tests
// ============================================================================

/// Test that the `/metrics` endpoint returns Prometheus-format data after traffic
/// flows through the gateway.
///
/// 1. Start an echo backend
/// 2. Start gateway in file mode with prometheus_metrics plugin
/// 3. Send a request through the gateway
/// 4. Scrape `/metrics` on the admin port
/// 5. Verify 200 status and Prometheus text format with `ferrum_` metric names
#[ignore]
#[tokio::test]
async fn test_prometheus_metrics_endpoint_returns_data() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let proxy_port = ephemeral_port().await;
    let admin_port = ephemeral_port().await;

    let config_content = format!(
        r#"
proxies:
  - id: "test-proxy"
    listen_path: "/test"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

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
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start echo backend
    tokio::spawn(start_echo_backend(backend_port));
    sleep(Duration::from_millis(500)).await;

    // Start gateway
    let mut gateway = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    sleep(Duration::from_secs(3)).await;
    wait_for_gateway(admin_port).await;

    let client = reqwest::Client::new();

    // Send a request through the proxy to generate metrics
    let proxy_resp = client
        .get(format!("http://127.0.0.1:{}/test/hello", proxy_port))
        .send()
        .await
        .expect("Failed to send proxy request");
    assert_eq!(proxy_resp.status(), 200, "Proxy request should succeed");

    // Small delay for async log/metrics recording
    sleep(Duration::from_secs(1)).await;

    // Scrape /metrics on admin port
    let metrics_resp = client
        .get(format!("http://127.0.0.1:{}/metrics", admin_port))
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

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Test that metrics reflect actual traffic volume.
///
/// 1. Start echo backend + gateway with prometheus_metrics plugin
/// 2. Send 3 requests through the gateway
/// 3. Scrape `/metrics`
/// 4. Verify request count metrics show values > 0
#[ignore]
#[tokio::test]
async fn test_prometheus_metrics_reflect_traffic() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let proxy_port = ephemeral_port().await;
    let admin_port = ephemeral_port().await;

    let config_content = format!(
        r#"
proxies:
  - id: "traffic-proxy"
    listen_path: "/traffic"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

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
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start echo backend
    tokio::spawn(start_echo_backend(backend_port));
    sleep(Duration::from_millis(500)).await;

    // Start gateway
    let mut gateway = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    sleep(Duration::from_secs(3)).await;
    wait_for_gateway(admin_port).await;

    let client = reqwest::Client::new();

    // Send 3 requests through the proxy
    for i in 0..3 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/traffic/req{}", proxy_port, i))
            .send()
            .await
            .expect("Failed to send proxy request");
        assert_eq!(resp.status(), 200, "Request {} should succeed", i);
    }

    // Wait for async metrics recording
    sleep(Duration::from_secs(1)).await;

    // Scrape /metrics
    let metrics_resp = client
        .get(format!("http://127.0.0.1:{}/metrics", admin_port))
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
            // Line format: ferrum_requests_total{proxy_id="...",method="...",status_code="200"} 3
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

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
}
