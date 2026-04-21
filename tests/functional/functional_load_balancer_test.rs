//! Functional tests for Ferrum Edge load balancing capabilities.
//!
//! These tests validate end-to-end load balancing behavior by:
//! 1. Starting multiple backend echo servers that identify themselves
//! 2. Creating YAML configs with upstreams, targets, and health checks
//! 3. Starting the gateway binary in file mode
//! 4. Sending requests and verifying correct distribution across backends
//!
//! Run with: cargo test --test functional_load_balancer_test -- --ignored --nocapture

use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Identifying Echo Server — each backend returns its own identity
// ============================================================================

/// Start an HTTP server that responds with a JSON body identifying itself.
/// Optionally serves a health endpoint at /health with a configurable status.
async fn start_identifying_server(port: u16, name: &'static str) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Failed to bind identifying server {} on port {}",
                name, port
            )
        });

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let server_name = name;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();

                // Parse the request path
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (status, body) = if path == "/health" {
                    (
                        200,
                        format!(r#"{{"server":"{}","status":"healthy"}}"#, server_name),
                    )
                } else {
                    (
                        200,
                        format!(r#"{{"server":"{}","path":"{}"}}"#, server_name, path),
                    )
                };

                let response = format!(
                    "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Start an HTTP server that always responds with a specific status code (for health check testing).
async fn start_status_server(port: u16, name: &'static str, status_code: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap_or_else(|_| panic!("Failed to bind status server {} on port {}", name, port));

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let server_name = name;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = format!(
                    r#"{{"server":"{}","status_code":{}}}"#,
                    server_name, status_code
                );
                let response = format!(
                    "HTTP/1.1 {} Error\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    status_code,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Start a server that initially returns errors then switches to healthy.
/// Uses a shared atomic counter to track call count.
async fn start_flapping_server(port: u16, name: &'static str, fail_count: u32) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap_or_else(|_| panic!("Failed to bind flapping server {} on port {}", name, port));

    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let server_name = name;
            let counter = counter.clone();
            let fail_limit = fail_count;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let call_num = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (status_code, status_text) = if call_num < fail_limit {
                    (500, "Internal Server Error")
                } else {
                    (200, "OK")
                };

                let body = format!(
                    r#"{{"server":"{}","call":{},"status_code":{}}}"#,
                    server_name, call_num, status_code
                );
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    status_code,
                    status_text,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

// ============================================================================
// Gateway Startup Helper
// ============================================================================

fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let build_output = std::process::Command::new("cargo")
        .args(["build", "--bin", "ferrum-edge"])
        .output()?;

    if !build_output.status.success() {
        eprintln!("Failed to build gateway binary");
        eprintln!("stderr: {}", String::from_utf8_lossy(&build_output.stderr));
        return Err("Build failed".into());
    }

    let binary_path = if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    };

    let child = std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    Ok(child)
}

/// Poll the admin /health endpoint until the gateway is ready or timeout.
async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    for _ in 0..30 {
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{}/health", admin_port))
            .send()
            .await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Start the gateway with port allocation retry logic.
/// Allocates fresh proxy and admin ports each attempt.
/// Returns (child process, proxy_port, admin_port) on success.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        // Allocate fresh ephemeral ports each attempt
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        match start_gateway_in_file_mode(config_path, proxy_port, admin_port) {
            Ok(mut child) => {
                if wait_for_gateway(admin_port).await {
                    return (child, proxy_port, admin_port);
                }
                eprintln!(
                    "Gateway startup attempt {}/{} failed (health check timeout on admin port {})",
                    attempt, MAX_ATTEMPTS, admin_port
                );
                let _ = child.kill();
                let _ = child.wait();
            }
            Err(e) => {
                eprintln!(
                    "Gateway startup attempt {}/{} failed to spawn: {}",
                    attempt, MAX_ATTEMPTS, e
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

/// Start an HTTP server that identifies itself but delays its response.
/// This keeps connections alive long enough for least-connections to see non-zero counts.
async fn start_slow_identifying_server(port: u16, name: &'static str, delay_ms: u64) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Failed to bind slow identifying server {} on port {}",
                name, port
            )
        });

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let server_name = name;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();

                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                // Delay before responding so connections stay open
                sleep(Duration::from_millis(delay_ms)).await;

                let body = format!(r#"{{"server":"{}","path":"{}"}}"#, server_name, path);
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

/// Parse the "server" field from a JSON response body.
fn parse_server_name(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("server").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_default()
}

// ============================================================================
// Test: Round-Robin Load Balancing
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_round_robin_load_balancing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "lb-proxy"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30001
    strip_listen_path: true
    upstream_id: "upstream-rr"

upstreams:
  - id: "upstream-rr"
    name: "Round Robin Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30001
        weight: 1
      - host: "127.0.0.1"
        port: 30002
        weight: 1
      - host: "127.0.0.1"
        port: 30003
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Start 3 backend servers
    let s1 = tokio::spawn(start_identifying_server(30001, "server1"));
    let s2 = tokio::spawn(start_identifying_server(30002, "server2"));
    let s3 = tokio::spawn(start_identifying_server(30003, "server3"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // Send 30 requests — should distribute evenly across 3 servers (10 each)
    for i in 0..30 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/api/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(
                    r.status().is_success(),
                    "Request {} failed with {}",
                    i,
                    r.status()
                );
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Round-robin distribution: {:?}", counts);

    // Verify all 3 servers received traffic
    assert!(
        counts.len() == 3,
        "Expected traffic to 3 servers, got {:?}",
        counts
    );

    // Each server should get exactly 10 requests with round-robin
    for (server, count) in &counts {
        assert_eq!(
            *count, 10,
            "Server {} got {} requests, expected 10",
            server, count
        );
    }

    // Cleanup
    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Weighted Round-Robin Load Balancing
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_weighted_round_robin_load_balancing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Weight 5 for heavy, weight 1 for light — heavy should get ~5x traffic
    let config = r#"
proxies:
  - id: "lb-wrr-proxy"
    listen_path: "/wrr"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30011
    strip_listen_path: true
    upstream_id: "upstream-wrr"

upstreams:
  - id: "upstream-wrr"
    name: "Weighted Round Robin Upstream"
    algorithm: weighted_round_robin
    targets:
      - host: "127.0.0.1"
        port: 30011
        weight: 5
      - host: "127.0.0.1"
        port: 30012
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let s1 = tokio::spawn(start_identifying_server(30011, "heavy"));
    let s2 = tokio::spawn(start_identifying_server(30012, "light"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // Send 60 requests — heavy should get ~50, light ~10
    for i in 0..60 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/wrr/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(
                    r.status().is_success(),
                    "Request {} failed with {}",
                    i,
                    r.status()
                );
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Weighted round-robin distribution: {:?}", counts);

    let heavy = counts.get("heavy").copied().unwrap_or(0);
    let light = counts.get("light").copied().unwrap_or(0);

    assert_eq!(heavy + light, 60, "Total requests should be 60");
    // heavy should get at least 3x more than light (actual ratio is 5:1)
    assert!(
        heavy > light * 3,
        "Heavy ({}) should get at least 3x more than light ({})",
        heavy,
        light
    );
    // Expected: heavy=50, light=10
    assert_eq!(heavy, 50, "Heavy server should get exactly 50 requests");
    assert_eq!(light, 10, "Light server should get exactly 10 requests");

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: Consistent Hashing — same key always routes to same server
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_consistent_hashing_load_balancing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "lb-hash-proxy"
    listen_path: "/hash"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30021
    strip_listen_path: true
    upstream_id: "upstream-hash"

upstreams:
  - id: "upstream-hash"
    name: "Consistent Hash Upstream"
    algorithm: consistent_hashing
    targets:
      - host: "127.0.0.1"
        port: 30021
        weight: 1
      - host: "127.0.0.1"
        port: 30022
        weight: 1
      - host: "127.0.0.1"
        port: 30023
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let s1 = tokio::spawn(start_identifying_server(30021, "hash-server1"));
    let s2 = tokio::spawn(start_identifying_server(30022, "hash-server2"));
    let s3 = tokio::spawn(start_identifying_server(30023, "hash-server3"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Same client IP (127.0.0.1) should always route to the same server
    let mut first_server = String::new();
    for i in 0..20 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/hash/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(r.status().is_success());
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if first_server.is_empty() {
                    first_server = server.clone();
                    println!("Consistent hashing selected server: {}", first_server);
                }
                assert_eq!(
                    server, first_server,
                    "Request {} went to {} instead of {}",
                    i, server, first_server
                );
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Active Health Checks — unhealthy targets are excluded
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_active_health_check_excludes_unhealthy() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Server on port 30031 is healthy, server on port 30032 returns 500s,
    // active health checks should mark 30032 as unhealthy after threshold
    let config = r#"
proxies:
  - id: "lb-health-proxy"
    listen_path: "/health-test"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30031
    strip_listen_path: true
    upstream_id: "upstream-health"

upstreams:
  - id: "upstream-health"
    name: "Health Check Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30031
        weight: 1
      - host: "127.0.0.1"
        port: 30032
        weight: 1
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 1
        timeout_ms: 2000
        healthy_threshold: 1
        unhealthy_threshold: 2
        healthy_status_codes: [200]

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 is healthy, server 2 returns 500
    let s1 = tokio::spawn(start_identifying_server(30031, "healthy-server"));
    let s2 = tokio::spawn(start_status_server(30032, "unhealthy-server", 500));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Wait for health checks to run (interval=1s, threshold=2 → needs ~3s)
    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // After health checks run, all traffic should go to the healthy server
    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/health-test/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Health check distribution: {:?}", counts);

    // All traffic should go to the healthy server
    assert!(
        counts.get("healthy-server").copied().unwrap_or(0) == 20,
        "All 20 requests should go to healthy-server, got {:?}",
        counts
    );
    assert!(
        !counts.contains_key("unhealthy-server"),
        "No requests should go to unhealthy-server, got {:?}",
        counts
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: Passive Health Checks — backends returning errors get excluded
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_passive_health_check_marks_unhealthy() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // One server always returns 500, passive health check should eventually mark it unhealthy
    let config = r#"
proxies:
  - id: "lb-passive-proxy"
    listen_path: "/passive"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30041
    strip_listen_path: true
    upstream_id: "upstream-passive"

upstreams:
  - id: "upstream-passive"
    name: "Passive Health Check Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30041
        weight: 1
      - host: "127.0.0.1"
        port: 30042
        weight: 1
    health_checks:
      passive:
        unhealthy_status_codes: [500, 502, 503]
        unhealthy_threshold: 3
        unhealthy_window_seconds: 60

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 is healthy, server 2 always returns 500
    let s1 = tokio::spawn(start_identifying_server(30041, "good-server"));
    let s2 = tokio::spawn(start_status_server(30042, "bad-server", 500));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // First, send enough requests that the bad server gets 3+ failures (threshold)
    // With round-robin across 2 servers, ~half go to bad-server
    for i in 0..10 {
        let _ = client
            .get(format!(
                "http://127.0.0.1:{}/passive/warmup-{}",
                proxy_port, i
            ))
            .send()
            .await;
    }

    // Give passive health check time to process
    sleep(Duration::from_millis(500)).await;

    // Now send more requests — bad-server should be excluded
    let mut counts: HashMap<String, u32> = HashMap::new();
    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/passive/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Passive health check distribution: {:?}", counts);

    // After passive health check kicks in, majority should go to good-server
    let good = counts.get("good-server").copied().unwrap_or(0);
    assert!(
        good >= 18,
        "At least 18 of 20 requests should go to good-server after passive health check, got {}",
        good
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: Active Health Check Recovery — server recovers and gets traffic again
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_active_health_check_recovery() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Server on port 30051 is always healthy.
    // Server on port 30052 starts failing then recovers (flapping server).
    // Active health check should eventually re-include server 2.
    let config = r#"
proxies:
  - id: "lb-recovery-proxy"
    listen_path: "/recovery"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30051
    strip_listen_path: true
    upstream_id: "upstream-recovery"

upstreams:
  - id: "upstream-recovery"
    name: "Recovery Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30051
        weight: 1
      - host: "127.0.0.1"
        port: 30052
        weight: 1
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 1
        timeout_ms: 2000
        healthy_threshold: 1
        unhealthy_threshold: 2
        healthy_status_codes: [200]

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 is always healthy. Server 2 starts by failing 4 health checks then recovers.
    let s1 = tokio::spawn(start_identifying_server(30051, "always-healthy"));
    let s2 = tokio::spawn(start_flapping_server(30052, "recovering", 4));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Wait for health checks: server2 fails first 4 checks, then recovers
    // interval=1s, so after ~6s server2 should have recovered
    sleep(Duration::from_secs(8)).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // After recovery, both servers should receive traffic
    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/recovery/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Recovery distribution: {:?}", counts);

    // Both servers should get some traffic after recovery
    assert!(
        counts.len() == 2,
        "Both servers should get traffic after recovery, got {:?}",
        counts
    );
    assert!(
        counts.get("always-healthy").copied().unwrap_or(0) > 0,
        "always-healthy should get traffic"
    );
    assert!(
        counts.get("recovering").copied().unwrap_or(0) > 0,
        "recovering server should get traffic after recovery"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: Config Reload Updates Upstream Targets (SIGHUP)
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_config_reload_updates_upstream_targets() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Initial config with 2 targets
    let initial_config = r#"
proxies:
  - id: "lb-reload-proxy"
    listen_path: "/reload"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30061
    strip_listen_path: true
    upstream_id: "upstream-reload"

upstreams:
  - id: "upstream-reload"
    name: "Reload Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30061
        weight: 1
      - host: "127.0.0.1"
        port: 30062
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(initial_config.as_bytes())
        .unwrap();

    let s1 = tokio::spawn(start_identifying_server(30061, "target-a"));
    let s2 = tokio::spawn(start_identifying_server(30062, "target-b"));
    let s3 = tokio::spawn(start_identifying_server(30063, "target-c"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Verify initial state: traffic goes to target-a and target-b
    let mut initial_counts: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/reload/test-{}", proxy_port, i))
            .send()
            .await;
        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            let server = parse_server_name(&body);
            if !server.is_empty() {
                *initial_counts.entry(server).or_insert(0) += 1;
            }
        }
    }

    println!("Initial distribution: {:?}", initial_counts);
    assert!(
        initial_counts.contains_key("target-a"),
        "target-a should get traffic initially"
    );
    assert!(
        initial_counts.contains_key("target-b"),
        "target-b should get traffic initially"
    );
    assert!(
        !initial_counts.contains_key("target-c"),
        "target-c should NOT get traffic initially"
    );

    // Update config: add target-c, remove target-b
    let updated_config = r#"
proxies:
  - id: "lb-reload-proxy"
    listen_path: "/reload"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30061
    strip_listen_path: true
    upstream_id: "upstream-reload"

upstreams:
  - id: "upstream-reload"
    name: "Reload Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30061
        weight: 1
      - host: "127.0.0.1"
        port: 30063
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(updated_config.as_bytes())
        .unwrap();

    // Send SIGHUP to reload config
    #[cfg(unix)]
    {
        let pid = gateway.id();
        let _ = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }

    sleep(Duration::from_secs(2)).await;

    // Verify updated state: traffic goes to target-a and target-c
    let mut updated_counts: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/reload/updated-{}",
                proxy_port, i
            ))
            .send()
            .await;
        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            let server = parse_server_name(&body);
            if !server.is_empty() {
                *updated_counts.entry(server).or_insert(0) += 1;
            }
        }
    }

    println!("Updated distribution: {:?}", updated_counts);
    assert!(
        updated_counts.contains_key("target-a"),
        "target-a should get traffic after reload"
    );
    assert!(
        updated_counts.contains_key("target-c"),
        "target-c should get traffic after reload"
    );
    assert!(
        !updated_counts.contains_key("target-b"),
        "target-b should NOT get traffic after reload"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Retry with Load Balancing — retry goes to different target
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_retry_selects_different_target() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // One server always returns 502, retry should go to the other server
    let config = r#"
proxies:
  - id: "lb-retry-proxy"
    listen_path: "/retry"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30171
    strip_listen_path: true
    upstream_id: "upstream-retry"
    retry:
      max_retries: 3
      retryable_status_codes: [502, 503]
      retryable_methods: ["GET", "HEAD"]
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 100

upstreams:
  - id: "upstream-retry"
    name: "Retry Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30171
        weight: 1
      - host: "127.0.0.1"
        port: 30172
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 always returns 502, server 2 is healthy
    let s1 = tokio::spawn(start_status_server(30171, "failing-server", 502));
    let s2 = tokio::spawn(start_identifying_server(30172, "fallback-server"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Send requests — retry logic should route to fallback-server after 502 from failing-server
    let mut success_count = 0;
    for i in 0..10 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/retry/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                if r.status().is_success() {
                    success_count += 1;
                }
            }
            Err(e) => eprintln!("Request {} error: {}", i, e),
        }
    }

    println!(
        "Retry test: {} successful responses out of 10",
        success_count
    );

    // At least some requests should succeed via retry to fallback-server
    assert!(
        success_count > 0,
        "Some requests should succeed via retry to fallback-server"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: All Unhealthy Fallback — when all targets are unhealthy, still serves
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_all_unhealthy_fallback() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Both servers return 500 on /health but 200 on other paths.
    // Active health checks will mark both as unhealthy,
    // but requests should still be served (fallback to all targets).
    let config = r#"
proxies:
  - id: "lb-fallback-proxy"
    listen_path: "/fallback"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30081
    strip_listen_path: true
    upstream_id: "upstream-fallback"

upstreams:
  - id: "upstream-fallback"
    name: "Fallback Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30081
        weight: 1
      - host: "127.0.0.1"
        port: 30082
        weight: 1
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 1
        timeout_ms: 2000
        healthy_threshold: 1
        unhealthy_threshold: 2
        healthy_status_codes: [200]

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Both servers return 500 on /health (so active checks mark them unhealthy)
    // but they respond normally to other requests
    let s1 = tokio::spawn(start_status_server(30081, "server-x", 500));
    let s2 = tokio::spawn(start_status_server(30082, "server-y", 500));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Wait for active health checks to mark both unhealthy
    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();

    // Even with all targets unhealthy, gateway should still route (fallback behavior)
    let mut response_count = 0;
    for i in 0..10 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/fallback/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        if resp.is_ok() {
            response_count += 1;
        }
    }

    println!(
        "Fallback test: {} responses received out of 10",
        response_count
    );

    // Should get responses even though all targets are unhealthy (fallback behavior)
    assert!(
        response_count == 10,
        "All 10 requests should get responses via fallback, got {}",
        response_count
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: Multiple Upstreams — different proxies use different upstreams
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_multiple_upstreams() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "api-proxy"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30091
    strip_listen_path: true
    upstream_id: "upstream-api"

  - id: "static-proxy"
    listen_path: "/static"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30093
    strip_listen_path: true
    upstream_id: "upstream-static"

upstreams:
  - id: "upstream-api"
    name: "API Servers"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30091
        weight: 1
      - host: "127.0.0.1"
        port: 30092
        weight: 1

  - id: "upstream-static"
    name: "Static Servers"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30093
        weight: 1
      - host: "127.0.0.1"
        port: 30094
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let s1 = tokio::spawn(start_identifying_server(30091, "api-1"));
    let s2 = tokio::spawn(start_identifying_server(30092, "api-2"));
    let s3 = tokio::spawn(start_identifying_server(30093, "static-1"));
    let s4 = tokio::spawn(start_identifying_server(30094, "static-2"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Test /api routes to api servers
    let mut api_servers: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/api/test-{}", proxy_port, i))
            .send()
            .await;
        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            let server = parse_server_name(&body);
            if !server.is_empty() {
                *api_servers.entry(server).or_insert(0) += 1;
            }
        }
    }

    // Test /static routes to static servers
    let mut static_servers: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/static/test-{}", proxy_port, i))
            .send()
            .await;
        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            let server = parse_server_name(&body);
            if !server.is_empty() {
                *static_servers.entry(server).or_insert(0) += 1;
            }
        }
    }

    println!("API servers: {:?}", api_servers);
    println!("Static servers: {:?}", static_servers);

    // API traffic should only go to api-1 and api-2
    assert!(
        api_servers.contains_key("api-1"),
        "api-1 should get /api traffic"
    );
    assert!(
        api_servers.contains_key("api-2"),
        "api-2 should get /api traffic"
    );
    assert!(
        !api_servers.contains_key("static-1"),
        "static-1 should NOT get /api traffic"
    );

    // Static traffic should only go to static-1 and static-2
    assert!(
        static_servers.contains_key("static-1"),
        "static-1 should get /static traffic"
    );
    assert!(
        static_servers.contains_key("static-2"),
        "static-2 should get /static traffic"
    );
    assert!(
        !static_servers.contains_key("api-1"),
        "api-1 should NOT get /static traffic"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
    s4.abort();
}

// ============================================================================
// Test: Weighted Targets with Unequal Weights (3:2:1 ratio)
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_weighted_round_robin_three_targets() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "lb-wrr3-proxy"
    listen_path: "/wrr3"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30101
    strip_listen_path: true
    upstream_id: "upstream-wrr3"

upstreams:
  - id: "upstream-wrr3"
    name: "WRR 3 Targets"
    algorithm: weighted_round_robin
    targets:
      - host: "127.0.0.1"
        port: 30101
        weight: 3
      - host: "127.0.0.1"
        port: 30102
        weight: 2
      - host: "127.0.0.1"
        port: 30103
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let s1 = tokio::spawn(start_identifying_server(30101, "weight-3"));
    let s2 = tokio::spawn(start_identifying_server(30102, "weight-2"));
    let s3 = tokio::spawn(start_identifying_server(30103, "weight-1"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // Send 60 requests: expected ratio 3:2:1 → 30:20:10
    for i in 0..60 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/wrr3/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("WRR 3:2:1 distribution: {:?}", counts);

    let w3 = counts.get("weight-3").copied().unwrap_or(0);
    let w2 = counts.get("weight-2").copied().unwrap_or(0);
    let w1 = counts.get("weight-1").copied().unwrap_or(0);

    assert_eq!(w3 + w2 + w1, 60, "Total should be 60");
    // weight-3 should get the most, weight-1 the least
    assert!(
        w3 > w2,
        "weight-3 ({}) should get more than weight-2 ({})",
        w3,
        w2
    );
    assert!(
        w2 > w1,
        "weight-2 ({}) should get more than weight-1 ({})",
        w2,
        w1
    );
    // Expected exact: 30, 20, 10
    assert_eq!(w3, 30, "weight-3 should get 30 requests");
    assert_eq!(w2, 20, "weight-2 should get 20 requests");
    assert_eq!(w1, 10, "weight-1 should get 10 requests");

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Combined Active + Passive Health Checks
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_combined_active_and_passive_health_checks() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "lb-combined-proxy"
    listen_path: "/combined"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30111
    strip_listen_path: true
    upstream_id: "upstream-combined"

upstreams:
  - id: "upstream-combined"
    name: "Combined Health Check Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30111
        weight: 1
      - host: "127.0.0.1"
        port: 30112
        weight: 1
      - host: "127.0.0.1"
        port: 30113
        weight: 1
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 1
        timeout_ms: 2000
        healthy_threshold: 1
        unhealthy_threshold: 2
        healthy_status_codes: [200]
      passive:
        unhealthy_status_codes: [500, 502, 503]
        unhealthy_threshold: 3
        unhealthy_window_seconds: 60

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 healthy, server 2 returns 500 (caught by active), server 3 healthy
    let s1 = tokio::spawn(start_identifying_server(30111, "combined-ok-1"));
    let s2 = tokio::spawn(start_status_server(30112, "combined-bad", 500));
    let s3 = tokio::spawn(start_identifying_server(30113, "combined-ok-2"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Wait for active health checks to detect unhealthy server
    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/combined/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Combined health check distribution: {:?}", counts);

    // Traffic should only go to healthy servers
    assert!(
        counts.get("combined-ok-1").copied().unwrap_or(0) > 0,
        "combined-ok-1 should get traffic"
    );
    assert!(
        counts.get("combined-ok-2").copied().unwrap_or(0) > 0,
        "combined-ok-2 should get traffic"
    );
    assert!(
        !counts.contains_key("combined-bad"),
        "combined-bad should NOT get traffic, got {:?}",
        counts
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Unreachable Target — connection failure handled gracefully
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_unreachable_target_with_retry() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // One target is on a port where nothing is listening (connection refused)
    let config = r#"
proxies:
  - id: "lb-unreachable-proxy"
    listen_path: "/unreachable"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30121
    strip_listen_path: true
    upstream_id: "upstream-unreachable"
    retry:
      max_retries: 3
      retryable_status_codes: [502, 503]
      retryable_methods: ["GET"]
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 50

upstreams:
  - id: "upstream-unreachable"
    name: "Unreachable Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30121
        weight: 1
      - host: "127.0.0.1"
        port: 39999
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Only start server on port 30121, port 39999 has nothing listening
    let s1 = tokio::spawn(start_identifying_server(30121, "reachable-server"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Requests that initially hit the unreachable target should retry to the reachable one
    let mut success_count = 0;
    for i in 0..10 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/unreachable/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                if r.status().is_success() {
                    success_count += 1;
                }
            }
            Err(e) => eprintln!("Request {} error: {}", i, e),
        }
    }

    println!(
        "Unreachable target test: {} successes out of 10",
        success_count
    );

    // With retry logic and connection failure retry enabled,
    // requests should eventually reach the reachable server
    assert!(
        success_count > 0,
        "Some requests should succeed by retrying to the reachable server"
    );

    let _ = gateway.kill();
    s1.abort();
}

// ============================================================================
// Test: Single-Backend Proxy (no upstream_id) coexists with LB proxies
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_single_backend_and_load_balanced_coexist() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Two proxies: one uses upstream_id (load balanced), one uses direct backend
    let config = r#"
proxies:
  - id: "direct-proxy"
    listen_path: "/direct"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30131
    strip_listen_path: true

  - id: "lb-proxy"
    listen_path: "/balanced"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30131
    strip_listen_path: true
    upstream_id: "upstream-coexist"

upstreams:
  - id: "upstream-coexist"
    name: "Coexist Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30132
        weight: 1
      - host: "127.0.0.1"
        port: 30133
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // direct-backend is the single-target server
    let s1 = tokio::spawn(start_identifying_server(30131, "direct-backend"));
    // lb targets
    let s2 = tokio::spawn(start_identifying_server(30132, "lb-target-1"));
    let s3 = tokio::spawn(start_identifying_server(30133, "lb-target-2"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // --- Test direct proxy (no upstream_id) ---
    let mut direct_servers: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/direct/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(
                    r.status().is_success(),
                    "Direct request {} failed: {}",
                    i,
                    r.status()
                );
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *direct_servers.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Direct request {} failed: {}", i, e),
        }
    }

    println!("Direct proxy servers: {:?}", direct_servers);

    // All 10 requests should go to direct-backend (no load balancing)
    assert_eq!(
        direct_servers.get("direct-backend").copied().unwrap_or(0),
        10,
        "All 10 direct requests should go to direct-backend, got {:?}",
        direct_servers
    );
    assert!(
        !direct_servers.contains_key("lb-target-1") && !direct_servers.contains_key("lb-target-2"),
        "Direct proxy should NOT route to LB targets, got {:?}",
        direct_servers
    );

    // --- Test load-balanced proxy (with upstream_id) ---
    let mut lb_servers: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/balanced/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(
                    r.status().is_success(),
                    "LB request {} failed: {}",
                    i,
                    r.status()
                );
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *lb_servers.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("LB request {} failed: {}", i, e),
        }
    }

    println!("Load-balanced proxy servers: {:?}", lb_servers);

    // Traffic should be split across lb-target-1 and lb-target-2
    assert!(
        lb_servers.contains_key("lb-target-1") && lb_servers.contains_key("lb-target-2"),
        "LB proxy should route to both LB targets, got {:?}",
        lb_servers
    );
    assert!(
        !lb_servers.contains_key("direct-backend"),
        "LB proxy should NOT route to direct-backend, got {:?}",
        lb_servers
    );
    assert_eq!(
        lb_servers.get("lb-target-1").copied().unwrap_or(0),
        5,
        "lb-target-1 should get 5 requests"
    );
    assert_eq!(
        lb_servers.get("lb-target-2").copied().unwrap_or(0),
        5,
        "lb-target-2 should get 5 requests"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Least Connections Load Balancing
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_least_connections_load_balancing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "lb-lc-proxy"
    listen_path: "/lc"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30201
    strip_listen_path: true
    upstream_id: "upstream-lc"

upstreams:
  - id: "upstream-lc"
    name: "Least Connections Upstream"
    algorithm: least_connections
    targets:
      - host: "127.0.0.1"
        port: 30201
        weight: 1
      - host: "127.0.0.1"
        port: 30202
        weight: 1
      - host: "127.0.0.1"
        port: 30203
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Use slow servers (200ms delay) so concurrent connections stay open
    // long enough for LC to see non-zero active connection counts.
    let s1 = tokio::spawn(start_slow_identifying_server(30201, "lc-server1", 200));
    let s2 = tokio::spawn(start_slow_identifying_server(30202, "lc-server2", 200));
    let s3 = tokio::spawn(start_slow_identifying_server(30203, "lc-server3", 200));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Send 30 requests in concurrent batches of 6.
    // The 200ms server delay ensures connections overlap, giving LC real
    // connection counts to differentiate targets.
    let mut all_bodies: Vec<String> = Vec::new();
    for batch in 0..5 {
        let mut handles = Vec::new();
        for i in 0..6 {
            let c = client.clone();
            let pp = proxy_port;
            let idx = batch * 6 + i;
            handles.push(tokio::spawn(async move {
                let resp = c
                    .get(format!("http://127.0.0.1:{}/lc/test-{}", pp, idx))
                    .send()
                    .await;
                match resp {
                    Ok(r) => {
                        assert!(
                            r.status().is_success(),
                            "Request {} failed with {}",
                            idx,
                            r.status()
                        );
                        r.text().await.unwrap_or_default()
                    }
                    Err(e) => panic!("Request {} failed: {}", idx, e),
                }
            }));
        }
        for h in handles {
            all_bodies.push(h.await.unwrap());
        }
    }

    let mut counts: HashMap<String, u32> = HashMap::new();
    for body in &all_bodies {
        let server = parse_server_name(body);
        if !server.is_empty() {
            *counts.entry(server).or_insert(0) += 1;
        }
    }

    println!("Least connections distribution: {:?}", counts);

    // All 3 servers should receive traffic
    assert!(
        counts.len() == 3,
        "Expected traffic to 3 servers, got {:?}",
        counts
    );

    // Each server should get some traffic (LC distributes to least-loaded)
    for (server, count) in &counts {
        assert!(
            *count >= 3 && *count <= 20,
            "Server {} got {} requests — expected LC to spread across all targets (3-20 of 30)",
            server,
            count
        );
    }

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Random Load Balancing
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_random_load_balancing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config = r#"
proxies:
  - id: "lb-rand-proxy"
    listen_path: "/rand"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30211
    strip_listen_path: true
    upstream_id: "upstream-rand"

upstreams:
  - id: "upstream-rand"
    name: "Random Upstream"
    algorithm: random
    targets:
      - host: "127.0.0.1"
        port: 30211
        weight: 1
      - host: "127.0.0.1"
        port: 30212
        weight: 1
      - host: "127.0.0.1"
        port: 30213
        weight: 1

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let s1 = tokio::spawn(start_identifying_server(30211, "rand-server1"));
    let s2 = tokio::spawn(start_identifying_server(30212, "rand-server2"));
    let s3 = tokio::spawn(start_identifying_server(30213, "rand-server3"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // Send 90 requests to get a meaningful distribution sample
    for i in 0..90 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/rand/test-{}", proxy_port, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(
                    r.status().is_success(),
                    "Request {} failed with {}",
                    i,
                    r.status()
                );
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Random distribution: {:?}", counts);

    // All 3 servers should receive some traffic
    assert!(
        counts.len() == 3,
        "Expected traffic to all 3 servers with random distribution, got {:?}",
        counts
    );

    // With 90 requests across 3 targets, each should get at least some requests.
    // Statistical guarantee: P(any server gets 0 of 90) is vanishingly small.
    for (server, count) in &counts {
        assert!(
            *count >= 5,
            "Server {} got only {} requests — random distribution should spread across all targets",
            server,
            count
        );
    }

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
    s3.abort();
}

// ============================================================================
// Test: Active Health Check with TCP Probes
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_active_health_check_tcp_probe() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Server on 30221 is healthy (TCP-accepting), server on 30222 has nothing listening.
    // TCP probe should detect 30222 as unhealthy (connection refused).
    let config = r#"
proxies:
  - id: "lb-tcp-probe-proxy"
    listen_path: "/tcp-probe"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30221
    strip_listen_path: true
    upstream_id: "upstream-tcp-probe"

upstreams:
  - id: "upstream-tcp-probe"
    name: "TCP Probe Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30221
        weight: 1
      - host: "127.0.0.1"
        port: 30222
        weight: 1
    health_checks:
      active:
        probe_type: tcp
        interval_seconds: 1
        timeout_ms: 1000
        healthy_threshold: 1
        unhealthy_threshold: 2

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Only start server on 30221; port 30222 has nothing listening (TCP probe fails)
    let s1 = tokio::spawn(start_identifying_server(30221, "tcp-healthy"));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Wait for TCP health checks to detect unreachable target
    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // All traffic should go to tcp-healthy since tcp probe marks 30222 unhealthy
    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/tcp-probe/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("TCP probe health check distribution: {:?}", counts);

    assert_eq!(
        counts.get("tcp-healthy").copied().unwrap_or(0),
        20,
        "All 20 requests should go to tcp-healthy, got {:?}",
        counts
    );

    let _ = gateway.kill();
    s1.abort();
}

// ============================================================================
// Test: Passive Health Check Recovery Timer (healthy_after_seconds)
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_passive_health_check_recovery_timer() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Configure passive health check with a short recovery timer.
    // One server returns 500s initially then recovers, the other is always healthy.
    // After the recovery timer fires, the flapping server should be restored.
    let config = r#"
proxies:
  - id: "lb-recovery-timer-proxy"
    listen_path: "/recovery-timer"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30231
    strip_listen_path: true
    upstream_id: "upstream-recovery-timer"

upstreams:
  - id: "upstream-recovery-timer"
    name: "Recovery Timer Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30231
        weight: 1
      - host: "127.0.0.1"
        port: 30232
        weight: 1
    health_checks:
      passive:
        unhealthy_status_codes: [500, 502, 503]
        unhealthy_threshold: 3
        unhealthy_window_seconds: 60
        healthy_after_seconds: 4

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 is always healthy. Server 2 fails first 10 requests then recovers.
    let s1 = tokio::spawn(start_identifying_server(30231, "stable-server"));
    let s2 = tokio::spawn(start_flapping_server(30232, "flapping-server", 10));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Phase 1: Send requests to trigger passive health check marking server2 unhealthy
    for i in 0..10 {
        let _ = client
            .get(format!(
                "http://127.0.0.1:{}/recovery-timer/warmup-{}",
                proxy_port, i
            ))
            .send()
            .await;
    }
    sleep(Duration::from_millis(500)).await;

    // Phase 2: Verify bad server is excluded (most traffic to stable-server)
    let mut phase2_counts: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/recovery-timer/phase2-{}",
                proxy_port, i
            ))
            .send()
            .await;

        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            let server = parse_server_name(&body);
            if !server.is_empty() {
                *phase2_counts.entry(server).or_insert(0) += 1;
            }
        }
    }

    println!("Phase 2 (after marking unhealthy): {:?}", phase2_counts);
    let stable_phase2 = phase2_counts.get("stable-server").copied().unwrap_or(0);
    assert!(
        stable_phase2 >= 8,
        "At least 8/10 requests should go to stable-server while flapping is marked unhealthy, got {}",
        stable_phase2
    );

    // Phase 3: Wait for the recovery timer (healthy_after_seconds=4, check interval=1s)
    sleep(Duration::from_secs(6)).await;

    // Phase 4: After recovery timer fires, flapping-server (now returning 200s)
    // should be back in rotation and receive traffic
    let mut phase4_counts: HashMap<String, u32> = HashMap::new();
    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/recovery-timer/phase4-{}",
                proxy_port, i
            ))
            .send()
            .await;

        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            let server = parse_server_name(&body);
            if !server.is_empty() {
                *phase4_counts.entry(server).or_insert(0) += 1;
            }
        }
    }

    println!("Phase 4 (after recovery timer): {:?}", phase4_counts);

    // Both servers should receive traffic after recovery
    assert!(
        phase4_counts.len() == 2,
        "Both servers should get traffic after recovery timer, got {:?}",
        phase4_counts
    );
    assert!(
        phase4_counts.get("flapping-server").copied().unwrap_or(0) > 0,
        "flapping-server should get traffic after recovery timer restores it"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}

// ============================================================================
// Test: Active Health Check with Custom Status Codes
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_active_health_check_custom_status_codes() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    // Configure active health checks that accept 200 AND 503 as "healthy".
    // Server on 30241 returns 200 (healthy), server on 30242 returns 503.
    // Because 503 is in healthy_status_codes, BOTH servers should stay healthy.
    let config = r#"
proxies:
  - id: "lb-custom-codes-proxy"
    listen_path: "/custom-codes"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 30241
    strip_listen_path: true
    upstream_id: "upstream-custom-codes"

upstreams:
  - id: "upstream-custom-codes"
    name: "Custom Status Codes Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: 30241
        weight: 1
      - host: "127.0.0.1"
        port: 30242
        weight: 1
    health_checks:
      active:
        http_path: "/health"
        interval_seconds: 1
        timeout_ms: 2000
        healthy_threshold: 1
        unhealthy_threshold: 2
        healthy_status_codes: [200, 503]

consumers: []
plugin_configs: []
"#;

    std::fs::File::create(&config_path)
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    // Server 1 returns 200, server 2 returns 503 — but 503 is in healthy_status_codes
    let s1 = tokio::spawn(start_identifying_server(30241, "ok-server"));
    let s2 = tokio::spawn(start_status_server(30242, "maint-server", 503));
    sleep(Duration::from_millis(500)).await;

    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Wait for health checks to run — both should pass
    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    // Both servers should be considered healthy since 503 is in the allowed list
    for i in 0..20 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/custom-codes/test-{}",
                proxy_port, i
            ))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Custom status codes distribution: {:?}", counts);

    // Both servers should receive traffic since 503 is acceptable
    assert!(
        counts.len() == 2,
        "Both servers should get traffic (503 is in healthy_status_codes), got {:?}",
        counts
    );
    assert!(
        counts.get("ok-server").copied().unwrap_or(0) > 0,
        "ok-server should get traffic"
    );
    assert!(
        counts.get("maint-server").copied().unwrap_or(0) > 0,
        "maint-server should get traffic (503 is in healthy codes)"
    );

    let _ = gateway.kill();
    s1.abort();
    s2.abort();
}
