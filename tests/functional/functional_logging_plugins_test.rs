//! Functional Tests for TCP and UDP Logging Plugins (E2E)
//!
//! Tests:
//! - tcp_logging plugin sends transaction logs to a TCP endpoint
//! - udp_logging plugin sends transaction logs as UDP datagrams
//!
//! All tests use file mode with ephemeral ports and mock log receivers.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_logging_plugins

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Mock Server Helpers
// ============================================================================

/// Start a simple HTTP echo backend that returns a JSON response.
async fn start_echo_backend(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind echo backend");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"status":"ok","echo":true}"#;
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

/// Start a TCP log receiver that sets a flag when it receives data.
async fn start_tcp_log_receiver(port: u16, received: Arc<AtomicBool>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind TCP log receiver");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            received.store(true, Ordering::SeqCst);
            // Just drain the data
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
        }
    });
}

/// Start a UDP log receiver that sets a flag when it receives data.
async fn start_udp_log_receiver(port: u16, received: Arc<AtomicBool>) {
    let socket = tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind UDP log receiver");

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, _)) if n > 0 => {
                    received.store(true, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    });
}

// ============================================================================
// Gateway Helpers
// ============================================================================

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
/// Returns true if healthy, false if timed out.
async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);

    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Allocate an ephemeral port by binding to port 0 and returning the assigned port.
async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Allocate an ephemeral UDP port by binding to port 0 and returning the assigned port.
async fn ephemeral_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    port
}

/// Start the gateway with retry logic for port allocation races.
/// Allocates fresh gateway/admin ports each attempt.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway(config_path, proxy_port, admin_port);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// Functional Tests
// ============================================================================

/// Test that the tcp_logging plugin sends transaction logs to a TCP endpoint.
///
/// 1. Start a mock TCP log receiver
/// 2. Start a backend echo server
/// 3. Start gateway in file mode with tcp_logging plugin
/// 4. Send an HTTP request through the gateway
/// 5. Wait for async log delivery
/// 6. Verify the TCP log receiver got data
#[ignore]
#[tokio::test]
async fn test_tcp_logging_sends_to_endpoint() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let tcp_log_port = ephemeral_port().await;

    // Write config with tcp_logging plugin
    let config_content = format!(
        r#"
proxies:
  - id: "tcp-log-proxy"
    listen_path: "/tcp-log-test"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "tcp-log-plugin-1"

consumers: []

plugin_configs:
  - id: "tcp-log-plugin-1"
    proxy_id: "tcp-log-proxy"
    plugin_name: "tcp_logging"
    scope: "proxy"
    enabled: true
    config:
      host: "127.0.0.1"
      port: {tcp_log_port}
      tls: false
      batch_size: 1
      flush_interval_ms: 500

upstreams: []
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start TCP log receiver
    let tcp_received = Arc::new(AtomicBool::new(false));
    start_tcp_log_receiver(tcp_log_port, tcp_received.clone()).await;

    // Start backend
    tokio::spawn(start_echo_backend(backend_port));

    // Allow servers to bind
    sleep(Duration::from_millis(500)).await;

    // Start gateway with retry
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a request through the gateway
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/tcp-log-test/hello",
            proxy_port
        ))
        .header("User-Agent", "tcp-logging-test/1.0")
        .send()
        .await
        .expect("Proxy request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Request through gateway should succeed"
    );

    // Wait for async log delivery (tcp_logging batches and flushes asynchronously)
    sleep(Duration::from_secs(2)).await;

    // Verify the TCP log receiver got data
    assert!(
        tcp_received.load(Ordering::SeqCst),
        "TCP log receiver should have received transaction log data"
    );

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Test that the udp_logging plugin sends transaction logs as UDP datagrams.
///
/// 1. Start a mock UDP log receiver
/// 2. Start a backend echo server
/// 3. Start gateway in file mode with udp_logging plugin
/// 4. Send an HTTP request through the gateway
/// 5. Wait for async log delivery
/// 6. Verify the UDP log receiver got data
#[ignore]
#[tokio::test]
async fn test_udp_logging_sends_to_endpoint() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let udp_log_port = ephemeral_udp_port().await;

    // Write config with udp_logging plugin
    let config_content = format!(
        r#"
proxies:
  - id: "udp-log-proxy"
    listen_path: "/udp-log-test"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "udp-log-plugin-1"

consumers: []

plugin_configs:
  - id: "udp-log-plugin-1"
    proxy_id: "udp-log-proxy"
    plugin_name: "udp_logging"
    scope: "proxy"
    enabled: true
    config:
      host: "127.0.0.1"
      port: {udp_log_port}
      batch_size: 1
      flush_interval_ms: 500

upstreams: []
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start UDP log receiver
    let udp_received = Arc::new(AtomicBool::new(false));
    start_udp_log_receiver(udp_log_port, udp_received.clone()).await;

    // Start backend
    tokio::spawn(start_echo_backend(backend_port));

    // Allow servers to bind
    sleep(Duration::from_millis(500)).await;

    // Start gateway with retry
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a request through the gateway
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/udp-log-test/hello",
            proxy_port
        ))
        .header("User-Agent", "udp-logging-test/1.0")
        .send()
        .await
        .expect("Proxy request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Request through gateway should succeed"
    );

    // Wait for async log delivery (udp_logging batches and flushes asynchronously)
    sleep(Duration::from_secs(2)).await;

    // Verify the UDP log receiver got data
    assert!(
        udp_received.load(Ordering::SeqCst),
        "UDP log receiver should have received transaction log data"
    );

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
}
