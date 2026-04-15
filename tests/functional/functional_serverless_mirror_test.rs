//! Functional Tests for Serverless Function and Request Mirror Plugins (E2E)
//!
//! Tests:
//! - Serverless function plugin in "terminate" mode (bypasses backend, returns function response)
//! - Request mirror plugin (fire-and-forget copy to a secondary destination)
//!
//! All tests use file mode with ephemeral ports and mock HTTP servers.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_serverless_mirror

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

/// Start a simple HTTP backend that returns a distinctive JSON body.
async fn start_backend_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind backend server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"source":"backend"}"#;
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

/// Start a mock serverless function endpoint that returns a custom response.
async fn start_function_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind function server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"source":"serverless-function","message":"hello from function"}"#;
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

/// Start a mock mirror server that sets a flag when it receives a request.
async fn start_mirror_server(port: u16, called: Arc<AtomicBool>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind mirror server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let called = called.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                // Mark that the mirror received a request
                called.store(true, Ordering::SeqCst);

                let body = r#"{"source":"mirror"}"#;
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

// ============================================================================
// Gateway Helpers
// ============================================================================

/// Detect the gateway binary path (debug preferred, fallback to release).
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
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

/// Test serverless_function plugin in terminate mode.
///
/// The gateway should call the mock function URL and return its response
/// directly to the client, bypassing the backend entirely.
#[ignore]
#[tokio::test]
async fn test_serverless_function_terminate_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let function_port = ephemeral_port().await;

    let config_content = format!(
        r#"
proxies:
  - id: "serverless-proxy"
    listen_path: "/fn"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "serverless-1"

consumers: []

plugin_configs:
  - id: "serverless-1"
    proxy_id: "serverless-proxy"
    plugin_name: "serverless_function"
    scope: "proxy"
    enabled: true
    config:
      provider: "gcp_cloud_functions"
      mode: "terminate"
      function_url: "http://127.0.0.1:{function_port}/function"
      timeout_ms: 5000

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    // Start both backend and function servers
    let _backend = tokio::spawn(start_backend_server(backend_port));
    let _function = tokio::spawn(start_function_server(function_port));
    sleep(Duration::from_millis(300)).await;

    // Start gateway with retry
    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send request through the gateway
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/fn/test", proxy_port))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Expected 200 from serverless function, got {}",
        resp.status()
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("serverless-function"),
        "Response should come from the serverless function, not the backend. Got: {}",
        body
    );
    assert!(
        !body.contains(r#""source":"backend"#),
        "Response should NOT come from the backend. Got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

/// Test request_mirror plugin sends a copy of the request to the mirror server.
///
/// The primary backend should respond normally, and the mirror server should
/// also receive the request (verified via a shared AtomicBool flag).
#[ignore]
#[tokio::test]
async fn test_request_mirror_sends_copy() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let mirror_port = ephemeral_port().await;

    let config_content = format!(
        r#"
proxies:
  - id: "mirror-proxy"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "mirror-1"

consumers: []

plugin_configs:
  - id: "mirror-1"
    proxy_id: "mirror-proxy"
    plugin_name: "request_mirror"
    scope: "proxy"
    enabled: true
    config:
      mirror_host: "127.0.0.1"
      mirror_port: {mirror_port}
      mirror_protocol: "http"
      percentage: 100.0

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    // Shared flag to verify the mirror received the request
    let mirror_called = Arc::new(AtomicBool::new(false));

    // Start backend and mirror servers
    let _backend = tokio::spawn(start_backend_server(backend_port));
    let _mirror = tokio::spawn(start_mirror_server(mirror_port, mirror_called.clone()));
    sleep(Duration::from_millis(300)).await;

    // Start gateway with retry
    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send request through the gateway
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/test", proxy_port))
        .send()
        .await
        .expect("Request failed");

    // Primary backend should respond normally
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Expected 200 from primary backend, got {}",
        resp.status()
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("backend"),
        "Response should come from the primary backend. Got: {}",
        body
    );

    // Give the fire-and-forget mirror request time to complete
    sleep(Duration::from_millis(500)).await;

    // Verify the mirror server received the request
    assert!(
        mirror_called.load(Ordering::SeqCst),
        "Mirror server should have received a copy of the request"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}
