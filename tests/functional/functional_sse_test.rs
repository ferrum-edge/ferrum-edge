//! Functional test for SSE (Server-Sent Events) plugin end-to-end.
//!
//! This test:
//! 1. Starts a simple HTTP echo backend
//! 2. Starts the gateway in file mode with the SSE plugin configured
//! 3. Verifies SSE plugin request validation and response header shaping
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_sse

use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Echo Server Helper
// ============================================================================

/// Start a simple HTTP echo server that returns SSE-style responses.
async fn start_sse_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind SSE echo server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = "data: hello\n\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Start the Ferrum Edge binary in file mode.
fn start_gateway_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let build_output = std::process::Command::new("cargo")
        .args(["build", "--bin", "ferrum-edge"])
        .output()?;

    if !build_output.status.success() {
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
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    Ok(child)
}

/// Wait for the gateway health endpoint to respond.
/// Returns true if healthy, false if timed out.
async fn wait_for_health(admin_port: u16) -> bool {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = std::time::SystemTime::now() + Duration::from_secs(30);
    loop {
        if std::time::SystemTime::now() >= deadline {
            return false;
        }
        match reqwest::get(&health_url).await {
            Ok(r) if r.status().is_success() => return true,
            _ => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Create a temp config file with the SSE plugin and return (TempDir, config_path, backend_port).
///
/// Backend port is allocated here (same-process listener, no race).
/// Proxy and admin ports are allocated by `start_gateway_with_retry()`.
async fn setup_sse_config() -> (TempDir, String, u16) {
    // Bind to port 0 to get an ephemeral port for the backend (same-process, safe)
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config_content = format!(
        r#"
proxies:
  - id: "sse-proxy"
    listen_path: "/sse"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "sse-1"

consumers: []

plugin_configs:
  - id: "sse-1"
    proxy_id: "sse-proxy"
    plugin_name: "sse"
    scope: "proxy"
    enabled: true
    config:
      require_accept_header: true
      require_get_method: true
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    (
        temp_dir,
        config_path.to_string_lossy().to_string(),
        backend_port,
    )
}

/// Start the gateway with retry on port-binding failures.
///
/// Allocates fresh ephemeral proxy and admin ports on each attempt to handle
/// the bind-drop-rebind port race. Returns (child, proxy_port, admin_port).
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let mut child = start_gateway_file_mode(config_path, proxy_port, admin_port)
            .expect("Failed to start gateway");

        if wait_for_health(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (ports: proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// Functional Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_sse_plugin_rejects_without_accept_header() {
    let (_temp_dir, config_path, backend_port) = setup_sse_config().await;

    // Start echo server
    let echo_server = tokio::spawn(start_sse_echo_server(backend_port));
    sleep(Duration::from_millis(500)).await;

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(&config_path).await;

    // Send request WITHOUT Accept: text/event-stream header
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/sse/events", proxy_port))
        .send()
        .await
        .expect("Request failed");

    // SSE plugin should reject with 406 Not Acceptable
    assert_eq!(
        response.status().as_u16(),
        406,
        "Expected 406 when Accept header is missing, got {}",
        response.status()
    );

    let body = response.text().await.unwrap_or_default();
    assert!(
        body.contains("text/event-stream"),
        "Error body should mention text/event-stream, got: {}",
        body
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_server.abort();
}

#[ignore]
#[tokio::test]
async fn test_sse_plugin_allows_valid_sse_request() {
    let (_temp_dir, config_path, backend_port) = setup_sse_config().await;

    // Start echo server
    let echo_server = tokio::spawn(start_sse_echo_server(backend_port));
    sleep(Duration::from_millis(500)).await;

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(&config_path).await;

    // Send valid SSE request with Accept: text/event-stream
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/sse/events", proxy_port))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        200,
        "Expected 200 for valid SSE request, got {}",
        response.status()
    );

    // Check SSE response headers set by the plugin
    let headers = response.headers();

    // X-Accel-Buffering: no should be added by the SSE plugin
    assert_eq!(
        headers
            .get("x-accel-buffering")
            .map(|v| v.to_str().unwrap_or("")),
        Some("no"),
        "SSE plugin should add X-Accel-Buffering: no"
    );

    // Content-Length should be stripped by the SSE plugin (streaming)
    assert!(
        headers.get("content-length").is_none(),
        "SSE plugin should strip Content-Length header"
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_server.abort();
}

#[ignore]
#[tokio::test]
async fn test_sse_plugin_rejects_post_when_require_get() {
    let (_temp_dir, config_path, backend_port) = setup_sse_config().await;

    // Start echo server
    let echo_server = tokio::spawn(start_sse_echo_server(backend_port));
    sleep(Duration::from_millis(500)).await;

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(&config_path).await;

    // Send POST request with proper Accept header - should still be rejected
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/sse/events", proxy_port))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .expect("Request failed");

    // SSE plugin should reject POST with 405 Method Not Allowed
    assert_eq!(
        response.status().as_u16(),
        405,
        "Expected 405 for POST with require_get_method=true, got {}",
        response.status()
    );

    let body = response.text().await.unwrap_or_default();
    assert!(
        body.contains("GET"),
        "Error body should mention GET method requirement, got: {}",
        body
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_server.abort();
}
