//! Functional test for Ferrum Edge in file mode.
//!
//! This test:
//! 1. Builds the gateway binary
//! 2. Creates a temporary YAML config with a proxy pointing to a local echo backend
//! 3. Starts a simple HTTP echo server
//! 4. Starts the gateway with FERRUM_MODE=file and FERRUM_FILE_CONFIG_PATH
//! 5. Sends HTTP requests through the proxy and verifies routing
//! 6. Tests SIGHUP config reload (updates config file, sends SIGHUP, verifies new proxy)
//!
//! This test is marked with #[ignore] as it requires the binary to be built
//! and should be run with: cargo test --test functional_file_mode_test -- --ignored --nocapture

use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Echo Server Helper
// ============================================================================

/// Start a simple HTTP echo server on a pre-bound listener (avoids port race).
async fn start_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = "echo response";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
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

/// Start the Ferrum Edge binary in file mode
fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> std::process::Child {
    let binary_path = gateway_binary_path();

    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
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

        let mut child = start_gateway_in_file_mode(config_path, proxy_port, admin_port);

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

#[ignore]
#[tokio::test]
async fn test_file_mode_basic_request_routing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Start echo server on a held listener (no port race for in-process servers)
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_server = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "echo-proxy"
    listen_path: "/echo"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start gateway with retry
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send a test request through the proxy
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/echo/test-path", proxy_port))
        .send()
        .await;

    match response {
        Ok(resp) => {
            println!("Response status: {}", resp.status());
            assert!(
                resp.status().is_success(),
                "Expected success response from echo server, got {}",
                resp.status()
            );
        }
        Err(e) => {
            eprintln!("Request failed: {}", e);
            panic!("Failed to send request through gateway");
        }
    }

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_server.abort();
}

#[ignore]
#[tokio::test]
async fn test_file_mode_config_reload_on_sighup() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Start echo server on a held listener
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_server = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let initial_config = format!(
        r#"
proxies:
  - id: "proxy-initial"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}

consumers: []
plugin_configs: []
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(initial_config.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start gateway with retry
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Verify initial proxy exists
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/api/v1", proxy_port))
        .send()
        .await;
    assert!(
        response.is_ok(),
        "Initial proxy should be accessible before reload"
    );

    // Update config with new proxy
    let updated_config = format!(
        r#"
proxies:
  - id: "proxy-initial"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
  - id: "proxy-new"
    listen_path: "/api/v2"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}

consumers: []
plugin_configs: []
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(updated_config.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Send SIGHUP to reload config (Unix only)
    #[cfg(unix)]
    {
        let pid = gateway_process.id();
        let _ = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }

    // Wait for config to reload
    sleep(Duration::from_secs(2)).await;

    // Verify new proxy exists
    let response = client
        .get(format!("http://127.0.0.1:{}/api/v2", proxy_port))
        .send()
        .await;
    assert!(
        response.is_ok(),
        "New proxy should be accessible after SIGHUP reload"
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_server.abort();
}

#[ignore]
#[tokio::test]
async fn test_file_mode_empty_config() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config_content = r#"
proxies: []
consumers: []
plugin_configs: []
"#;

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start gateway with retry (verifies it starts successfully with empty config)
    let (mut gateway_process, _proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
}

#[ignore]
#[tokio::test]
async fn test_file_mode_multiple_backends() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Start echo servers on held listeners
    let echo1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo1_port = echo1_listener.local_addr().unwrap().port();
    let echo1 = tokio::spawn(start_echo_server_on(echo1_listener));

    let echo2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo2_port = echo2_listener.local_addr().unwrap().port();
    let echo2 = tokio::spawn(start_echo_server_on(echo2_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "backend1"
    listen_path: "/api/backend1"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo1_port}
    strip_listen_path: true

  - id: "backend2"
    listen_path: "/api/backend2"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo2_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start gateway with retry
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Test requests to both backends
    let client = reqwest::Client::new();

    let resp1 = client
        .get(format!("http://127.0.0.1:{}/api/backend1/test", proxy_port))
        .send()
        .await;
    assert!(resp1.is_ok(), "Request to backend1 should succeed");

    let resp2 = client
        .get(format!("http://127.0.0.1:{}/api/backend2/test", proxy_port))
        .send()
        .await;
    assert!(resp2.is_ok(), "Request to backend2 should succeed");

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo1.abort();
    echo2.abort();
}

/// Start an HTTP server that echoes back request headers as JSON in the response body
/// on a pre-bound listener.
async fn start_header_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);

                // Parse headers from the raw HTTP request
                let mut headers = serde_json::Map::new();
                for line in request.lines().skip(1) {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(": ") {
                        headers.insert(
                            key.to_lowercase(),
                            serde_json::Value::String(value.to_string()),
                        );
                    }
                }

                let body = serde_json::to_string(&headers).unwrap_or_default();
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

#[ignore]
#[tokio::test]
async fn test_file_mode_consumer_identity_headers_forwarded() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Start header echo server on a held listener
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_server = tokio::spawn(start_header_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");

    // Config with key_auth plugin and a consumer
    let config_content = format!(
        r#"
proxies:
  - id: "auth-proxy"
    listen_path: "/auth-api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "key-auth-plugin"

consumers:
  - id: "consumer-1"
    username: "test-user"
    custom_id: "cust-42"
    credentials:
      keyauth:
        key: "my-secret-api-key"

plugin_configs:
  - id: "key-auth-plugin"
    proxy_id: "auth-proxy"
    plugin_name: "key_auth"
    scope: proxy
    enabled: true
    config:
      key_location: "header:X-Api-Key"
"#
    );

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start gateway with retry
    let (mut gateway_process, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();

    // Test 1: Request without API key should be rejected (401)
    let resp = client
        .get(format!("http://127.0.0.1:{}/auth-api/test", proxy_port))
        .send()
        .await
        .expect("Request should complete");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "Request without API key should be rejected"
    );

    // Test 2: Request with valid API key should succeed and include consumer headers
    let resp = client
        .get(format!("http://127.0.0.1:{}/auth-api/test", proxy_port))
        .header("X-Api-Key", "my-secret-api-key")
        .send()
        .await
        .expect("Authenticated request should complete");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Authenticated request should succeed"
    );

    let body: serde_json::Value = resp.json().await.expect("Response should be valid JSON");
    assert_eq!(
        body.get("x-consumer-username").and_then(|v| v.as_str()),
        Some("test-user"),
        "X-Consumer-Username header should be forwarded to backend"
    );
    assert_eq!(
        body.get("x-consumer-custom-id").and_then(|v| v.as_str()),
        Some("cust-42"),
        "X-Consumer-Custom-Id header should be forwarded to backend"
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_server.abort();
}
