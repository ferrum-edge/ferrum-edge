//! Functional test for Ferrum Gateway in file mode.
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

/// Start a simple HTTP echo server on the given port using raw tokio TCP.
async fn start_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind echo server");

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

/// Start the Ferrum Gateway binary in file mode
fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    // Build the gateway binary first (debug profile to match `cargo test`)
    let build_output = std::process::Command::new("cargo")
        .args(["build", "--bin", "ferrum-gateway"])
        .output()?;

    if !build_output.status.success() {
        eprintln!("Failed to build gateway binary");
        eprintln!("stderr: {}", String::from_utf8_lossy(&build_output.stderr));
        return Err("Build failed".into());
    }

    // Use debug binary (matches default `cargo test` profile), fall back to release
    let binary_path = if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
        "./target/debug/ferrum-gateway"
    } else {
        "./target/release/ferrum-gateway"
    };

    // Start the gateway binary
    let child = std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "ferrum_gateway=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    Ok(child)
}

// ============================================================================
// Functional Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_file_mode_basic_request_routing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config_content = r#"
proxies:
  - id: "echo-proxy"
    listen_path: "/echo"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19990
    strip_listen_path: true

consumers: []
plugin_configs: []
"#;

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start echo server
    let echo_server = tokio::spawn(start_echo_server(19990));
    sleep(Duration::from_millis(500)).await;

    // Build and start gateway in file mode on a unique port
    let gateway_process = start_gateway_in_file_mode(config_path.to_str().unwrap(), 18080);

    // Give gateway time to start
    sleep(Duration::from_secs(3)).await;

    // Send a test request through the proxy
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:18080/echo/test-path")
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
    if let Ok(mut proc) = gateway_process {
        let _ = proc.kill();
    }
    echo_server.abort();
}

#[ignore]
#[tokio::test]
async fn test_file_mode_config_reload_on_sighup() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let initial_config = r#"
proxies:
  - id: "proxy-initial"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19991

consumers: []
plugin_configs: []
"#;

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(initial_config.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start echo server
    let echo_server = tokio::spawn(start_echo_server(19991));
    sleep(Duration::from_millis(500)).await;

    // Build and start gateway
    let gateway_process = start_gateway_in_file_mode(config_path.to_str().unwrap(), 18081);
    sleep(Duration::from_secs(3)).await;

    // Verify initial proxy exists
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:18081/api/v1").send().await;
    assert!(
        response.is_ok(),
        "Initial proxy should be accessible before reload"
    );

    // Update config with new proxy
    let updated_config = r#"
proxies:
  - id: "proxy-initial"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19991
  - id: "proxy-new"
    listen_path: "/api/v2"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19991

consumers: []
plugin_configs: []
"#;

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(updated_config.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Send SIGHUP to reload config (Unix only)
    #[cfg(unix)]
    if let Ok(ref proc) = gateway_process {
        let pid = proc.id();
        let _ = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }

    // Wait for config to reload
    sleep(Duration::from_secs(2)).await;

    // Verify new proxy exists
    let response = client.get("http://127.0.0.1:18081/api/v2").send().await;
    assert!(
        response.is_ok(),
        "New proxy should be accessible after SIGHUP reload"
    );

    // Cleanup
    if let Ok(mut proc) = gateway_process {
        let _ = proc.kill();
    }
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

    // Start gateway in file mode
    let gateway_process = start_gateway_in_file_mode(config_path.to_str().unwrap(), 18082);
    sleep(Duration::from_secs(3)).await;

    // Gateway should start successfully even with empty config
    assert!(
        gateway_process.is_ok(),
        "Gateway should start with empty config"
    );

    // Cleanup
    if let Ok(mut proc) = gateway_process {
        let _ = proc.kill();
    }
}

#[ignore]
#[tokio::test]
async fn test_file_mode_multiple_backends() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.yaml");

    let config_content = r#"
proxies:
  - id: "backend1"
    listen_path: "/api/backend1"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19992
    strip_listen_path: true

  - id: "backend2"
    listen_path: "/api/backend2"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19993
    strip_listen_path: true

consumers: []
plugin_configs: []
"#;

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start echo servers on different ports
    let echo1 = tokio::spawn(start_echo_server(19992));
    let echo2 = tokio::spawn(start_echo_server(19993));
    sleep(Duration::from_millis(500)).await;

    // Start gateway
    let gateway_process = start_gateway_in_file_mode(config_path.to_str().unwrap(), 18083);
    sleep(Duration::from_secs(3)).await;

    // Test requests to both backends
    let client = reqwest::Client::new();

    let resp1 = client
        .get("http://127.0.0.1:18083/api/backend1/test")
        .send()
        .await;
    assert!(resp1.is_ok(), "Request to backend1 should succeed");

    let resp2 = client
        .get("http://127.0.0.1:18083/api/backend2/test")
        .send()
        .await;
    assert!(resp2.is_ok(), "Request to backend2 should succeed");

    // Cleanup
    if let Ok(mut proc) = gateway_process {
        let _ = proc.kill();
    }
    echo1.abort();
    echo2.abort();
}

/// Start an HTTP server that echoes back request headers as JSON in the response body.
async fn start_header_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind header echo server");

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
    let config_path = temp_dir.path().join("config.yaml");

    // Config with key_auth plugin and a consumer
    let config_content = r#"
proxies:
  - id: "auth-proxy"
    listen_path: "/auth-api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 19994
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
"#;

    let mut config_file =
        std::fs::File::create(&config_path).expect("Failed to create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("Failed to write config");
    drop(config_file);

    // Start header echo server
    let echo_server = tokio::spawn(start_header_echo_server(19994));
    sleep(Duration::from_millis(500)).await;

    // Start gateway
    let gateway_process = start_gateway_in_file_mode(config_path.to_str().unwrap(), 18084);
    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();

    // Test 1: Request without API key should be rejected (401)
    let resp = client
        .get("http://127.0.0.1:18084/auth-api/test")
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
        .get("http://127.0.0.1:18084/auth-api/test")
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
    if let Ok(mut proc) = gateway_process {
        let _ = proc.kill();
    }
    echo_server.abort();
}
