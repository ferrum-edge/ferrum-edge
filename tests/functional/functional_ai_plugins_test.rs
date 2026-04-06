//! Functional Tests for AI Plugins (E2E)
//!
//! Tests AI plugins (ai_prompt_shield, ai_request_guard) end-to-end through
//! the gateway in file mode. These plugins perform local validation without
//! calling external services.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_ai_plugins

use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Echo Server Helper
// ============================================================================

/// Start a simple HTTP echo server that reads the full request and echoes
/// back a JSON response with status 200.
async fn start_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind echo server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
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

// ============================================================================
// ai_prompt_shield tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_ai_prompt_shield_rejects_pii() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Bind echo server to an ephemeral port
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();
    drop(echo_listener);

    // Bind gateway ports
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    drop(admin_listener);

    let config_content = format!(
        r#"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []

plugin_configs:
  - id: "shield-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_prompt_shield"
    scope: "proxy"
    enabled: true
    config:
      action: "reject"
      patterns:
        - "ssn"
        - "credit_card"
        - "email"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let mut gw = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    wait_for_gateway(admin_port).await;

    // Send a request with an SSN in the message content
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "messages": [
                    {
                        "role": "user",
                        "content": "My SSN is 123-45-6789, can you help me?"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "Should reject request with PII"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("PII detected"),
        "Response should mention PII detection, got: {}",
        body
    );
    assert!(
        body.contains("ssn"),
        "Response should identify SSN pattern, got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

#[ignore]
#[tokio::test]
async fn test_ai_prompt_shield_allows_clean_request() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();
    drop(echo_listener);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    drop(admin_listener);

    let config_content = format!(
        r#"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []

plugin_configs:
  - id: "shield-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_prompt_shield"
    scope: "proxy"
    enabled: true
    config:
      action: "reject"
      patterns:
        - "ssn"
        - "credit_card"
        - "email"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let mut gw = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    wait_for_gateway(admin_port).await;

    // Send a clean request with no PII
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "messages": [
                    {
                        "role": "user",
                        "content": "What is the weather in Tokyo today?"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Clean request should pass through to backend"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

// ============================================================================
// ai_request_guard tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_ai_request_guard_rejects_disallowed_model() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();
    drop(echo_listener);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    drop(admin_listener);

    let config_content = format!(
        r#"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []

plugin_configs:
  - id: "guard-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_request_guard"
    scope: "proxy"
    enabled: true
    config:
      max_tokens_limit: 100
      enforce_max_tokens: "reject"
      allowed_models:
        - "gpt-4"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let mut gw = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    wait_for_gateway(admin_port).await;

    // Send a request with a disallowed model
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "model": "gpt-3.5-turbo",
                "max_tokens": 50,
                "messages": [
                    {
                        "role": "user",
                        "content": "Hello"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "Should reject disallowed model"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("not in the allowed models list"),
        "Response should indicate model is not allowed, got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

#[ignore]
#[tokio::test]
async fn test_ai_request_guard_rejects_excess_tokens() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();
    drop(echo_listener);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    drop(admin_listener);

    let config_content = format!(
        r#"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []

plugin_configs:
  - id: "guard-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_request_guard"
    scope: "proxy"
    enabled: true
    config:
      max_tokens_limit: 100
      enforce_max_tokens: "reject"
      allowed_models:
        - "gpt-4"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let mut gw = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    wait_for_gateway(admin_port).await;

    // Send a request with excessive max_tokens
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "model": "gpt-4",
                "max_tokens": 500,
                "messages": [
                    {
                        "role": "user",
                        "content": "Hello"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "Should reject excessive max_tokens"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("max_tokens exceeds limit"),
        "Response should indicate token limit exceeded, got: {}",
        body
    );
    assert!(
        body.contains("500") && body.contains("100"),
        "Response should show requested and max values, got: {}",
        body
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

#[ignore]
#[tokio::test]
async fn test_ai_request_guard_allows_valid_request() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = echo_listener.local_addr().unwrap().port();
    drop(echo_listener);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    drop(admin_listener);

    let config_content = format!(
        r#"
proxies:
  - id: "ai-proxy"
    listen_path: "/ai"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []

plugin_configs:
  - id: "guard-1"
    proxy_id: "ai-proxy"
    plugin_name: "ai_request_guard"
    scope: "proxy"
    enabled: true
    config:
      max_tokens_limit: 100
      enforce_max_tokens: "reject"
      allowed_models:
        - "gpt-4"

upstreams: []
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    let _echo = tokio::spawn(start_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let mut gw = start_gateway(config_path.to_str().unwrap(), proxy_port, admin_port);
    wait_for_gateway(admin_port).await;

    // Send a valid request: allowed model + tokens within limit
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/ai/chat", proxy_port))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "model": "gpt-4",
                "max_tokens": 50,
                "messages": [
                    {
                        "role": "user",
                        "content": "What is the capital of France?"
                    }
                ]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Valid request should pass through to backend"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}
