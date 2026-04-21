//! Functional tests for OTel Tracing and LDAP Auth plugins.
//!
//! - **OTel Tracing**: Verifies the plugin injects a `traceparent` response header
//!   (W3C Trace Context) when configured in propagation-only mode.
//! - **LDAP Auth**: Verifies the plugin rejects requests when the configured LDAP
//!   server is unreachable (no silent bypass of authentication).
//!
//! Both tests use file mode with ephemeral ports.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_otel_ldap

use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Echo Server Helper
// ============================================================================

/// Start a simple HTTP echo server on a pre-bound listener that returns 200 with a JSON body.
async fn start_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
fn start_gateway(
    config_path: &str,
    proxy_port: u16,
    admin_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let binary_path = gateway_binary_path();

    let child = std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    Ok(child)
}

/// Wait for the gateway health endpoint to respond.
async fn wait_for_health(admin_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = std::time::SystemTime::now() + Duration::from_secs(30);
    loop {
        if std::time::SystemTime::now() >= deadline {
            return Err("Gateway did not start within 30 seconds".into());
        }
        match reqwest::get(&health_url).await {
            Ok(r) if r.status().is_success() => return Ok(()),
            _ => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Start the gateway with retry logic to handle ephemeral port races.
/// Returns (gateway_process, echo_handle, proxy_port, admin_port, _temp_dir, _backend_listener).
async fn start_otel_gateway_with_retry(
    config_template: &str,
) -> (
    std::process::Child,
    tokio::task::JoinHandle<()>,
    u16,
    u16,
    TempDir,
    // Keep the backend listener alive indirectly via the spawned task
) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        // Allocate fresh ports each attempt
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().unwrap().port();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind admin");
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join("config.yaml");
        let config_content = config_template.replace("{backend_port}", &backend_port.to_string());
        std::fs::write(&config_path, config_content.as_bytes())
            .expect("Failed to write config file");

        // Start echo backend on the pre-bound listener (no port race)
        let echo_handle = tokio::spawn(start_echo_server_on(backend_listener));
        sleep(Duration::from_millis(200)).await;

        // Start gateway
        let mut gateway_process =
            match start_gateway(&config_path.to_string_lossy(), proxy_port, admin_port) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "Gateway spawn attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, e
                    );
                    echo_handle.abort();
                    if attempt < MAX_ATTEMPTS {
                        sleep(Duration::from_secs(1)).await;
                    }
                    continue;
                }
            };

        match wait_for_health(admin_port).await {
            Ok(()) => {
                return (
                    gateway_process,
                    echo_handle,
                    proxy_port,
                    admin_port,
                    temp_dir,
                );
            }
            Err(e) => {
                eprintln!(
                    "Gateway startup attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                let _ = gateway_process.kill();
                let _ = gateway_process.wait();
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// OTel Tracing Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_otel_tracing_injects_traceparent() {
    let config_template = r#"
proxies:
  - id: "traced-proxy"
    listen_path: "/traced"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "otel-1"

consumers: []

plugin_configs:
  - id: "otel-1"
    proxy_id: "traced-proxy"
    plugin_name: "otel_tracing"
    scope: "proxy"
    enabled: true
    config:
      service_name: "test-gateway"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_otel_gateway_with_retry(config_template).await;

    // Send a request without a traceparent header — the plugin should generate one
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/traced/test", proxy_port))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        200,
        "Expected 200, got {}",
        response.status()
    );

    // The OTel plugin echoes traceparent back in the response headers
    let traceparent = response
        .headers()
        .get("traceparent")
        .expect("Response should contain traceparent header")
        .to_str()
        .expect("traceparent should be valid UTF-8");

    // W3C Trace Context format: version-trace_id-parent_id-flags
    // e.g. "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(
        parts.len(),
        4,
        "traceparent should have 4 dash-separated parts, got: {}",
        traceparent
    );
    assert_eq!(parts[0], "00", "traceparent version should be '00'");
    assert_eq!(
        parts[1].len(),
        32,
        "trace_id should be 32 hex chars, got {} chars: {}",
        parts[1].len(),
        parts[1]
    );
    assert_eq!(
        parts[2].len(),
        16,
        "span_id should be 16 hex chars, got {} chars: {}",
        parts[2].len(),
        parts[2]
    );
    assert_eq!(parts[3], "01", "traceparent flags should be '01'");

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_handle.abort();
}

#[ignore]
#[tokio::test]
async fn test_otel_tracing_preserves_existing_traceparent() {
    let config_template = r#"
proxies:
  - id: "traced-proxy"
    listen_path: "/traced"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "otel-1"

consumers: []

plugin_configs:
  - id: "otel-1"
    proxy_id: "traced-proxy"
    plugin_name: "otel_tracing"
    scope: "proxy"
    enabled: true
    config:
      service_name: "test-gateway"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_otel_gateway_with_retry(config_template).await;

    // Send a request WITH an existing traceparent — the plugin should preserve the trace_id
    let existing_traceparent = "00-abcdef1234567890abcdef1234567890-1234567890abcdef-01";
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/traced/test", proxy_port))
        .header("traceparent", existing_traceparent)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        response.status().as_u16(),
        200,
        "Expected 200, got {}",
        response.status()
    );

    let traceparent = response
        .headers()
        .get("traceparent")
        .expect("Response should contain traceparent header")
        .to_str()
        .expect("traceparent should be valid UTF-8");

    // The trace_id should be preserved from the incoming traceparent
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(parts.len(), 4, "traceparent should have 4 parts");
    assert_eq!(
        parts[1], "abcdef1234567890abcdef1234567890",
        "trace_id should be preserved from the incoming traceparent"
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_handle.abort();
}

// ============================================================================
// LDAP Auth Tests
// ============================================================================

/// Start the gateway with retry logic for LDAP tests (echo backend + unreachable LDAP port).
async fn start_ldap_gateway_with_retry(
    config_template: &str,
) -> (
    std::process::Child,
    tokio::task::JoinHandle<()>,
    u16,
    u16,
    TempDir,
) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().unwrap().port();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind admin");
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        // Use a port that we do NOT listen on — guaranteeing LDAP connection failure
        let ldap_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ldap");
        let ldap_port = ldap_listener.local_addr().unwrap().port();
        drop(ldap_listener);

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join("config.yaml");
        let config_content = config_template
            .replace("{backend_port}", &backend_port.to_string())
            .replace("{ldap_port}", &ldap_port.to_string());
        std::fs::write(&config_path, config_content.as_bytes())
            .expect("Failed to write config file");

        let echo_handle = tokio::spawn(start_echo_server_on(backend_listener));
        sleep(Duration::from_millis(200)).await;

        let mut gateway_process =
            match start_gateway(&config_path.to_string_lossy(), proxy_port, admin_port) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "Gateway spawn attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, e
                    );
                    echo_handle.abort();
                    if attempt < MAX_ATTEMPTS {
                        sleep(Duration::from_secs(1)).await;
                    }
                    continue;
                }
            };

        match wait_for_health(admin_port).await {
            Ok(()) => {
                return (
                    gateway_process,
                    echo_handle,
                    proxy_port,
                    admin_port,
                    temp_dir,
                );
            }
            Err(e) => {
                eprintln!(
                    "Gateway startup attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                let _ = gateway_process.kill();
                let _ = gateway_process.wait();
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

#[ignore]
#[tokio::test]
async fn test_ldap_auth_rejects_when_server_unreachable() {
    let config_template = r#"
proxies:
  - id: "auth-proxy"
    listen_path: "/secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ldap-1"

consumers: []

plugin_configs:
  - id: "ldap-1"
    proxy_id: "auth-proxy"
    plugin_name: "ldap_auth"
    scope: "proxy"
    enabled: true
    config:
      ldap_url: "ldap://127.0.0.1:{ldap_port}"
      bind_dn_template: "uid={{username}},ou=users,dc=example,dc=com"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_ldap_gateway_with_retry(config_template).await;

    // Send a request with Basic auth credentials — LDAP server is unreachable so auth must fail
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/secure/resource", proxy_port))
        .basic_auth("testuser", Some("testpassword"))
        .send()
        .await
        .expect("Request failed");

    // The LDAP plugin should reject with 401 (LDAP authentication failed)
    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 when LDAP server is unreachable, got {}",
        response.status()
    );

    let body = response.text().await.unwrap_or_default();
    assert!(
        body.contains("LDAP authentication failed"),
        "Error body should contain 'LDAP authentication failed', got: {}",
        body
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_handle.abort();
}

#[ignore]
#[tokio::test]
async fn test_ldap_auth_rejects_missing_credentials() {
    let config_template = r#"
proxies:
  - id: "auth-proxy"
    listen_path: "/secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ldap-1"

consumers: []

plugin_configs:
  - id: "ldap-1"
    proxy_id: "auth-proxy"
    plugin_name: "ldap_auth"
    scope: "proxy"
    enabled: true
    config:
      ldap_url: "ldap://127.0.0.1:{ldap_port}"
      bind_dn_template: "uid={{username}},ou=users,dc=example,dc=com"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_ldap_gateway_with_retry(config_template).await;

    // Send a request WITHOUT any auth credentials
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/secure/resource", proxy_port))
        .send()
        .await
        .expect("Request failed");

    // The LDAP plugin should reject with 401 (no credentials provided)
    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 when no credentials are provided, got {}",
        response.status()
    );

    // Cleanup
    let _ = gateway_process.kill();
    let _ = gateway_process.wait();
    echo_handle.abort();
}
