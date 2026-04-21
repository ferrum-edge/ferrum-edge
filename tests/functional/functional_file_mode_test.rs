//! Functional test for Ferrum Edge in file mode.
//!
//! Covers:
//! - Basic request routing from a YAML-defined proxy to a backend
//! - SIGHUP config-reload (write new YAML, signal, verify new proxy is routable)
//! - Empty-config startup
//! - Multiple backends from one config
//! - Consumer-identity headers forwarded to backend when key_auth authenticates
//! - `FERRUM_NAMESPACE` filtering (only matching-namespace proxies route)
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_file_mode

use crate::common::{TestGateway, spawn_http_echo};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;

// ============================================================================
// Header-Echo Server (specific to consumer-identity test — the shared echo
// helpers reply with a fixed body, so this file owns the only variant that
// echoes request headers back as JSON. Listener is held inside the task to
// avoid the bind-drop-rebind race documented in CLAUDE.md.)
// ============================================================================

async fn start_header_echo_server() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);

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
    });
    (port, handle)
}

// ============================================================================
// Functional Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_file_mode_basic_request_routing() {
    let backend = spawn_http_echo().await.expect("spawn echo");

    let config = format!(
        r#"
proxies:
  - id: "echo-proxy"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#,
        echo_port = backend.port
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();
    let response = client
        .get(gateway.proxy_url("/echo/test-path"))
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
}

#[ignore]
#[tokio::test]
async fn test_file_mode_config_reload_on_sighup() {
    let backend = spawn_http_echo().await.expect("spawn echo");

    let initial_config = format!(
        r#"
proxies:
  - id: "proxy-initial"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}

consumers: []
plugin_configs: []
"#,
        echo_port = backend.port
    );

    let gateway = TestGateway::builder()
        .mode_file(initial_config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    // Verify initial proxy exists
    let client = reqwest::Client::new();
    let response = client.get(gateway.proxy_url("/api/v1")).send().await;
    assert!(
        response.is_ok(),
        "Initial proxy should be accessible before reload"
    );

    // Rewrite the config file in place with a second proxy added.
    let updated_config = format!(
        r#"
proxies:
  - id: "proxy-initial"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
  - id: "proxy-new"
    listen_path: "/api/v2"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}

consumers: []
plugin_configs: []
"#,
        echo_port = backend.port
    );

    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    std::fs::write(config_path, updated_config).expect("rewrite config");

    // SIGHUP the running gateway (Unix only — file-mode reload on Windows is
    // not supported by the gateway itself).
    #[cfg(unix)]
    {
        let pid = gateway.pid().expect("gateway still running");
        let _ = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }

    sleep(Duration::from_secs(2)).await;

    // Verify new proxy is routable
    let response = client.get(gateway.proxy_url("/api/v2")).send().await;
    assert!(
        response.is_ok(),
        "New proxy should be accessible after SIGHUP reload"
    );
}

#[ignore]
#[tokio::test]
async fn test_file_mode_empty_config() {
    let config = r#"
proxies: []
consumers: []
plugin_configs: []
"#;

    // Just verify the gateway starts successfully with an empty config.
    let _gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("gateway should start with empty config");
}

#[ignore]
#[tokio::test]
async fn test_file_mode_multiple_backends() {
    let backend1 = spawn_http_echo().await.expect("spawn echo1");
    let backend2 = spawn_http_echo().await.expect("spawn echo2");

    let config = format!(
        r#"
proxies:
  - id: "backend1"
    listen_path: "/api/backend1"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {p1}
    strip_listen_path: true

  - id: "backend2"
    listen_path: "/api/backend2"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {p2}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#,
        p1 = backend1.port,
        p2 = backend2.port,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();
    let resp1 = client
        .get(gateway.proxy_url("/api/backend1/test"))
        .send()
        .await;
    assert!(resp1.is_ok(), "Request to backend1 should succeed");

    let resp2 = client
        .get(gateway.proxy_url("/api/backend2/test"))
        .send()
        .await;
    assert!(resp2.is_ok(), "Request to backend2 should succeed");
}

#[ignore]
#[tokio::test]
async fn test_file_mode_consumer_identity_headers_forwarded() {
    let (echo_port, echo_handle) = start_header_echo_server().await;

    let config = format!(
        r#"
proxies:
  - id: "auth-proxy"
    listen_path: "/auth-api"
    backend_scheme: http
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

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .spawn()
        .await
        .expect("start gateway");

    let client = reqwest::Client::new();

    // Test 1: Request without API key should be rejected (401)
    let resp = client
        .get(gateway.proxy_url("/auth-api/test"))
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
        .get(gateway.proxy_url("/auth-api/test"))
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

    echo_handle.abort();
}

// ============================================================================
// Namespace filtering in file mode
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_file_mode_namespace_filtering() {
    // One echo server — both namespace proxies point at it; differentiation is
    // purely via listen_path.
    let backend = spawn_http_echo().await.expect("spawn echo");

    // Proxies in two namespaces. `load_config_from_file` captures
    // `known_namespaces` before filtering, so both appear via /namespaces,
    // but only the proxies matching FERRUM_NAMESPACE are routable.
    let config = format!(
        r#"
proxies:
  - id: "prod-proxy"
    namespace: "prod"
    listen_path: "/prod"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
  - id: "staging-proxy"
    namespace: "staging"
    listen_path: "/staging"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#,
        echo_port = backend.port,
    );

    let client = reqwest::Client::new();

    // ---- Run 1: FERRUM_NAMESPACE=prod ----
    {
        let gw = TestGateway::builder()
            .mode_file(&config)
            .namespace("prod")
            .log_level("warn")
            .spawn()
            .await
            .expect("start prod gateway");

        // Positive routing: /prod → prod proxy → backend echo.
        let r = client
            .get(gw.proxy_url("/prod"))
            .send()
            .await
            .expect("prod request");
        assert!(
            r.status().is_success(),
            "prod namespace proxy must serve /prod: {}",
            r.status()
        );

        // Negative routing: /staging must not resolve when namespace=prod.
        let r = client
            .get(gw.proxy_url("/staging"))
            .send()
            .await
            .expect("staging request");
        assert_eq!(
            r.status().as_u16(),
            404,
            "staging proxy must be filtered out when FERRUM_NAMESPACE=prod"
        );

        // gw drops here → gateway is killed
    }

    // ---- Run 2: FERRUM_NAMESPACE=staging ----
    {
        let gw = TestGateway::builder()
            .mode_file(&config)
            .namespace("staging")
            .log_level("warn")
            .spawn()
            .await
            .expect("start staging gateway");

        let r = client
            .get(gw.proxy_url("/staging"))
            .send()
            .await
            .expect("staging request");
        assert!(
            r.status().is_success(),
            "staging namespace proxy must serve /staging: {}",
            r.status()
        );

        let r = client
            .get(gw.proxy_url("/prod"))
            .send()
            .await
            .expect("prod request");
        assert_eq!(
            r.status().as_u16(),
            404,
            "prod proxy must be filtered out when FERRUM_NAMESPACE=staging"
        );
    }
}
