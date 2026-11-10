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

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{TestGateway, spawn_http_echo, spawn_http_identifying};
use std::time::{Duration, Instant};
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
    let listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
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

/// GET `url` and return its status and JSON body. Panics on a transport error
/// or a non-JSON body, so a caller asserting on the result cannot pass on an
/// unanswered request.
async fn get_json(client: &reqwest::Client, url: &str) -> (u16, serde_json::Value) {
    let resp = client
        .get(url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
    let status = resp.status().as_u16();
    let body = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("response from {url} is not JSON: {e}"));
    (status, body)
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
version: "1"
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
version: "1"
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

    // The initial proxy routes to the echo backend, and the route the reload
    // adds does not exist yet (so a later 200 can only come from the reload).
    let client = reqwest::Client::new();
    let (status, body) = get_json(&client, &gateway.proxy_url("/api/v1/one")).await;
    assert_eq!(
        status, 200,
        "initial proxy must route before reload: {body}"
    );
    assert_eq!(
        body["echo"], "/one",
        "initial proxy must strip /api/v1 and reach the echo backend"
    );
    let before = client
        .get(gateway.proxy_url("/api/v2/two"))
        .send()
        .await
        .expect("pre-reload request to /api/v2/two");
    assert_eq!(
        before.status().as_u16(),
        404,
        "/api/v2 must not route before the reload adds it"
    );

    // Rewrite the config file in place with a second proxy added.
    let updated_config = format!(
        r#"
version: "1"
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

    // SIGHUP the running gateway (file-mode reload is Unix-only; the functional
    // suite runs on Linux) and require that the signal was actually delivered.
    let pid = gateway.pid().expect("gateway still running");
    let kill = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output()
        .expect("run kill -HUP");
    assert!(
        kill.status.success(),
        "kill -HUP {pid} failed: {}",
        String::from_utf8_lossy(&kill.stderr)
    );

    // Poll the added route until the reloaded config serves it.
    let deadline = Instant::now() + Duration::from_secs(15);
    let body: serde_json::Value = loop {
        let resp = client.get(gateway.proxy_url("/api/v2/two")).send().await;
        if let Ok(resp) = resp
            && resp.status().is_success()
        {
            break resp.json().await.expect("reloaded route returns JSON");
        }
        assert!(
            Instant::now() < deadline,
            "/api/v2 did not start routing within 15s of SIGHUP; the reload did not apply"
        );
        sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        body["echo"], "/two",
        "the reloaded route must strip /api/v2 and reach the echo backend"
    );

    // The proxy that survived the reload keeps routing.
    let (status, body) = get_json(&client, &gateway.proxy_url("/api/v1/one")).await;
    assert_eq!(
        status, 200,
        "initial proxy must still route after reload: {body}"
    );
    assert_eq!(body["echo"], "/one");
}

#[ignore]
#[tokio::test]
async fn test_file_mode_empty_config() {
    let config = r#"
version: "1"
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
    let backend1 = spawn_http_identifying("backend-1")
        .await
        .expect("spawn backend 1");
    let backend2 = spawn_http_identifying("backend-2")
        .await
        .expect("spawn backend 2");

    let config = format!(
        r#"
version: "1"
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

    // Each listen path must reach its own backend, with the listen path
    // stripped.
    let client = reqwest::Client::new();
    for (path, server) in [
        ("/api/backend1/test", "backend-1"),
        ("/api/backend2/test", "backend-2"),
    ] {
        let (status, body) = get_json(&client, &gateway.proxy_url(path)).await;
        assert_eq!(status, 200, "{path} must route: {body}");
        assert_eq!(body["server"], server, "{path} reached the wrong backend");
        assert_eq!(body["path"], "/test", "{path} was not stripped");
    }
}

#[ignore]
#[tokio::test]
async fn test_file_mode_consumer_identity_headers_forwarded() {
    let (echo_port, echo_handle) = start_header_echo_server().await;

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "auth-proxy"
    listen_path: "/auth-api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "key-auth-plugin"
      - plugin_config_id: "transaction-debugger-plugin"

consumers:
  - id: "consumer-1"
    username: "test-user"
    custom_id: "cust-42"
    credentials:
      keyauth:
        - key: "my-secret-api-key"

plugin_configs:
  - id: "key-auth-plugin"
    proxy_id: "auth-proxy"
    plugin_name: "key_auth"
    scope: proxy
    enabled: true
    config:
      key_location: "header:X-Tenant-Credential"
  - id: "transaction-debugger-plugin"
    proxy_id: "auth-proxy"
    plugin_name: "transaction_debugger"
    scope: proxy
    enabled: true
    config: {{}}
"#
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .capture_output()
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
        .header("X-Tenant-Credential", "my-secret-api-key")
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
    assert!(
        body.get("x-tenant-credential").is_none(),
        "accepted API key must be stripped before backend forwarding"
    );

    sleep(Duration::from_millis(100)).await;
    let logs = gateway
        .read_combined_captured_output()
        .expect("read captured gateway logs");
    assert!(
        !logs.contains("my-secret-api-key"),
        "custom key_auth credential leaked into transaction debugger logs: {logs}"
    );
    assert!(
        logs.contains("***REDACTED***"),
        "transaction debugger did not record a redacted custom credential header: {logs}"
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
version: "1"
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
