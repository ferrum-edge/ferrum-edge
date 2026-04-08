//! Functional tests for gRPC-specific plugins and gRPC-specific reject handling.
//!
//! These tests:
//! 1. Start a local gRPC echo backend (h2c HTTP/2 server)
//! 2. Start the gateway binary in file mode with gRPC plugin configs
//! 3. Verify plugin behavior end-to-end through the real gateway binary
//!
//! Run with: cargo test --test functional_tests functional_grpc_plugins -- --ignored --nocapture

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Helpers (same patterns as functional_grpc_test.rs)
// ============================================================================

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Start a mock gRPC backend that echoes headers and body.
/// Also echoes grpc-timeout back as x-echo-grpc-timeout for deadline verification.
async fn start_grpc_echo_backend(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind gRPC echo backend");

    tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let method = req.method().to_string();

                    // Echo grpc-timeout if present (for deadline plugin verification)
                    let grpc_timeout = req
                        .headers()
                        .get("grpc-timeout")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "0")
                        .header("grpc-message", "OK")
                        .header("x-echo-path", &path)
                        .header("x-echo-method", &method);

                    if let Some(timeout) = grpc_timeout {
                        builder = builder.header("x-echo-grpc-timeout", timeout);
                    }

                    let response = builder.body(Full::new(body_bytes)).unwrap();
                    Ok::<_, hyper::Error>(response)
                });

                if let Err(e) = builder.serve_connection(io, service).await
                    && !format!("{}", e).contains("connection closed")
                {
                    eprintln!("gRPC echo backend error: {}", e);
                }
            });
        }
    })
}

fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("cargo")
        .args(["build", "--bin", "ferrum-edge"])
        .output()?;
    if !output.status.success() {
        eprintln!("Build stderr: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Failed to build gateway binary".into());
    }
    Ok(())
}

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let child = std::process::Command::new(gateway_binary_path())
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

async fn send_grpc_request(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Client h2 connection error: {}", e);
        }
    });

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers");

    for (k, v) in extra_headers {
        req_builder = req_builder.header(*k, *v);
    }

    let req = req_builder.body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();

    Ok((status, headers, body_bytes))
}

async fn wait_for_gateway(admin_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);

    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    Err("Gateway did not become healthy within 15 seconds".into())
}

// ============================================================================
// Config writers
// ============================================================================

/// Write config with grpc_method_router plugin: allow_methods only.
fn write_method_router_allow_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "grpc-router-proxy"
    listen_path: "/"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-method-router"

consumers: []

plugin_configs:
  - id: "grpc-method-router"
    plugin_name: "grpc_method_router"
    scope: proxy
    proxy_id: "grpc-router-proxy"
    enabled: true
    config:
      allow_methods:
        - "my.EchoService/Echo"
        - "my.EchoService/Ping"
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write config with grpc_method_router plugin: deny_methods.
fn write_method_router_deny_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "grpc-router-proxy"
    listen_path: "/"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-method-router"

consumers: []

plugin_configs:
  - id: "grpc-method-router"
    plugin_name: "grpc_method_router"
    scope: proxy
    proxy_id: "grpc-router-proxy"
    enabled: true
    config:
      deny_methods:
        - "my.EchoService/Forbidden"
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write config with grpc_method_router plugin: per-method rate limiting.
fn write_method_router_ratelimit_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "grpc-router-proxy"
    listen_path: "/"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-method-router"

consumers: []

plugin_configs:
  - id: "grpc-method-router"
    plugin_name: "grpc_method_router"
    scope: proxy
    proxy_id: "grpc-router-proxy"
    enabled: true
    config:
      method_rate_limits:
        "my.EchoService/Limited":
          max_requests: 3
          window_seconds: 60
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write config with grpc_deadline plugin.
fn write_deadline_config(
    config_path: &std::path::Path,
    backend_port: u16,
    max_deadline_ms: Option<u64>,
    default_deadline_ms: Option<u64>,
) {
    let max_line = max_deadline_ms
        .map(|v| format!("      max_deadline_ms: {v}"))
        .unwrap_or_default();
    let default_line = default_deadline_ms
        .map(|v| format!("      default_deadline_ms: {v}"))
        .unwrap_or_default();

    let config = format!(
        r#"
proxies:
  - id: "grpc-deadline-proxy"
    listen_path: "/"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-deadline"

consumers: []

plugin_configs:
  - id: "grpc-deadline"
    plugin_name: "grpc_deadline"
    scope: proxy
    proxy_id: "grpc-deadline-proxy"
    enabled: true
    config:
{max_line}
{default_line}
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write config with response_size_limiting plugin for gRPC responses.
fn write_response_size_limit_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "grpc-size-limit-proxy"
    listen_path: "/"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-response-size-limit"

consumers: []

plugin_configs:
  - id: "grpc-response-size-limit"
    plugin_name: "response_size_limiting"
    scope: proxy
    proxy_id: "grpc-size-limit-proxy"
    enabled: true
    config:
      max_bytes: 4
      require_buffered_check: true
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

// ============================================================================
// grpc_method_router tests
// ============================================================================

/// Allowed method passes through, disallowed method is rejected with PERMISSION_DENIED.
#[ignore]
#[tokio::test]
async fn test_grpc_method_router_allow_list() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_method_router_allow_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Allowed method should succeed
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Echo", b"", &[])
            .await
            .expect("Allowed method should succeed");

    assert_eq!(status, 200, "Allowed gRPC method should return HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Allowed method should get grpc-status OK"
    );

    // Disallowed method should be rejected
    let (status2, headers2, body2) =
        send_grpc_request(&gateway_addr, "/my.EchoService/NotAllowed", b"", &[])
            .await
            .expect("Disallowed method request should complete");

    assert_eq!(status2, 200, "gRPC method rejection should return HTTP 200");
    assert!(
        body2.is_empty(),
        "gRPC method rejection should be trailers-only"
    );
    assert_eq!(
        headers2.get("grpc-status").map(|s| s.as_str()),
        Some("7"),
        "Disallowed method should map to grpc-status 7 (PERMISSION_DENIED)"
    );
    assert!(
        headers2
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("not permitted")),
        "gRPC rejection should preserve the plugin message"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_method_router_allow_list PASSED");
}

/// Deny list blocks specific method, allows others through.
#[ignore]
#[tokio::test]
async fn test_grpc_method_router_deny_list() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_method_router_deny_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Non-denied method should pass through
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Echo", b"", &[])
            .await
            .expect("Non-denied method should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Non-denied method should succeed"
    );

    // Denied method should be blocked
    let (status2, _headers2, body2) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Forbidden", b"", &[])
            .await
            .expect("Denied method request should complete");

    assert_eq!(status2, 200, "gRPC method rejection should return HTTP 200");
    assert!(
        body2.is_empty(),
        "gRPC method rejection should be trailers-only"
    );
    assert_eq!(
        _headers2.get("grpc-status").map(|s| s.as_str()),
        Some("7"),
        "Denied method should map to grpc-status 7 (PERMISSION_DENIED)"
    );
    assert!(
        _headers2
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("not permitted")),
        "Denied method should preserve the plugin message"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_method_router_deny_list PASSED");
}

/// Per-method rate limiting enforces request limits.
#[ignore]
#[tokio::test]
async fn test_grpc_method_router_rate_limiting() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_method_router_ratelimit_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send 3 requests (within limit) — all should succeed
    for i in 0..3 {
        let (status, headers, _body) =
            send_grpc_request(&gateway_addr, "/my.EchoService/Limited", b"", &[])
                .await
                .unwrap_or_else(|e| panic!("Request {} should succeed: {}", i, e));

        assert_eq!(status, 200, "Request {} within limit should return 200", i);
        assert_eq!(
            headers.get("grpc-status").map(|s| s.as_str()),
            Some("0"),
            "Request {} within limit should succeed",
            i
        );
    }

    // 4th request should be rate-limited
    let (status, headers, body) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Limited", b"", &[])
            .await
            .expect("Rate-limited request should complete");

    assert_eq!(status, 200, "gRPC rate limiting should return HTTP 200");
    assert!(
        body.is_empty(),
        "gRPC rate limiting should be trailers-only"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("8"),
        "Rate-limited method should map to grpc-status 8 (RESOURCE_EXHAUSTED)"
    );
    assert!(
        headers
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("Rate limit exceeded")),
        "Rate limit rejection should preserve the plugin message"
    );

    // Non-rate-limited method should still work
    let (status2, headers2, _body2) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Echo", b"", &[])
            .await
            .expect("Non-limited method should succeed");

    assert_eq!(
        status2, 200,
        "Non-limited method should not be affected by rate limit"
    );
    assert_eq!(
        headers2.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Non-limited method should succeed"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_method_router_rate_limiting PASSED");
}

/// Response-path plugin rejections are translated into gRPC trailers-only errors.
#[ignore]
#[tokio::test]
async fn test_grpc_response_size_limiting_returns_grpc_error() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_response_size_limit_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);
    let (status, headers, body) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Echo", b"1234567890", &[])
            .await
            .expect("Size-limited request should complete");

    assert_eq!(
        status, 200,
        "gRPC response rejection should return HTTP 200"
    );
    assert!(
        body.is_empty(),
        "gRPC response rejection should be trailers-only"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("14"),
        "Gateway-generated response rejection should map to grpc-status 14 (UNAVAILABLE)"
    );
    assert!(
        headers
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("Response body too large")),
        "gRPC response rejection should preserve the plugin message"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_response_size_limiting_returns_grpc_error PASSED");
}

// ============================================================================
// grpc_deadline tests
// ============================================================================

/// Default deadline is injected when client omits grpc-timeout.
#[ignore]
#[tokio::test]
async fn test_grpc_deadline_default_injection() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_deadline_config(&config_path, backend_port, None, Some(5000));

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send request WITHOUT grpc-timeout — plugin should inject default
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/my.EchoService/Echo", b"", &[])
            .await
            .expect("Request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Request should succeed"
    );

    // Backend should have received a grpc-timeout header (default deadline injected)
    assert!(
        headers.contains_key("x-echo-grpc-timeout"),
        "Backend should receive grpc-timeout header from deadline plugin (default injection)"
    );
    let timeout_val = headers.get("x-echo-grpc-timeout").unwrap();
    assert!(
        timeout_val.contains("m") || timeout_val.contains("S"),
        "grpc-timeout should be in milliseconds or seconds, got: {}",
        timeout_val
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_deadline_default_injection PASSED");
}

/// Client grpc-timeout is forwarded when within max_deadline_ms.
#[ignore]
#[tokio::test]
async fn test_grpc_deadline_passthrough() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_deadline_config(&config_path, backend_port, Some(30000), None);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send request WITH grpc-timeout within max — should be forwarded
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/my.EchoService/Echo",
        b"",
        &[("grpc-timeout", "10000m")], // 10 seconds in milliseconds
    )
    .await
    .expect("Request should succeed");

    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(|s| s.as_str()), Some("0"),);

    // Backend should receive the grpc-timeout
    assert!(
        headers.contains_key("x-echo-grpc-timeout"),
        "Backend should receive forwarded grpc-timeout"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_deadline_passthrough PASSED");
}

/// Client grpc-timeout exceeding max_deadline_ms is clamped.
#[ignore]
#[tokio::test]
async fn test_grpc_deadline_clamped_to_max() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    // max_deadline_ms=5000 (5 seconds)
    write_deadline_config(&config_path, backend_port, Some(5000), None);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send request with grpc-timeout of 60 seconds — should be clamped to 5s
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/my.EchoService/Echo",
        b"",
        &[("grpc-timeout", "60S")], // 60 seconds — way over max
    )
    .await
    .expect("Request should succeed (clamped, not rejected)");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Clamped deadline should still allow request through"
    );

    // Backend should receive a grpc-timeout that was clamped to max
    let timeout_val = headers
        .get("x-echo-grpc-timeout")
        .expect("Backend should receive clamped grpc-timeout");

    // The clamped value should be 5000m (5000 milliseconds) or equivalent
    // Parse the numeric part to verify it's <= 5000ms
    let numeric: String = timeout_val
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let unit: String = timeout_val
        .chars()
        .skip_while(|c| c.is_ascii_digit())
        .collect();
    let timeout_ms: u64 = match unit.as_str() {
        "H" => numeric.parse::<u64>().unwrap_or(0) * 3_600_000,
        "M" => numeric.parse::<u64>().unwrap_or(0) * 60_000,
        "S" => numeric.parse::<u64>().unwrap_or(0) * 1_000,
        "m" => numeric.parse::<u64>().unwrap_or(0),
        "u" => numeric.parse::<u64>().unwrap_or(0) / 1_000,
        "n" => numeric.parse::<u64>().unwrap_or(0) / 1_000_000,
        _ => panic!("Unknown grpc-timeout unit: {}", unit),
    };

    assert!(
        timeout_ms <= 5000,
        "Clamped timeout should be <= 5000ms, got {}ms (raw: {})",
        timeout_ms,
        timeout_val
    );
    assert!(
        timeout_ms > 0,
        "Clamped timeout should be > 0ms, got {}ms",
        timeout_ms
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_deadline_clamped_to_max PASSED");
}

/// Non-gRPC requests bypass the gRPC plugins entirely.
#[ignore]
#[tokio::test]
async fn test_grpc_plugins_skip_non_grpc_requests() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;
    let admin_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Config with method_router allow_methods — but the request is HTTP, not gRPC
    let config = format!(
        r#"
proxies:
  - id: "http-proxy"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    auth_mode: single
    plugins:
      - plugin_config_id: "grpc-method-router"

consumers: []

plugin_configs:
  - id: "grpc-method-router"
    plugin_name: "grpc_method_router"
    scope: proxy
    proxy_id: "http-proxy"
    enabled: true
    config:
      allow_methods:
        - "only.This/Allowed"
"#
    );

    let mut file =
        std::fs::File::create(config_path.as_path()).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port, admin_port)
        .expect("Failed to start gateway");
    wait_for_gateway(admin_port)
        .await
        .expect("Gateway did not become healthy");

    // Send a plain HTTP request (not gRPC) — plugin should skip
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/test", gateway_port))
        .send()
        .await
        .expect("HTTP request should complete");

    // The request should NOT be blocked by gRPC method router (plugin skips non-gRPC)
    assert_ne!(
        resp.status().as_u16(),
        403,
        "Non-gRPC HTTP request should not be blocked by gRPC method router"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_plugins_skip_non_grpc_requests PASSED");
}
