//! Functional test for gRPC reverse proxying through Ferrum Gateway.
//!
//! This test:
//! 1. Starts a local gRPC echo backend (h2c HTTP/2 server)
//! 2. Starts the gateway binary in file mode with a `grpc` proxy config
//! 3. Connects an HTTP/2 gRPC client through the gateway
//! 4. Verifies end-to-end gRPC request/response round-trips
//! 5. Tests gRPC trailers (grpc-status, grpc-message) forwarding
//! 6. Tests gRPC error propagation and metadata forwarding
//! 7. Tests backend unavailable returns proper gRPC error
//!
//! This test is marked with #[ignore] as it requires the binary to be built
//! and should be run with: cargo test --test functional_tests functional_grpc -- --ignored --nocapture

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
// Helpers
// ============================================================================

/// Allocate a free port by binding to port 0 and returning the assigned port.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Start a mock gRPC backend server (h2c HTTP/2).
///
/// The backend:
/// - Accepts cleartext HTTP/2 connections (h2c / prior knowledge)
/// - Echoes the request path in `x-echo-path` header
/// - Echoes the request method in `x-echo-method` header
/// - Echoes the request body back in the response
/// - Returns `grpc-status: 0` (OK) by default
/// - Supports `x-test-grpc-status` / `x-test-grpc-message` headers to override status
/// - Echoes `authorization` header back as `x-echo-authorization` for metadata verification
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

                    // Echo the authorization header if present
                    let auth_header = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    // Check for custom test behavior headers
                    let test_status = req
                        .headers()
                        .get("x-test-grpc-status")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u32>().ok());
                    let test_message = req
                        .headers()
                        .get("x-test-grpc-message")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    // Collect request body to echo back
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    let grpc_status = test_status.unwrap_or(0);
                    let grpc_message = test_message.unwrap_or_else(|| "OK".to_string());

                    // Build gRPC response
                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", grpc_status.to_string())
                        .header("grpc-message", &grpc_message)
                        .header("x-echo-path", &path)
                        .header("x-echo-method", &method);

                    if let Some(auth) = auth_header {
                        builder = builder.header("x-echo-authorization", auth);
                    }

                    let response = builder.body(Full::new(body_bytes)).unwrap();

                    Ok::<_, hyper::Error>(response)
                });

                if let Err(e) = builder.serve_connection(io, service).await {
                    // Connection closed by client is normal
                    if !format!("{}", e).contains("connection closed") {
                        eprintln!("gRPC echo backend error: {}", e);
                    }
                }
            });
        }
    })
}

/// Build the gateway binary (debug profile).
fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("cargo")
        .args(["build", "--bin", "ferrum-gateway"])
        .output()?;
    if !output.status.success() {
        eprintln!("Build stderr: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Failed to build gateway binary".into());
    }
    Ok(())
}

/// Find the gateway binary path.
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
        "./target/debug/ferrum-gateway"
    } else {
        "./target/release/ferrum-gateway"
    }
}

/// Start the gateway in file mode.
fn start_gateway(
    config_path: &str,
    http_port: u16,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let child = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "ferrum_gateway=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    Ok(child)
}

/// Write a YAML config file with a gRPC proxy pointing to the given backend port.
fn write_grpc_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "grpc-echo-proxy"
    listen_path: "/grpc"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

  - id: "grpc-nostrip-proxy"
    listen_path: "/grpc-full"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: false

  - id: "grpc-unavailable-proxy"
    listen_path: "/grpc-down"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: 19999
    strip_listen_path: true

consumers: []
plugin_configs: []
"#,
        backend_port, backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a YAML config with a gRPC proxy protected by key_auth, including a consumer.
fn write_grpc_auth_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "grpc-secured-proxy"
    listen_path: "/grpc-secure"
    backend_protocol: grpc
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    auth_mode: single
    plugins:
      - plugin_config_id: "plugin-keyauth-grpc"

consumers:
  - id: "consumer-grpc-service"
    username: "grpc-test-service"
    credentials:
      keyauth:
        key: "grpc-valid-api-key-99887766"

plugin_configs:
  - id: "plugin-keyauth-grpc"
    plugin_name: "key_auth"
    config:
      key_location: "header:x-api-key"
    scope: proxy
    proxy_id: "grpc-secured-proxy"
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Send a gRPC request through the gateway using hyper's HTTP/2 client (h2c).
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

/// Wait for the gateway to start by attempting TCP connections.
async fn wait_for_gateway(gateway_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::SystemTime::now() + Duration::from_secs(15);
    let addr = format!("127.0.0.1:{}", gateway_port);

    loop {
        if std::time::SystemTime::now() >= deadline {
            return Err("Gateway did not start within 15 seconds".into());
        }
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => return Ok(()),
            Err(_) => sleep(Duration::from_millis(300)).await,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

/// End-to-end test: gRPC unary call through the gateway.
/// Client →(h2c)→ Gateway →(h2c)→ gRPC backend → echo response.
#[ignore]
#[tokio::test]
async fn test_grpc_unary_echo_through_gateway() {
    // Allocate ports
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    // Start gRPC echo backend
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    // Send gRPC request through the gateway
    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // gRPC message: [compressed:0][length:5][payload:"hello"]
    let grpc_body = b"\x00\x00\x00\x00\x05hello";
    let (status, headers, body) =
        send_grpc_request(&gateway_addr, "/grpc/my.EchoService/Echo", grpc_body, &[])
            .await
            .expect("gRPC request should succeed");

    // Verify HTTP 200 (gRPC always uses 200)
    assert_eq!(status, 200, "gRPC responses must use HTTP 200");

    // Verify gRPC content-type
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc"),
        "Response should have application/grpc content-type"
    );

    // Verify grpc-status is OK (0)
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "grpc-status should be 0 (OK)"
    );

    // Verify path was stripped correctly
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/my.EchoService/Echo"),
        "Gateway should strip /grpc prefix and forward /my.EchoService/Echo"
    );

    // Verify method is POST (gRPC standard)
    assert_eq!(
        headers.get("x-echo-method").map(|s| s.as_str()),
        Some("POST"),
        "gRPC always uses POST"
    );

    // Verify body was echoed back
    assert_eq!(body, grpc_body, "Backend should echo the gRPC message body");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_unary_echo_through_gateway PASSED");
}

/// End-to-end test: gRPC error status forwarding through the gateway.
/// Backend returns a gRPC error (e.g. NOT_FOUND) and the gateway forwards it.
#[ignore]
#[tokio::test]
async fn test_grpc_error_status_forwarding() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Request the backend to return grpc-status 5 (NOT_FOUND)
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/grpc/my.EchoService/NotFound",
        b"",
        &[
            ("x-test-grpc-status", "5"),
            ("x-test-grpc-message", "method not found"),
        ],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200, "gRPC errors still use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("5"),
        "Gateway should forward grpc-status 5 (NOT_FOUND)"
    );
    assert_eq!(
        headers.get("grpc-message").map(|s| s.as_str()),
        Some("method not found"),
        "Gateway should forward grpc-message"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_error_status_forwarding PASSED");
}

/// End-to-end test: gRPC metadata (HTTP/2 headers) forwarding through the gateway.
/// Verifies that authorization and custom headers are forwarded to the backend.
#[ignore]
#[tokio::test]
async fn test_grpc_metadata_forwarding() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send gRPC request with authorization metadata
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/grpc/my.EchoService/Secure",
        b"",
        &[("authorization", "Bearer test-jwt-token-12345")],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Request should succeed"
    );

    // Verify the authorization header was forwarded to the backend
    assert_eq!(
        headers.get("x-echo-authorization").map(|s| s.as_str()),
        Some("Bearer test-jwt-token-12345"),
        "Authorization metadata should be forwarded to backend"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_metadata_forwarding PASSED");
}

/// End-to-end test: gRPC backend unavailable returns proper gRPC error.
/// The proxy points to a port with no server, so the gateway should return
/// grpc-status 14 (UNAVAILABLE) with HTTP 200.
#[ignore]
#[tokio::test]
async fn test_grpc_backend_unavailable() {
    let backend_port = free_port().await; // For config, but we also need the unavailable proxy
    let gateway_port = free_port().await;

    // Start a real backend for the config (needed for other proxies in config)
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send to the proxy configured with port 19999 (no server running)
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/grpc-down/my.EchoService/Echo", b"", &[])
            .await
            .expect("Request should complete even if backend is down");

    assert_eq!(status, 200, "gRPC errors use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("14"),
        "Backend unavailable should return grpc-status 14 (UNAVAILABLE)"
    );
    assert!(
        headers.contains_key("grpc-message"),
        "Should include a grpc-message explaining the error"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_backend_unavailable PASSED");
}

/// End-to-end test: gRPC with strip_listen_path=false preserves full path.
#[ignore]
#[tokio::test]
async fn test_grpc_no_strip_listen_path() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Use the /grpc-full proxy which has strip_listen_path=false
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/grpc-full/my.EchoService/Echo", b"", &[])
            .await
            .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Request should succeed"
    );
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/grpc-full/my.EchoService/Echo"),
        "Full path including listen_path should be forwarded to backend"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_no_strip_listen_path PASSED");
}

/// End-to-end test: multiple sequential gRPC calls through the gateway.
/// Verifies connection pooling and reuse work correctly for gRPC.
#[ignore]
#[tokio::test]
async fn test_grpc_multiple_sequential_calls() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send 10 sequential gRPC calls with different payloads
    for i in 0..10 {
        let payload = format!("message-{}", i);
        let grpc_body = {
            let mut buf = vec![0u8]; // not compressed
            let len = payload.len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(payload.as_bytes());
            buf
        };

        let (status, headers, body) = send_grpc_request(
            &gateway_addr,
            &format!("/grpc/my.EchoService/Echo{}", i),
            &grpc_body,
            &[],
        )
        .await
        .unwrap_or_else(|e| panic!("gRPC request {} failed: {}", i, e));

        assert_eq!(status, 200, "Call {} should return HTTP 200", i);
        assert_eq!(
            headers.get("grpc-status").map(|s| s.as_str()),
            Some("0"),
            "Call {} should return grpc-status OK",
            i
        );
        assert_eq!(body, grpc_body, "Call {} should echo the body", i);
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_multiple_sequential_calls PASSED");
}

/// End-to-end test: gRPC request rejected by key_auth plugin (no API key).
/// Verifies that gateway auth plugins properly reject unauthenticated gRPC requests.
#[ignore]
#[tokio::test]
async fn test_grpc_key_auth_rejects_missing_key() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_auth_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send gRPC request WITHOUT an API key — should be rejected
    let (status, headers, body) = send_grpc_request(
        &gateway_addr,
        "/grpc-secure/my.EchoService/Echo",
        b"",
        &[], // No x-api-key header
    )
    .await
    .expect("Request should complete");

    assert_eq!(
        status, 401,
        "Missing API key should return HTTP 401 Unauthorized"
    );
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("Missing API key") || body_str.contains("error"),
        "Response body should indicate missing API key, got: {}",
        body_str
    );
    // Auth rejection happens before gRPC proxy path, so no grpc-status header
    assert!(
        !headers.contains_key("grpc-status"),
        "Auth rejection should not include grpc-status (it's a pre-proxy rejection)"
    );

    // Also verify an INVALID key is rejected
    let (status2, _headers2, body2) = send_grpc_request(
        &gateway_addr,
        "/grpc-secure/my.EchoService/Echo",
        b"",
        &[("x-api-key", "wrong-key-12345")],
    )
    .await
    .expect("Request should complete");

    assert_eq!(
        status2, 401,
        "Invalid API key should return HTTP 401 Unauthorized"
    );
    let body_str2 = String::from_utf8_lossy(&body2);
    assert!(
        body_str2.contains("Invalid API key") || body_str2.contains("error"),
        "Response body should indicate invalid API key, got: {}",
        body_str2
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_key_auth_rejects_missing_key PASSED");
}

/// End-to-end test: gRPC request authenticated by key_auth plugin with valid API key.
/// Verifies that the gateway auth plugin accepts the key, identifies the consumer,
/// and proxies the gRPC request to the backend successfully.
#[ignore]
#[tokio::test]
async fn test_grpc_key_auth_accepts_valid_key() {
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_auth_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(config_path.to_str().unwrap(), gateway_port)
        .expect("Failed to start gateway");
    wait_for_gateway(gateway_port)
        .await
        .expect("Gateway did not become healthy");

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send gRPC request WITH a valid API key — should be accepted and proxied
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/grpc-secure/my.EchoService/SecureMethod",
        b"\x00\x00\x00\x00\x05hello",
        &[("x-api-key", "grpc-valid-api-key-99887766")],
    )
    .await
    .expect("gRPC request should succeed");

    // Request should pass through auth and reach the gRPC backend
    assert_eq!(
        status, 200,
        "Authenticated gRPC request should return HTTP 200"
    );
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc"),
        "Response should have gRPC content-type (request reached backend)"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Authenticated gRPC request should succeed with grpc-status OK"
    );
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/my.EchoService/SecureMethod"),
        "Path should be stripped and forwarded to backend"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_key_auth_accepts_valid_key PASSED");
}
