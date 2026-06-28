//! Functional test for WebSocket proxying through Ferrum Edge.
//!
//! This test:
//! 1. Starts a local WebSocket echo server as the backend
//! 2. Starts the gateway in file mode with a ws:// proxy config
//! 3. Connects a WebSocket client through the gateway
//! 4. Verifies end-to-end echo round-trips for text and binary messages
//! 5. Tests plaintext (ws://), TLS (wss://), and HTTP/3 Extended CONNECT
//!    WebSocket connections
//! 6. Verifies configured WebSocket Origin allowlists across H1 Upgrade and
//!    H3 Extended CONNECT envelopes
//! 6. Exercises global WebSocket connection admission limits
//!    WebSocket connections, including the H3 WebSocket disablement toggle
//!
//! This test is marked with #[ignore] as it requires the binary to be built
//! and should be run with: cargo test --test functional_tests functional_websocket -- --ignored --nocapture

use futures_util::{SinkExt, StreamExt};
use http::StatusCode;
use std::io::Write;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::scaffolding::{H3WebSocketFrame, Http3Client, WebSocketOptions};

// ============================================================================
// Helpers
// ============================================================================

const WS_FRAME_LIMIT_UNDER_TEST: usize = 64;
const WS_OVERSIZE_FRAME_BYTES: usize = WS_FRAME_LIMIT_UNDER_TEST * 2;
const WS_H3_FRAME_LIMIT_UNDER_TEST: usize = 64;
const WS_H3_OVERSIZE_FRAME_BYTES: usize = WS_H3_FRAME_LIMIT_UNDER_TEST * 2;

/// Allocate a free port by binding to port 0 and returning the assigned port.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Start a WebSocket echo server on the given port.
/// Echoes text messages with "Echo: " prefix and binary messages with "Echo binary: N bytes".
// The `Message::Ping(data)` arm consumes `data` (a `Bytes`) when forwarding
// to `Message::Pong(data)`. Collapsing into a match guard is rejected by the
// borrow checker (E0507) because variables bound in patterns cannot be moved
// from inside a pattern guard.
#[allow(clippy::collapsible_match)]
async fn start_ws_echo_server(port: u16) {
    start_ws_echo_server_with_subprotocol(port, None).await;
}

#[allow(clippy::collapsible_match, clippy::result_large_err)]
async fn start_ws_echo_server_with_subprotocol(
    port: u16,
    selected_subprotocol: Option<&'static str>,
) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind WS echo server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let callback = move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                     mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    if let Some(selected) = selected_subprotocol {
                        let offered = req
                            .headers()
                            .get("sec-websocket-protocol")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        if offered.split(',').any(|v| v.trim() == selected) {
                            resp.headers_mut().insert(
                                "sec-websocket-protocol",
                                selected.parse().expect("valid subprotocol header"),
                            );
                        }
                    }
                    Ok(resp)
                };
                let ws_stream = match tokio_tungstenite::accept_hdr_async(stream, callback).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let (mut sink, mut source) = ws_stream.split();

                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Text(text) => {
                            let echo = format!("Echo: {}", text);
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Ping(data) => {
                            if sink.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

/// Start a WebSocket probe backend that can report whether an oversized
/// client-to-backend frame reached it and can deliberately emit an oversized
/// backend-to-client frame.
#[allow(clippy::collapsible_match)]
async fn start_ws_frame_limit_probe_server(
    port: u16,
    client_oversize_frames: Arc<AtomicUsize>,
    server_oversize_frames: Arc<AtomicUsize>,
) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind WS frame-limit probe server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            let client_oversize_frames = client_oversize_frames.clone();
            let server_oversize_frames = server_oversize_frames.clone();

            tokio::spawn(async move {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let (mut sink, mut source) = ws_stream.split();

                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Text(text) => {
                            if text.len() > WS_FRAME_LIMIT_UNDER_TEST {
                                client_oversize_frames.fetch_add(1, Ordering::Relaxed);
                            }

                            if text.as_str() == "server-oversize" {
                                server_oversize_frames.fetch_add(1, Ordering::Relaxed);
                                let payload = "s".repeat(WS_OVERSIZE_FRAME_BYTES);
                                if sink.send(Message::Text(payload.into())).await.is_err() {
                                    break;
                                }
                                continue;
                            }

                            let echo = format!("Echo: {}", text);
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            if data.len() > WS_FRAME_LIMIT_UNDER_TEST {
                                client_oversize_frames.fetch_add(1, Ordering::Relaxed);
                            }

                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Ping(data) => {
                            if sink.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

/// Start a WebSocket probe backend that counts oversized client frames.
#[allow(clippy::collapsible_match)]
async fn start_ws_oversize_probe_server(port: u16, oversized_frames: Arc<AtomicUsize>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind WS oversize probe server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            let oversized_frames = oversized_frames.clone();
            tokio::spawn(async move {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let (mut sink, mut source) = ws_stream.split();

                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Text(text) => {
                            if text.len() > WS_H3_FRAME_LIMIT_UNDER_TEST {
                                oversized_frames.fetch_add(1, Ordering::Relaxed);
                            }
                            let echo = format!("Echo: {}", text);
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            if data.len() > WS_H3_FRAME_LIMIT_UNDER_TEST {
                                oversized_frames.fetch_add(1, Ordering::Relaxed);
                            }
                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Ping(data) => {
                            if sink.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

async fn start_http_text_server(port: u16, body: &'static str) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind HTTP text server");

    loop {
        if let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
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

/// Build the gateway binary. Thin wrapper over the shared
/// [`crate::common::ensure_gateway_built`] so this file's tests share the
/// same `OnceLock` memoization and `FERRUM_SKIP_GATEWAY_BUILD=1` contract as
/// the [`crate::common::TestGateway`] builder.
fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

/// Find the gateway binary path.
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn start_gateway_with_extra_env(
    config_path: &str,
    http_port: u16,
    https_port: Option<u16>,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    if let Some(port) = https_port {
        cmd.env("FERRUM_PROXY_HTTPS_PORT", port.to_string())
            .env("FERRUM_ENABLE_HTTP3", "true");
    }
    if let Some(cert) = tls_cert_path {
        cmd.env("FERRUM_FRONTEND_TLS_CERT_PATH", cert);
    }
    if let Some(key) = tls_key_path {
        cmd.env("FERRUM_FRONTEND_TLS_KEY_PATH", key);
    }
    for (name, value) in extra_env {
        cmd.env(name, value);
    }

    Ok(cmd.spawn()?)
}

/// Write a YAML config file with a WebSocket proxy pointing to the given backend port.
fn write_ws_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-echo-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a YAML config with a WebSocket proxy protected by an Origin allowlist.
fn write_ws_origin_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-origin-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    allowed_ws_origins:
      - "https://app.example.com"

consumers: []
plugin_configs: []
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a YAML config with a WebSocket proxy protected by key_auth.
fn write_ws_auth_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-secured-proxy"
    listen_path: "/ws-secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    auth_mode: single
    plugins:
      - plugin_config_id: "plugin-keyauth-ws"

consumers:
  - id: "consumer-ws-client"
    username: "ws-test-client"
    credentials:
      keyauth:
        - key: "ws-valid-api-key-112233"

plugin_configs:
  - id: "plugin-keyauth-ws"
    plugin_name: "key_auth"
    config:
      key_location: "header:x-api-key"
    scope: proxy
    proxy_id: "ws-secured-proxy"
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Build a WebSocket proxy backed by an upstream whose first target is
/// intentionally dead and second target is live. H3 WebSocket retries should
/// rotate from target 1 to target 2 on the same CONNECT request.
fn write_ws_retry_upstream_config(
    config_path: &std::path::Path,
    dead_port: u16,
    backend_port: u16,
) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "h3-ws-retry-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {dead_port}
    strip_listen_path: true
    upstream_id: "h3-ws-upstream"
    backend_connect_timeout_ms: 200
    retry:
      max_retries: 1
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 10

upstreams:
  - id: "h3-ws-upstream"
    name: "H3 WS Upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {dead_port}
        weight: 1
      - host: "127.0.0.1"
        port: {backend_port}
        weight: 1

consumers: []
plugin_configs: []
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

fn write_ws_and_http_config(config_path: &std::path::Path, ws_backend_port: u16, http_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-echo-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ws_backend_port}
    strip_listen_path: true

  - id: "plain-proxy"
    listen_path: "/plain"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {http_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Build a rustls ClientConfig that accepts any certificate (for self-signed test certs).
fn insecure_tls_client_config() -> tokio_tungstenite::Connector {
    use std::sync::Arc;

    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("Failed to set protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    tokio_tungstenite::Connector::Rustls(Arc::new(config))
}

/// A certificate verifier that accepts everything (for testing with self-signed certs).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wait for the gateway to become ready by probing the proxy port via TCP connect.
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

/// Start the gateway with retry logic to handle ephemeral port races.
///
/// Each attempt allocates a fresh gateway port, starts the gateway subprocess,
/// and waits for it to become healthy. On failure the process is killed and a
/// new attempt is made with a different port. Panics only after all attempts
/// are exhausted.
async fn start_gateway_with_retry(
    config_path: &str,
    https_port: Option<u16>,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
) -> (std::process::Child, u16) {
    start_gateway_with_retry_extra_env(config_path, https_port, tls_cert_path, tls_key_path, &[])
        .await
}

async fn start_gateway_with_retry_extra_env(
    config_path: &str,
    https_port: Option<u16>,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        match start_gateway_with_extra_env(
            config_path,
            gateway_port,
            https_port,
            tls_cert_path,
            tls_key_path,
            extra_env,
        ) {
            Ok(mut child) => match wait_for_gateway(gateway_port).await {
                Ok(()) => return (child, gateway_port),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Gateway startup attempt {}/{} failed (port {}): {}",
                        attempt, MAX_ATTEMPTS, gateway_port, last_err
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                }
            },
            Err(e) => {
                last_err = e.to_string();
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, last_err
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

async fn start_gateway_plain_with_retry_extra_env(
    config_path: &str,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        match start_gateway_with_extra_env(config_path, gateway_port, None, None, None, extra_env) {
            Ok(mut child) => match wait_for_gateway(gateway_port).await {
                Ok(()) => return (child, gateway_port),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Gateway startup attempt {}/{} failed (port {}): {}",
                        attempt, MAX_ATTEMPTS, gateway_port, last_err
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                }
            },
            Err(e) => {
                last_err = e.to_string();
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, last_err
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

/// Start the gateway with TLS and retry logic for both HTTP and HTTPS port allocation.
///
/// Allocates fresh HTTP and HTTPS gateway ports on each attempt.
async fn start_gateway_tls_with_retry(
    config_path: &str,
    tls_cert_path: &str,
    tls_key_path: &str,
) -> (std::process::Child, u16, u16) {
    start_gateway_tls_with_retry_extra_env(config_path, tls_cert_path, tls_key_path, &[]).await
}

async fn start_gateway_tls_with_retry_extra_env(
    config_path: &str,
    tls_cert_path: &str,
    tls_key_path: &str,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_http_port = free_port().await;
        let gateway_https_port = free_port().await;
        match start_gateway_with_extra_env(
            config_path,
            gateway_http_port,
            Some(gateway_https_port),
            Some(tls_cert_path),
            Some(tls_key_path),
            extra_env,
        ) {
            Ok(mut child) => match wait_for_gateway(gateway_https_port).await {
                Ok(()) => return (child, gateway_http_port, gateway_https_port),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Gateway TLS startup attempt {}/{} failed (ports {}/{}): {}",
                        attempt, MAX_ATTEMPTS, gateway_http_port, gateway_https_port, last_err
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                }
            },
            Err(e) => {
                last_err = e.to_string();
                eprintln!(
                    "Gateway TLS spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, last_err
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway (TLS) did not start after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

fn assert_websocket_limit_closed(reply: Option<Result<Message, WsError>>, context: &str) {
    match reply {
        Some(Ok(Message::Text(text))) => {
            panic!(
                "{context}: oversized frame was forwarded as text ({} bytes)",
                text.len()
            );
        }
        Some(Ok(Message::Binary(data))) => {
            panic!(
                "{context}: oversized frame was forwarded as binary ({} bytes)",
                data.len()
            );
        }
        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {}
        Some(Ok(other)) => panic!("{context}: expected close/error, got {other:?}"),
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test plaintext WebSocket (ws://) proxying: client → gateway → backend echo.
#[ignore]
#[tokio::test]
async fn test_websocket_plaintext_echo() {
    // Allocate ports
    let backend_port = free_port().await;

    // Start echo backend
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    // Connect WebSocket client through the gateway
    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Test text echo
    ws.send(Message::Text("hello world".into()))
        .await
        .expect("Failed to send text");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo: hello world".into()));

    // Test binary echo
    ws.send(Message::Binary(vec![1, 2, 3, 4, 5].into()))
        .await
        .expect("Failed to send binary");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo binary: 5 bytes".into()));

    // Clean close
    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_plaintext_echo PASSED");
}

/// Origin allowlists should fail closed for browser WebSocket handshakes while
/// preserving the documented case-insensitive match behavior.
#[ignore]
#[tokio::test]
async fn test_websocket_origin_allowlist_rejects_missing_and_disallowed_h1() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_origin_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let missing_origin = match tokio_tungstenite::connect_async(&url).await {
        Ok(_) => panic!("WebSocket handshake without Origin should be rejected"),
        Err(err) => err,
    };
    match missing_origin {
        WsError::Http(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN),
        other => panic!("expected HTTP 403 handshake rejection, got {other:?}"),
    }

    let mut blocked_request = url
        .as_str()
        .into_client_request()
        .expect("valid WebSocket request");
    blocked_request
        .headers_mut()
        .insert("origin", "https://evil.example.com".parse().unwrap());
    let blocked_origin = match tokio_tungstenite::connect_async(blocked_request).await {
        Ok(_) => panic!("WebSocket handshake from disallowed Origin should be rejected"),
        Err(err) => err,
    };
    match blocked_origin {
        WsError::Http(response) => assert_eq!(response.status(), StatusCode::FORBIDDEN),
        other => panic!("expected HTTP 403 handshake rejection, got {other:?}"),
    }

    let mut allowed_request = url
        .as_str()
        .into_client_request()
        .expect("valid WebSocket request");
    allowed_request
        .headers_mut()
        .insert("origin", "HTTPS://APP.EXAMPLE.COM".parse().unwrap());
    let (mut ws, response) = tokio_tungstenite::connect_async(allowed_request)
        .await
        .expect("WebSocket handshake from allowed Origin should succeed");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    ws.send(Message::Text("origin ok".into()))
        .await
        .expect("Failed to send text");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo: origin ok".into()));

    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_origin_allowlist_rejects_missing_and_disallowed_h1 PASSED");
}

/// The global WebSocket frame-size env limit is enforced by the shared
/// frame-parsed relay in both directions. Oversized client frames must not
/// reach the backend, and oversized backend frames must not reach the client.
#[ignore]
#[tokio::test]
async fn test_websocket_global_frame_limit_enforced_both_directions() {
    let backend_port = free_port().await;
    let client_oversize_frames = Arc::new(AtomicUsize::new(0));
    let server_oversize_frames = Arc::new(AtomicUsize::new(0));

    let probe_handle = tokio::spawn(start_ws_frame_limit_probe_server(
        backend_port,
        client_oversize_frames.clone(),
        server_oversize_frames.clone(),
    ));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let frame_limit = WS_FRAME_LIMIT_UNDER_TEST.to_string();
    let extra_env = [(
        "FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES",
        frame_limit.as_str(),
    )];
    let (mut gateway, gateway_port) =
        start_gateway_plain_with_retry_extra_env(config_path.to_str().unwrap(), &extra_env).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    ws.send(Message::Text("small".into()))
        .await
        .expect("Failed to send small text");
    let reply = ws
        .next()
        .await
        .expect("No small-frame reply")
        .expect("Error reading small-frame reply");
    assert_eq!(reply, Message::Text("Echo: small".into()));

    let oversized_client_payload = "c".repeat(WS_OVERSIZE_FRAME_BYTES);
    ws.send(Message::Text(oversized_client_payload.into()))
        .await
        .expect("Failed to send oversized client frame");
    let reply = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("gateway did not close after oversized client frame");
    assert_websocket_limit_closed(reply, "client-to-backend");
    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        client_oversize_frames.load(Ordering::Relaxed),
        0,
        "oversized client frame reached backend despite FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES"
    );

    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to reconnect WebSocket");
    ws.send(Message::Text("server-oversize".into()))
        .await
        .expect("Failed to request oversized backend frame");
    let reply = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("gateway did not close after oversized backend frame");
    assert_websocket_limit_closed(reply, "backend-to-client");
    assert_eq!(
        server_oversize_frames.load(Ordering::Relaxed),
        1,
        "probe backend should have attempted exactly one oversized response"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    probe_handle.abort();
    println!("test_websocket_global_frame_limit_enforced_both_directions PASSED");
}

/// End-to-end test: WebSocket handshakes are rejected by key_auth without a key.
#[ignore]
#[tokio::test]
async fn test_websocket_key_auth_rejects_missing_key() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_auth_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-secure", gateway_port);
    let err = match tokio_tungstenite::connect_async(&url).await {
        Ok(_) => panic!("WebSocket handshake without API key should be rejected"),
        Err(err) => err,
    };

    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok()),
                Some("ferrum-edge")
            );
        }
        other => panic!("expected HTTP 401 handshake rejection, got {other:?}"),
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_key_auth_rejects_missing_key PASSED");
}

/// End-to-end test: WebSocket handshakes with a valid API key reach the backend.
#[ignore]
#[tokio::test]
async fn test_websocket_key_auth_accepts_valid_key() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_auth_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-secure", gateway_port);
    let mut request = url
        .as_str()
        .into_client_request()
        .expect("valid WebSocket request");
    request
        .headers_mut()
        .insert("x-api-key", "ws-valid-api-key-112233".parse().unwrap());

    let (mut ws, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WebSocket handshake with valid API key should succeed");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    ws.send(Message::Text("auth ok".into()))
        .await
        .expect("Failed to send authenticated text");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo: auth ok".into()));

    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_key_auth_accepts_valid_key PASSED");
}

/// Test TLS WebSocket (wss://) proxying: client →(TLS)→ gateway → backend echo.
/// The gateway terminates TLS; the backend connection is plaintext ws://.
#[ignore]
#[tokio::test]
async fn test_websocket_tls_echo() {
    // Allocate ports
    let backend_port = free_port().await;

    // Start plaintext echo backend (gateway handles TLS termination)
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway with TLS
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    // Use existing test certs
    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    // Connect with TLS (accept self-signed cert)
    let url = format!("wss://localhost:{}/ws-echo", gateway_https_port);
    let connector = insecure_tls_client_config();
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, Some(connector))
            .await
            .expect("Failed to connect WebSocket over TLS");

    // Test text echo
    ws.send(Message::Text("hello tls".into()))
        .await
        .expect("Failed to send text");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo: hello tls".into()));

    // Clean close
    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_tls_echo PASSED");
}

/// Test multiple sequential WebSocket messages through the gateway.
#[ignore]
#[tokio::test]
async fn test_websocket_multiple_messages() {
    // Allocate ports
    let backend_port = free_port().await;

    // Start echo backend
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    // Connect
    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Send multiple text messages
    for i in 0..10 {
        let msg = format!("message {}", i);
        ws.send(Message::Text(msg.clone().into()))
            .await
            .expect("Failed to send");
        let reply = ws.next().await.expect("No reply").expect("Error reading");
        assert_eq!(reply, Message::Text(format!("Echo: {}", msg).into()));
    }

    // Send multiple binary messages
    for size in [0, 1, 100, 1000] {
        let data = vec![0xABu8; size];
        ws.send(Message::Binary(data.into()))
            .await
            .expect("Failed to send binary");
        let reply = ws.next().await.expect("No reply").expect("Error reading");
        assert_eq!(
            reply,
            Message::Text(format!("Echo binary: {} bytes", size).into())
        );
    }

    // Clean close
    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_multiple_messages PASSED");
}

/// Test HTTP/2 WebSocket (RFC 8441 Extended CONNECT) proxying:
/// client →(h2c Extended CONNECT)→ gateway → backend echo.
#[ignore]
#[tokio::test]
async fn test_h2_websocket_extended_connect_echo() {
    use bytes::Bytes;
    use http::{Method, Version};
    use http_body_util::Empty;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", gateway_port))
        .await
        .expect("Failed to connect to gateway H2 port");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("H2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{}/ws-echo", gateway_port))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build H2 WebSocket CONNECT request");

    let response = sender
        .send_request(request)
        .await
        .expect("send H2 WebSocket CONNECT");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);
    assert!(
        response.headers().get("upgrade").is_none(),
        "RFC 8441 H2 WebSocket responses must not use H1 Upgrade headers"
    );

    let upgraded = hyper::upgrade::on(response)
        .await
        .expect("H2 Extended CONNECT upgrade");
    let io = TokioIo::new(upgraded);
    let mut ws = WebSocketStream::from_raw_socket(io, Role::Client, None).await;

    ws.send(Message::Text("hello h2".into()))
        .await
        .expect("send H2 WebSocket text");
    let reply = ws
        .next()
        .await
        .expect("No H2 WebSocket reply")
        .expect("Error reading H2 WebSocket reply");
    assert_eq!(reply, Message::Text("Echo: hello h2".into()));

    ws.send(Message::Binary(vec![9, 8, 7].into()))
        .await
        .expect("send H2 WebSocket binary");
    let reply = ws
        .next()
        .await
        .expect("No H2 WebSocket binary reply")
        .expect("Error reading H2 WebSocket binary reply");
    assert_eq!(reply, Message::Text("Echo binary: 3 bytes".into()));

    ws.send(Message::Close(None))
        .await
        .expect("close H2 WebSocket");
    drop(ws);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_h2_websocket_extended_connect_echo PASSED");
}

/// Global WebSocket connection admission should reject a second upgraded
/// session while the first one is still open.
#[ignore]
#[tokio::test]
async fn test_websocket_global_connection_limit_rejects_second_upgrade() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry_extra_env(
        config_path.to_str().unwrap(),
        None,
        None,
        None,
        &[("FERRUM_WEBSOCKET_MAX_CONNECTIONS", "1")],
    )
    .await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut first_ws, _first_response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("first WebSocket should connect");
    first_ws
        .send(Message::Text("first".into()))
        .await
        .expect("send first");
    assert_eq!(
        first_ws
            .next()
            .await
            .expect("first echo frame")
            .expect("first echo result"),
        Message::Text("Echo: first".into())
    );

    let second = tokio_tungstenite::connect_async(&url).await;
    match second {
        Err(WsError::Http(response)) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = response
                .body()
                .as_ref()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .unwrap_or_default();
            assert!(
                body.contains("WebSocket connection limit exceeded"),
                "unexpected rejection body: {body}"
            );
        }
        Ok(_) => panic!("second WebSocket upgrade should be rejected by global limit"),
        Err(err) => panic!("unexpected second WebSocket error: {err:?}"),
    }

    first_ws
        .send(Message::Text("still-open".into()))
        .await
        .expect("send still-open");
    assert_eq!(
        first_ws
            .next()
            .await
            .expect("still-open echo frame")
            .expect("still-open echo result"),
        Message::Text("Echo: still-open".into())
    );

    first_ws
        .send(Message::Close(None))
        .await
        .expect("close first");
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Test HTTP/3 WebSocket (RFC 9220 Extended CONNECT) proxying through the
/// gateway, including unmasked compliant frames, binary frames, and today's
/// documented permissive handling of masked client frames.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_rfc9220_echo_and_masked_frame() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut ws = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket connect");
    assert_eq!(ws.status, StatusCode::OK);
    assert!(
        ws.headers.get("sec-websocket-protocol").is_none(),
        "backend negotiated no subprotocol, so H3 200 must not invent one"
    );

    ws.send_text("hello h3").await.expect("send text");
    assert_eq!(ws.recv_text().await.expect("text echo"), "Echo: hello h3");

    ws.send_binary(&[1, 2, 3, 4, 5]).await.expect("send binary");
    assert_eq!(
        ws.recv_text().await.expect("binary echo"),
        "Echo binary: 5 bytes"
    );

    ws.send_masked_text("masked but accepted")
        .await
        .expect("send masked text");
    assert_eq!(
        ws.recv_text().await.expect("masked text echo"),
        "Echo: masked but accepted"
    );

    ws.send_close().await.expect("close");
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// `FERRUM_HTTP3_WEBSOCKET_ENABLED=false` disables only RFC 9220 Extended
/// CONNECT. Plain HTTP/3 requests on the same listener must continue to work,
/// while a client that sends Extended CONNECT anyway receives 501.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_disabled_env_rejects_extended_connect_only() {
    let dead_ws_backend_port = free_port().await;
    let http_backend_port = free_port().await;
    let http_handle = tokio::spawn(start_http_text_server(http_backend_port, "h3-ok"));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_and_http_config(&config_path, dead_ws_backend_port, http_backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry_extra_env(
            config_path.to_str().unwrap(),
            cert_path,
            key_path,
            &[("FERRUM_HTTP3_WEBSOCKET_ENABLED", "false")],
        )
        .await;

    let client = Http3Client::insecure().expect("H3 client");
    let plain_url = format!("https://localhost:{}/plain", gateway_https_port);
    let plain = client.get(&plain_url).await.expect("plain H3 request");
    assert_eq!(plain.status, StatusCode::OK);
    assert_eq!(plain.body_text(), "h3-ok");

    let ws_url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut ws = client
        .websocket(&ws_url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket disabled response");
    assert_eq!(ws.status, StatusCode::NOT_IMPLEMENTED);
    assert!(
        ws.recv_body_text()
            .await
            .expect("disabled H3 WebSocket body")
            .contains("WebSocket over HTTP/3 is disabled"),
        "disabled response should explain H3 WebSocket is disabled"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    http_handle.abort();
}

/// H3 WebSocket always uses the shared frame-parsed relay. Verify the global
/// WebSocket frame-size env limit rejects oversized RFC 9220 client frames
/// before they reach the backend.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_global_frame_limit_rejects_oversized_client_frame() {
    let backend_port = free_port().await;
    let oversized_frames = Arc::new(AtomicUsize::new(0));
    let probe_handle = tokio::spawn(start_ws_oversize_probe_server(
        backend_port,
        oversized_frames.clone(),
    ));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let frame_limit = WS_H3_FRAME_LIMIT_UNDER_TEST.to_string();
    let extra_env = [(
        "FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES",
        frame_limit.as_str(),
    )];
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry_extra_env(
            config_path.to_str().unwrap(),
            cert_path,
            key_path,
            &extra_env,
        )
        .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut ws = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket connect");
    assert_eq!(ws.status, StatusCode::OK);

    ws.send_text("small h3").await.expect("send small text");
    assert_eq!(
        ws.recv_text().await.expect("small text echo"),
        "Echo: small h3"
    );

    let oversized_payload = "x".repeat(WS_H3_OVERSIZE_FRAME_BYTES);
    ws.send_text(&oversized_payload)
        .await
        .expect("send oversized H3 WebSocket frame");

    let rejected = match tokio::time::timeout(Duration::from_secs(5), ws.recv_frame()).await {
        Ok(Ok(H3WebSocketFrame::Text(text))) => {
            panic!(
                "oversized H3 WebSocket frame was echoed to client ({} bytes)",
                text.len()
            );
        }
        Ok(Ok(H3WebSocketFrame::Binary(data))) => {
            panic!(
                "oversized H3 WebSocket frame was echoed as binary ({} bytes)",
                data.len()
            );
        }
        Ok(Ok(H3WebSocketFrame::Close(_))) | Ok(Err(_)) | Err(_) => true,
        Ok(Ok(other)) => panic!("expected H3 WebSocket close/error, got {other:?}"),
    };
    assert!(rejected, "oversized H3 WebSocket frame should be rejected");

    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        oversized_frames.load(Ordering::Relaxed),
        0,
        "oversized H3 WebSocket frame reached backend despite FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    probe_handle.abort();
}

/// The H3 bridge forwards the client's offered subprotocols to the backend
/// H1 Upgrade handshake and mirrors the backend's selected protocol on the
/// RFC 9220 200 response.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_subprotocol_forwarding_and_none() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server_with_subprotocol(
        backend_port,
        Some("chat.v2"),
    ));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut with_subprotocol = client
        .websocket(
            &url,
            WebSocketOptions::default().subprotocols(["chat.v1", "chat.v2"]),
        )
        .await
        .expect("H3 WebSocket connect with subprotocols");
    assert_eq!(with_subprotocol.status, StatusCode::OK);
    assert_eq!(
        with_subprotocol
            .headers
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("chat.v2")
    );
    with_subprotocol
        .send_text("subprotocol")
        .await
        .expect("send text");
    assert_eq!(
        with_subprotocol.recv_text().await.expect("echo"),
        "Echo: subprotocol"
    );
    with_subprotocol.send_close().await.expect("close");

    let mut without_subprotocol = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket connect without subprotocol");
    assert_eq!(without_subprotocol.status, StatusCode::OK);
    assert!(
        without_subprotocol
            .headers
            .get("sec-websocket-protocol")
            .is_none(),
        "backend should not select a subprotocol when the client offered none"
    );
    without_subprotocol
        .send_text("plain")
        .await
        .expect("send text");
    assert_eq!(
        without_subprotocol.recv_text().await.expect("echo"),
        "Echo: plain"
    );
    without_subprotocol.send_close().await.expect("close");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Origin allowlists are enforced before the H3 Extended CONNECT stream is
/// upgraded to backend WebSocket transport.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_origin_allowlist_enforced_before_backend_connect() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_origin_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{}/ws-echo", gateway_https_port);

    let mut missing_origin = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket missing-origin response");
    assert_eq!(missing_origin.status, StatusCode::FORBIDDEN);
    assert!(
        missing_origin
            .recv_body_text()
            .await
            .expect("missing-origin body")
            .contains("WebSocket Origin not allowed")
    );

    let mut blocked_origin = client
        .websocket(
            &url,
            WebSocketOptions {
                headers: vec![("origin".to_string(), "https://evil.example.com".to_string())],
                ..Default::default()
            },
        )
        .await
        .expect("H3 WebSocket disallowed-origin response");
    assert_eq!(blocked_origin.status, StatusCode::FORBIDDEN);
    assert!(
        blocked_origin
            .recv_body_text()
            .await
            .expect("disallowed-origin body")
            .contains("WebSocket Origin not allowed")
    );

    let mut allowed_origin = client
        .websocket(
            &url,
            WebSocketOptions {
                headers: vec![("origin".to_string(), "HTTPS://APP.EXAMPLE.COM".to_string())],
                ..Default::default()
            },
        )
        .await
        .expect("H3 WebSocket allowed-origin connect");
    assert_eq!(allowed_origin.status, StatusCode::OK);
    allowed_origin
        .send_text("origin h3")
        .await
        .expect("send text");
    assert_eq!(
        allowed_origin.recv_text().await.expect("text echo"),
        "Echo: origin h3"
    );
    allowed_origin.send_close().await.expect("close");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// H3 WebSocket backend setup failures should follow the same retry-on-connect
/// policy and target rotation as H1/H2 WebSockets.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_retry_rotates_to_next_upstream_target() {
    let dead_port = free_port().await;
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_retry_upstream_config(&config_path, dead_port, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut ws = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket connect should retry from dead target to live target");
    assert_eq!(ws.status, StatusCode::OK);

    ws.send_text("retry rotation").await.expect("send text");
    assert_eq!(ws.recv_text().await.expect("echo"), "Echo: retry rotation");
    ws.send_close().await.expect("close");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// A failed H3 WebSocket backend setup should be surfaced as the same 502 JSON
/// response as the H1/H2 upgrade path instead of hanging the CONNECT stream.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_failed_backend_upgrade_returns_502() {
    let dead_port = free_port().await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, dead_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut ws = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket failed-upgrade response");
    assert_eq!(ws.status, StatusCode::BAD_GATEWAY);
    assert!(
        ws.recv_body_text()
            .await
            .expect("failed-upgrade body")
            .contains("Backend WebSocket connection failed")
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// The H3 bridge releases the per-IP request guard after the 200 upgrade
/// response. Keeping it for the full WebSocket session would make one
/// long-lived socket block ordinary requests from the same client IP.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_releases_per_ip_request_slot_after_200() {
    let ws_backend_port = free_port().await;
    let http_backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(ws_backend_port));
    let http_handle = tokio::spawn(start_http_text_server(http_backend_port, "plain-ok"));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_and_http_config(&config_path, ws_backend_port, http_backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry_extra_env(
            config_path.to_str().unwrap(),
            cert_path,
            key_path,
            &[("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP", "1")],
        )
        .await;

    let client = Http3Client::insecure().expect("H3 client");
    let ws_url = format!("https://localhost:{}/ws-echo", gateway_https_port);
    let mut ws = client
        .websocket(&ws_url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket connect");
    assert_eq!(ws.status, StatusCode::OK);

    let plain_url = format!("https://localhost:{}/plain", gateway_https_port);
    let plain = client.get(&plain_url).await.expect("plain H3 request");
    assert_eq!(
        plain.status,
        StatusCode::OK,
        "per-IP request slot should be released after the H3 WS 200 response"
    );
    assert_eq!(plain.body_text(), "plain-ok");

    ws.send_text("still open").await.expect("send text");
    assert_eq!(ws.recv_text().await.expect("echo"), "Echo: still open");
    ws.send_close().await.expect("close");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    http_handle.abort();
}

/// Disabling `FERRUM_HTTP3_WEBSOCKET_ENABLED` must only gate RFC 9220
/// WebSocket Extended CONNECT. Ordinary HTTP/3 traffic on the same listener
/// must keep working.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_env_disabled_rejects_connect_but_plain_h3_works() {
    let ws_backend_port = free_port().await;
    let http_backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(ws_backend_port));
    let http_handle = tokio::spawn(start_http_text_server(http_backend_port, "h3-ok"));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_and_http_config(&config_path, ws_backend_port, http_backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry_extra_env(
            config_path.to_str().unwrap(),
            cert_path,
            key_path,
            &[("FERRUM_HTTP3_WEBSOCKET_ENABLED", "false")],
        )
        .await;

    let client = Http3Client::insecure().expect("H3 client");
    let plain_url = format!("https://localhost:{gateway_https_port}/plain");
    let plain = client
        .get(&plain_url)
        .await
        .expect("plain H3 request should still work");
    assert_eq!(plain.status, StatusCode::OK);
    assert_eq!(plain.body_text(), "h3-ok");

    let ws_url = format!("https://localhost:{gateway_https_port}/ws-echo");
    let mut ws = client
        .websocket(&ws_url, WebSocketOptions::default())
        .await
        .expect("disabled H3 WebSocket response");
    assert_eq!(ws.status, StatusCode::NOT_IMPLEMENTED);
    assert!(
        ws.recv_body_text()
            .await
            .expect("disabled H3 WebSocket body")
            .contains("WebSocket over HTTP/3 is disabled"),
        "disabled H3 WebSocket response should explain the env gate"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    http_handle.abort();
}

// ============================================================================
// WebSocket idle timeout (FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS + per-proxy)
// ============================================================================

/// Read frames until the relay terminates (Close frame, stream end, or transport
/// error) or `deadline` elapses. Non-terminal frames (Pong, echo replies) are
/// ignored. Returns `true` if the gateway closed the session within `deadline`.
async fn ws_session_closed_within<S>(ws: &mut S, deadline: Duration) -> bool
where
    S: futures_util::Stream<Item = Result<Message, WsError>> + Unpin,
{
    let start = tokio::time::Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            return false;
        }
        match tokio::time::timeout(deadline - elapsed, ws.next()).await {
            Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => continue, // ignore Pong / echo / other frames
            Ok(Some(Err(_))) => return true, // transport error => relay torn down
            Ok(None) => return true,     // stream ended => relay torn down
            Err(_) => return false,      // deadline elapsed with no termination
        }
    }
}

/// Default-bounded deployments must close a silent WebSocket session once the
/// idle window elapses (frame-parsed relay path).
#[ignore]
#[tokio::test]
async fn test_websocket_idle_timeout_closes_idle_session() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_plain_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS", "2")],
    )
    .await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Session is live: a round-trip succeeds before we go idle.
    ws.send(Message::Text("hello".into()))
        .await
        .expect("Failed to send text");
    let reply = ws.next().await.expect("No reply").expect("Error reading");
    assert_eq!(reply, Message::Text("Echo: hello".into()));

    // Now stay idle. The 2s idle bound must tear the session down; 10s is a
    // generous ceiling (the watchdog fires within a few seconds of inactivity).
    assert!(
        ws_session_closed_within(&mut ws, Duration::from_secs(10)).await,
        "idle WebSocket session should be closed by the gateway within the idle window"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Explicit `0` must preserve the legacy "never time out" behavior so operators
/// can intentionally opt out for genuinely long-lived silent streams.
#[ignore]
#[tokio::test]
async fn test_websocket_idle_timeout_disabled_keeps_session_open() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_plain_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS", "0")],
    )
    .await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Stay idle well past any reasonable window — must NOT be closed.
    assert!(
        !ws_session_closed_within(&mut ws, Duration::from_secs(5)).await,
        "with idle timeout disabled (0) the session must stay open while idle"
    );

    // And it is still usable: a round-trip succeeds after the idle period.
    ws.send(Message::Text("still-here".into()))
        .await
        .expect("send after idle should succeed when timeout disabled");
    let reply = ws.next().await.expect("No reply").expect("Error reading");
    assert_eq!(reply, Message::Text("Echo: still-here".into()));

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Data-frame activity from either direction must refresh the shared idle
/// watermark, keeping a busy session alive past the window; once activity stops
/// the session then closes.
#[ignore]
#[tokio::test]
async fn test_websocket_idle_timeout_activity_refreshes_then_closes() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_plain_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS", "3")],
    )
    .await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Exchange a frame every ~1s for ~6s (twice the 3s window). Each round-trip
    // refreshes the watermark, so the session must remain open the whole time.
    for i in 0..6 {
        ws.send(Message::Text(format!("beat-{i}").into()))
            .await
            .expect("send during activity window should succeed");
        let reply = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("echo should arrive while session is kept alive")
            .expect("stream open")
            .expect("no transport error");
        assert_eq!(reply, Message::Text(format!("Echo: beat-{i}").into()));
        sleep(Duration::from_secs(1)).await;
    }

    // Activity stops: the session must now close within the idle window.
    assert!(
        ws_session_closed_within(&mut ws, Duration::from_secs(10)).await,
        "session should close once activity stops and the idle window elapses"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Tunnel mode (raw bidirectional copy) must enforce the same idle bound as the
/// frame-parsed relay, so the two modes behave consistently.
#[ignore]
#[tokio::test]
async fn test_websocket_idle_timeout_tunnel_mode_closes_idle_session() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_plain_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[
            ("FERRUM_WEBSOCKET_TUNNEL_MODE", "true"),
            ("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS", "2"),
        ],
    )
    .await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Confirm the tunnel relay is live before idling.
    ws.send(Message::Text("tunnel-hello".into()))
        .await
        .expect("Failed to send text");
    let reply = ws.next().await.expect("No reply").expect("Error reading");
    assert_eq!(reply, Message::Text("Echo: tunnel-hello".into()));

    assert!(
        ws_session_closed_within(&mut ws, Duration::from_secs(10)).await,
        "tunnel-mode idle WebSocket session should be closed within the idle window"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}
