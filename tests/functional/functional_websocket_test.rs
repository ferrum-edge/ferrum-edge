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
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

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

/// Backend that answers each Ping with exactly one explicit Pong (`auto_pong`
/// disabled so tungstenite does not queue a second local reply).
#[allow(clippy::collapsible_match)]
async fn start_ws_ping_responsive_server(port: u16) {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind ping-responsive WS server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut cfg = WebSocketConfig::default();
                cfg.auto_pong = false;
                let ws_stream =
                    match tokio_tungstenite::accept_async_with_config(stream, Some(cfg)).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                let (mut sink, mut source) = ws_stream.split();
                while let Some(Ok(msg)) = source.next().await {
                    match msg {
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

/// Backend that never answers Ping (auto_pong disabled + ignore). Used to prove
/// the gateway does not locally auto-Pong when forwarding client→backend Ping.
#[allow(clippy::collapsible_match)]
async fn start_ws_silent_ping_server(port: u16) {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind silent-ping WS server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut cfg = WebSocketConfig::default();
                cfg.auto_pong = false;
                let ws_stream =
                    match tokio_tungstenite::accept_async_with_config(stream, Some(cfg)).await {
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
                        Message::Ping(_) | Message::Pong(_) => {
                            // Intentionally ignore — far side is unresponsive to Ping.
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

/// Backend that sends one Ping after accept and counts inbound Pongs. When
/// `auto_pong` is false the backend itself will not answer client Pings.
async fn start_ws_backend_ping_server(
    port: u16,
    auto_pong: bool,
    ping_payload: &'static [u8],
    pongs_received: Arc<AtomicUsize>,
) {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind backend-ping WS server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            let pongs_received = pongs_received.clone();
            tokio::spawn(async move {
                let mut cfg = WebSocketConfig::default();
                cfg.auto_pong = auto_pong;
                let ws_stream =
                    match tokio_tungstenite::accept_async_with_config(stream, Some(cfg)).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                let (mut sink, mut source) = ws_stream.split();
                if sink
                    .send(Message::Ping(ping_payload.to_vec().into()))
                    .await
                    .is_err()
                {
                    return;
                }
                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Pong(_) => {
                            pongs_received.fetch_add(1, Ordering::SeqCst);
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

/// Collect the next message, or `None` if `duration` elapses first.
async fn next_ws_message_within(
    ws: &mut (impl StreamExt<Item = Result<Message, WsError>> + Unpin),
    duration: Duration,
) -> Option<Result<Message, WsError>> {
    tokio::time::timeout(duration, ws.next())
        .await
        .unwrap_or_default()
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

/// Mint a per-spawn-attempt observability credential.
///
/// Nothing here is a real secret — it exists only so two gateways started by two
/// parallel tests can never be mistaken for each other — but it is still handled
/// like one: it is never printed, and identity failures report why the probe
/// failed, never the credential. Mirrors `InstanceIdentity` in
/// `tests/common/gateway_harness.rs` (issue #3428).
fn mint_observability_token() -> String {
    format!("ferrum-edge-ws-probe-{}", uuid::Uuid::new_v4().simple())
}

/// Spawn the gateway subprocess. Returns the child plus the admin HTTP port
/// that [`wait_for_owned_gateway`] probes for process identity.
fn start_gateway_with_extra_env(
    config_path: &str,
    http_port: u16,
    https_port: Option<u16>,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    extra_env: &[(&str, &str)],
    observability_token: &str,
) -> Result<(std::process::Child, u16, std::path::PathBuf), Box<dyn std::error::Error>> {
    // Use a fresh admin HTTP port and disable admin HTTPS so parallel gateways
    // in the same functional shard never contend on the default admin ports
    // (9000/9443). Admin-listener bind failure aborts startup (fatal), which
    // would otherwise surface here as a spurious "gateway did not start" when an
    // unrelated parallel test holds the default port.
    //
    // The admin HTTP port must be a real port, never the `0` sentinel: `0`
    // disables the plaintext admin listener, and this file's readiness barrier
    // proves child identity through that listener.
    let admin_http_port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())?;
    let stderr_path =
        std::path::Path::new(config_path).with_extension(format!("gateway-{http_port}.stderr.log"));
    let stderr_file = std::fs::File::create(&stderr_path)?;
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_http_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        // Ownership proof for this exact child (issue #3428 pattern). Presenting
        // this token unlocks the authenticated detail tier of `/health`, which
        // no other gateway on the box can answer with. A leaked parent-shell
        // CIDR allowlist would let a foreign gateway answer the detail tier
        // without the token, so it is scrubbed from the child's environment.
        .env("FERRUM_METRICS_BEARER_TOKEN", observability_token)
        .env_remove("FERRUM_METRICS_ALLOWED_CIDRS")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(stderr_file));

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

    Ok((cmd.spawn()?, admin_http_port, stderr_path))
}

/// Include the bounded tail of the child log in startup failures. The previous
/// null stderr made deterministic config rejection look like a port-readiness
/// flake and multiplied one root cause across every fixture consumer.
fn gateway_startup_error(
    error: &str,
    stderr_path: &std::path::Path,
    observability_token: &str,
) -> String {
    const MAX_LOG_CHARS: usize = 4_000;
    let Ok(stderr) = std::fs::read_to_string(stderr_path) else {
        return error.to_string();
    };
    let stderr = stderr.replace(observability_token, "[REDACTED]");
    let stderr = stderr.trim();
    if stderr.is_empty() {
        return error.to_string();
    }
    let tail = if stderr.chars().count() > MAX_LOG_CHARS {
        stderr
            .chars()
            .rev()
            .take(MAX_LOG_CHARS)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    } else {
        stderr.to_string()
    };
    format!("{error}; gateway stderr (tail): {tail}")
}

/// Write a YAML config file with a WebSocket proxy pointing to the given backend port.
///
/// Keep protocol-managed hop-by-hop/framing destinations (`Connection`,
/// `Upgrade`, `Content-Length`, …) out of `security_headers.set`: the plugin now
/// rejects those at construction, and their rejection matrix is covered by the
/// plugin unit tests.
///
/// The WebSocket negotiation names (`Sec-WebSocket-*`) are deliberately KEPT:
/// they are still admissible configuration, and stripping them at the WebSocket
/// response boundary is a separate production guarantee. Without these sentinel
/// values `assert_no_ws_transport_policy_values` would pass vacuously on both
/// successful handshakes and rejects.
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
plugin_configs:
  - id: "plugin-security-headers-ws"
    plugin_name: "security_headers"
    config:
      hsts: true
      set:
        X-WS-Security: "gateway-enforced"
        Sec-WebSocket-Accept: "policy-must-not-escape"
        Sec-WebSocket-Protocol: "policy-must-not-escape"
      remove: ["server", "x-powered-by"]
    scope: global
    enabled: true
  - id: "plugin-correlation-id-ws"
    plugin_name: "correlation_id"
    config:
      header_name: X-Request-Id
      echo_downstream: true
    scope: global
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

fn write_invalid_correlation_id_file_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "invalid-correlation-proxy"
    listen_path: "/invalid-correlation"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

consumers: []
plugin_configs:
  - id: "invalid-correlation-plugin"
    plugin_name: "correlation_id"
    config: []
    scope: global
    enabled: true
"#,
        backend_port
    );
    let mut file = std::fs::File::create(config_path).expect("create invalid config file");
    file.write_all(config.as_bytes())
        .expect("write invalid config file");
}

/// Write a WebSocket config whose route-level method filter rejects both the
/// H1 Upgrade GET and H2/H3 Extended CONNECT before the ordinary plugin chain.
fn write_ws_method_reject_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-method-reject-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    allowed_methods:
      - POST

consumers: []
plugin_configs:
  - id: "plugin-security-headers-ws-method-reject"
    plugin_name: "security_headers"
    config:
      hsts: true
      set:
        X-WS-Security: "gateway-enforced"
        Sec-WebSocket-Accept: "policy-must-not-escape"
        Sec-WebSocket-Protocol: "policy-must-not-escape"
      remove: ["server", "x-powered-by"]
    scope: global
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a WebSocket route whose response-mock plugin owns both matching and
/// unmatched handshake responses before any backend connection is attempted.
fn write_ws_response_mock_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-response-mock-proxy"
    listen_path: "/ws-mock"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

consumers: []
plugin_configs:
  - id: "plugin-response-mock-ws"
    plugin_name: "response_mock"
    config:
      rules:
        - path: "/match"
          status_code: 418
          headers:
            content-type: "application/json"
            x-mock: "ws"
          body: '{{"mock":"ws-handshake"}}'
    scope: global
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a WebSocket config whose backend-admission limiter holds one permit
/// for the full upgraded session and rejects a concurrent second handshake.
fn write_ws_backend_admission_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-admission-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

consumers: []
plugin_configs:
  - id: "plugin-ws-adaptive-concurrency"
    plugin_name: "adaptive_concurrency"
    config:
      min_limit: 1
      initial_limit: 1
      max_limit: 1
    scope: global
    enabled: true
  - id: "plugin-security-headers-ws-admission"
    plugin_name: "security_headers"
    config:
      hsts: true
      set:
        X-WS-Security: "gateway-enforced"
        X-WS-Reject-Order: "security-policy"
        Sec-WebSocket-Accept: "policy-must-not-escape"
        Sec-WebSocket-Protocol: "policy-must-not-escape"
      remove: ["server", "x-powered-by", "content-type"]
    scope: global
    enabled: true
  - id: "plugin-correlation-id-ws-admission"
    plugin_name: "correlation_id"
    priority_override: 4090
    config:
      header_name: X-WS-Reject-Order
      echo_downstream: true
    scope: global
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a WebSocket config whose first failed backend dial opens the circuit
/// breaker. The second H3 Extended CONNECT is then rejected by the pre-handler
/// breaker branch before `handle_h3_websocket` owns the stream.
fn write_ws_circuit_breaker_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-circuit-breaker-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    backend_connect_timeout_ms: 200
    circuit_breaker:
      failure_threshold: 1
      success_threshold: 1
      timeout_seconds: 60
      failure_status_codes: [500, 502, 503, 504]
      trip_on_connection_errors: true

consumers: []
plugin_configs:
  - id: "plugin-security-headers-ws-circuit-breaker"
    plugin_name: "security_headers"
    config:
      hsts: true
      set:
        X-WS-Security: "gateway-enforced"
        Sec-WebSocket-Accept: "policy-must-not-escape"
        Sec-WebSocket-Key: "policy-must-not-escape"
        Sec-WebSocket-Version: "policy-must-not-escape"
        Sec-WebSocket-Protocol: "policy-must-not-escape"
        Sec-WebSocket-Extensions: "policy-must-not-escape"
      remove: ["server", "x-powered-by"]
    scope: global
    enabled: true
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
plugin_configs:
  - id: "plugin-security-headers-ws-origin"
    plugin_name: "security_headers"
    config:
      hsts: true
      set:
        X-WS-Security: "gateway-enforced"
        Sec-WebSocket-Accept: "policy-must-not-escape"
        Sec-WebSocket-Protocol: "policy-must-not-escape"
      remove: ["server", "x-powered-by"]
    scope: global
    enabled: true
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
  - id: "plugin-security-headers-ws-auth"
    plugin_name: "security_headers"
    config:
      hsts: true
      set:
        X-WS-Security: "gateway-enforced"
        Sec-WebSocket-Accept: "policy-must-not-escape"
        Sec-WebSocket-Protocol: "policy-must-not-escape"
      remove: ["server", "x-powered-by"]
    scope: global
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

/// Wait until `child` has proven it owns its admin port *and* the requested
/// proxy port accepts a TCP connection.
///
/// Readiness is not identity (issue #3435). `free_port` releases its listener
/// before the subprocess binds it, so between reservation and bind any parallel
/// fixture in the shard — another gateway, a tonic backend, a scripted H2
/// server — can claim the reserved proxy port. The gateway then dies with
/// `Address already in use` while a bare TCP connect keeps succeeding against
/// the squatter, and the test proceeds to speak WebSocket to a stranger. That is
/// how `test_h2_websocket_extended_connect_echo` observed
/// `Reset(StreamId(1), PROTOCOL_ERROR, Remote)`: the H2 peer that answered was
/// an h2 server without RFC 8441 `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so it reset
/// the Extended CONNECT that a real Ferrum listener accepts.
///
/// The barrier is the same one `TestGateway` uses (issue #3428), applied to this
/// file's bespoke spawner:
///
/// 1. `Child::try_wait` is polled around every probe, so a child that died after
///    a partial bind consumes its retry attempt immediately instead of polling
///    whatever claimed the released port.
/// 2. The admin port must answer `/health` in the authenticated detail tier for
///    this attempt's `FERRUM_METRICS_BEARER_TOKEN` *and* report `ready: true`.
///    A foreign listener has a different token (or is not a gateway at all) and
///    is rejected.
/// 3. `ready` flips only after `wait_for_start_signals` observed every listener
///    bind — HTTP, HTTPS, and HTTP/3 proxy listeners included — so an identified,
///    ready child is proof that the child owns the port being probed. It holds
///    that socket for its whole lifetime, so the proof stays valid.
///
/// The deadline is generous (60s) because the TLS/HTTP3 gateway cold-start
/// (jemalloc + rustls + config/cert load + QUIC socket setup + DNS/pool warmup)
/// can exceed a tight budget on a loaded CI runner — the previous 15s caused
/// intermittent "Gateway did not start" failures in the H3 WebSocket tests even
/// across the 3 retry attempts. This does not slow the happy path: both stages
/// return as soon as they are satisfied, and they share the one deadline so
/// proving identity cannot double the caller's budget.
async fn wait_for_owned_gateway(
    child: &mut std::process::Child,
    admin_port: u16,
    observability_token: &str,
    gateway_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    const STARTUP_TIMEOUT_SECS: u64 = 60;
    // Slice the ownership probe so `try_wait` is re-polled while it retries.
    const PROBE_SLICE: Duration = Duration::from_secs(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(STARTUP_TIMEOUT_SECS);
    let addr = format!("127.0.0.1:{}", gateway_port);

    let mut last_observation = String::from("no response yet");
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "Gateway exited during startup with {status} \
                 (last observation: {last_observation})"
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "Gateway did not prove ownership of admin port {admin_port} within \
                 {STARTUP_TIMEOUT_SECS} seconds (last observation: {last_observation})"
            )
            .into());
        }
        match crate::common::probe_gateway_identity(
            admin_port,
            observability_token,
            remaining.min(PROBE_SLICE),
        )
        .await
        {
            Ok(()) => break,
            Err(err) => last_observation = err.to_string(),
        }
    }

    // Identity is proven, so this child bound every listener. The proxy socket
    // can still need a moment to surface in the kernel's accept queue on a
    // loaded runner, and a connect that fails now means the child died between
    // the two stages — which `try_wait` reports distinctly.
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("Gateway exited after reporting ready with {status}").into());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Gateway port {gateway_port} did not accept TCP connections within \
                 {STARTUP_TIMEOUT_SECS} seconds"
            )
            .into());
        }
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }
}

/// Start the gateway with retry logic to handle ephemeral port races.
///
/// Each attempt allocates a fresh gateway port and a fresh instance credential,
/// starts the gateway subprocess, and waits for that child to prove it owns its
/// ports ([`wait_for_owned_gateway`]). An attempt whose child lost the port race
/// is void: the process is killed and a new attempt is made with a different
/// port. Panics only after all attempts are exhausted.
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
        let observability_token = mint_observability_token();
        match start_gateway_with_extra_env(
            config_path,
            gateway_port,
            https_port,
            tls_cert_path,
            tls_key_path,
            extra_env,
            &observability_token,
        ) {
            Ok((mut child, admin_port, stderr_path)) => {
                let owned = wait_for_owned_gateway(
                    &mut child,
                    admin_port,
                    &observability_token,
                    gateway_port,
                )
                .await;
                match owned {
                    Ok(()) => return (child, gateway_port),
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        last_err = gateway_startup_error(
                            &e.to_string(),
                            &stderr_path,
                            &observability_token,
                        );
                        eprintln!(
                            "Gateway startup attempt {}/{} failed (port {}): {}",
                            attempt, MAX_ATTEMPTS, gateway_port, last_err
                        );
                    }
                }
            }
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
        let observability_token = mint_observability_token();
        match start_gateway_with_extra_env(
            config_path,
            gateway_port,
            None,
            None,
            None,
            extra_env,
            &observability_token,
        ) {
            Ok((mut child, admin_port, stderr_path)) => {
                let owned = wait_for_owned_gateway(
                    &mut child,
                    admin_port,
                    &observability_token,
                    gateway_port,
                )
                .await;
                match owned {
                    Ok(()) => return (child, gateway_port),
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        last_err = gateway_startup_error(
                            &e.to_string(),
                            &stderr_path,
                            &observability_token,
                        );
                        eprintln!(
                            "Gateway startup attempt {}/{} failed (port {}): {}",
                            attempt, MAX_ATTEMPTS, gateway_port, last_err
                        );
                    }
                }
            }
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
        let observability_token = mint_observability_token();
        match start_gateway_with_extra_env(
            config_path,
            gateway_http_port,
            Some(gateway_https_port),
            Some(tls_cert_path),
            Some(tls_key_path),
            extra_env,
            &observability_token,
        ) {
            Ok((mut child, admin_port, stderr_path)) => {
                let owned = wait_for_owned_gateway(
                    &mut child,
                    admin_port,
                    &observability_token,
                    gateway_https_port,
                )
                .await;
                match owned {
                    Ok(()) => return (child, gateway_http_port, gateway_https_port),
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        last_err = gateway_startup_error(
                            &e.to_string(),
                            &stderr_path,
                            &observability_token,
                        );
                        eprintln!(
                            "Gateway TLS startup attempt {}/{} failed (ports {}/{}): {}",
                            attempt, MAX_ATTEMPTS, gateway_http_port, gateway_https_port, last_err
                        );
                    }
                }
            }
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

fn assert_ws_security_policy(headers: &http::HeaderMap) {
    assert_eq!(
        headers
            .get("x-ws-security")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
    assert_eq!(
        headers
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
}

fn assert_generated_ws_request_id(headers: &http::HeaderMap) -> String {
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("successful WebSocket response must include generated x-request-id")
        .to_string();
    assert!(
        uuid::Uuid::parse_str(&request_id).is_ok(),
        "generated WebSocket request ID must be UUID v4: {request_id}"
    );
    request_id
}

fn assert_preserved_ws_request_id(headers: &http::HeaderMap, expected: &str) {
    assert_eq!(
        headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

fn assert_ws_later_reject_hook_wins(headers: &http::HeaderMap) {
    assert_eq!(
        headers
            .get("x-ws-reject-order")
            .and_then(|value| value.to_str().ok()),
        Some("later-response-hook")
    );
}

/// A response-header policy must never control a transport-managed WebSocket
/// field, on a successful handshake or on a reject.
///
/// The `sec-websocket-*` sentinels are the load-bearing ones: those names are
/// still admissible `security_headers.set` destinations, so the fixtures author
/// `policy-must-not-escape` for them and only the WebSocket response boundary
/// can keep it off the wire. `upgrade` / `connection` are additionally rejected
/// at plugin construction now, so their sentinel can no longer be authored —
/// they stay here as a cheap belt-and-braces check against a future writer.
fn assert_no_ws_transport_policy_values(headers: &http::HeaderMap) {
    for name in [
        "upgrade",
        "connection",
        "sec-websocket-accept",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
    ] {
        assert_ne!(
            headers.get(name).and_then(|value| value.to_str().ok()),
            Some("policy-must-not-escape"),
            "security policy must not control transport-managed {name}"
        );
    }
}

fn assert_no_h1_only_websocket_headers(headers: &http::HeaderMap) {
    for name in ["upgrade", "connection", "sec-websocket-accept"] {
        assert!(
            headers.get(name).is_none(),
            "Extended CONNECT/failure response must not carry H1-only {name}"
        );
    }
}

/// A failed WebSocket handshake is an ordinary HTTP response (RFC 6455 §4.2.2):
/// it must not carry transport-owned negotiation or hop-by-hop fields, but it
/// keeps ordinary representation metadata such as `Content-Length`. Framing
/// coverage lives in [`assert_failed_websocket_handshake_framing`] and
/// [`assert_authoritative_content_length`].
fn assert_no_failed_websocket_negotiation_headers(headers: &http::HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "sec-websocket-accept",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
    ] {
        assert!(
            headers.get(name).is_none(),
            "failed WebSocket handshake must not carry transport-managed {name}"
        );
    }
}

/// The reject must be self-delimiting through an authoritative gateway-derived
/// `Content-Length`, never through `Transfer-Encoding` or connection close. A
/// missing length here is how the earlier HTTP/1.0 framing workaround made
/// RFC 6455 clients fail the handshake response outright.
fn assert_failed_websocket_handshake_framing(headers: &http::HeaderMap) {
    let Some(content_length) = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
    else {
        panic!("failed WebSocket handshake must advertise Content-Length; headers={headers:?}");
    };
    assert!(
        !content_length.is_empty() && content_length.bytes().all(|b| b.is_ascii_digit()),
        "Content-Length must be a plain decimal, got {content_length:?}"
    );
    assert!(
        headers.get(http::header::TRANSFER_ENCODING).is_none(),
        "failed WebSocket handshake must not be chunked; headers={headers:?}"
    );
}

/// Exact-length variant for call sites that can read the reject body.
fn assert_authoritative_content_length(headers: &http::HeaderMap, body_len: usize) {
    let expected = body_len.to_string();
    assert_eq!(
        headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(expected.as_str()),
        "Content-Length must equal the {body_len}-byte reject body; headers={headers:?}"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_file_mode_rejects_non_object_correlation_id_config() {
    let temp_dir = TempDir::new().expect("temporary config directory");
    let config_path = temp_dir.path().join("invalid-correlation.yaml");
    write_invalid_correlation_id_file_config(&config_path, free_port().await);
    build_gateway().expect("build gateway");

    let (mut gateway, _admin_port, _stderr_path) = start_gateway_with_extra_env(
        config_path.to_str().unwrap(),
        free_port().await,
        None,
        None,
        None,
        &[],
        &mint_observability_token(),
    )
    .expect("spawn gateway with invalid file config");
    let exit_status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = gateway.try_wait().expect("poll invalid gateway") {
                break status;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    match exit_status {
        Ok(status) => assert!(
            !status.success(),
            "file mode must fail startup for non-object correlation_id config"
        ),
        Err(_) => {
            let _ = gateway.kill();
            let _ = gateway.wait();
            panic!("gateway stayed running with non-object correlation_id config");
        }
    }
}

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
    let (mut ws, response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");
    assert_ws_security_policy(response.headers());
    assert_generated_ws_request_id(response.headers());
    assert_no_ws_transport_policy_values(response.headers());
    assert_eq!(
        response
            .headers()
            .get("upgrade")
            .and_then(|value| value.to_str().ok()),
        Some("websocket")
    );
    assert_eq!(
        response
            .headers()
            .get("connection")
            .and_then(|value| value.to_str().ok()),
        Some("upgrade")
    );
    assert!(response.headers().get("sec-websocket-accept").is_some());
    assert!(response.headers().get("sec-websocket-protocol").is_none());

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

    let preserved_id = "h1-preserved-websocket-id";
    let mut preserved_request = url
        .as_str()
        .into_client_request()
        .expect("valid preserved-ID WebSocket request");
    preserved_request.headers_mut().insert(
        "x-request-id",
        preserved_id.parse().expect("valid preserved request ID"),
    );
    let (mut preserved_ws, preserved_response) =
        tokio_tungstenite::connect_async(preserved_request)
            .await
            .expect("preserved-ID H1 WebSocket handshake");
    assert_preserved_ws_request_id(preserved_response.headers(), preserved_id);
    preserved_ws
        .send(Message::Close(None))
        .await
        .expect("close preserved-ID H1 WebSocket");

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
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_ws_security_policy(response.headers());
            assert_no_ws_transport_policy_values(response.headers());
            assert_no_h1_only_websocket_headers(response.headers());
            assert_no_failed_websocket_negotiation_headers(response.headers());
        }
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
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_ws_security_policy(response.headers());
            assert_no_ws_transport_policy_values(response.headers());
            assert_no_h1_only_websocket_headers(response.headers());
            assert_no_failed_websocket_negotiation_headers(response.headers());
        }
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
    assert_ws_security_policy(response.headers());
    assert_no_ws_transport_policy_values(response.headers());

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
            assert_ws_security_policy(response.headers());
            assert_no_ws_transport_policy_values(response.headers());
            assert_no_h1_only_websocket_headers(response.headers());
            assert_no_failed_websocket_negotiation_headers(response.headers());
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

/// H3 authentication rejects traverse the same ordered response-hook pipeline
/// as H1, then strip fields owned by the failed Extended CONNECT handshake.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_key_auth_reject_strips_transport_policy_fields() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_auth_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";
    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;
    let url = format!("https://localhost:{gateway_https_port}/ws-secure");

    let client = Http3Client::insecure().expect("H3 client");
    let rejected = client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket authentication rejection response");
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
    assert_ws_security_policy(&rejected.headers);
    assert_no_ws_transport_policy_values(&rejected.headers);
    assert_no_h1_only_websocket_headers(&rejected.headers);
    assert_no_failed_websocket_negotiation_headers(&rejected.headers);
    assert_eq!(
        rejected
            .headers
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("ferrum-edge")
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
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
    assert_ws_security_policy(response.headers());
    assert_generated_ws_request_id(response.headers());
    assert_no_ws_transport_policy_values(response.headers());
    assert_no_h1_only_websocket_headers(response.headers());
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

    let preserved_id = "h2-preserved-websocket-id";
    let preserved_request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{}/ws-echo", gateway_port))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header("x-request-id", preserved_id)
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build preserved-ID H2 WebSocket CONNECT request");
    let preserved_response = sender
        .send_request(preserved_request)
        .await
        .expect("send preserved-ID H2 WebSocket CONNECT");
    assert_eq!(preserved_response.status(), http::StatusCode::OK);
    assert_preserved_ws_request_id(preserved_response.headers(), preserved_id);
    let preserved_upgrade = hyper::upgrade::on(preserved_response)
        .await
        .expect("preserved-ID H2 Extended CONNECT upgrade");
    let mut preserved_ws =
        WebSocketStream::from_raw_socket(TokioIo::new(preserved_upgrade), Role::Client, None).await;
    preserved_ws
        .send(Message::Close(None))
        .await
        .expect("close preserved-ID H2 WebSocket");
    drop(preserved_ws);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_h2_websocket_extended_connect_echo PASSED");
}

/// Regression for issue #3435: a bare TCP accept is not proof that the spawned
/// gateway owns its proxy port.
///
/// A foreign listener holds the port the gateway is told to bind — exactly the
/// state left behind when a parallel fixture wins the race after `free_port`
/// released its reservation. The gateway then dies with `Address already in
/// use`, and the old readiness check (connect to the proxy port, succeed) handed
/// the test the squatter's socket. `test_h2_websocket_extended_connect_echo`
/// observed that as `Reset(StreamId(1), PROTOCOL_ERROR, Remote)`, because the
/// stranger's h2 server never advertised RFC 8441
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
///
/// The barrier must reject the attempt (so the retry loop rerolls the port)
/// rather than report a started gateway.
#[ignore]
#[tokio::test]
async fn test_foreign_listener_on_proxy_port_is_not_gateway_readiness() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, free_port().await);
    build_gateway().expect("Failed to build gateway");

    // Held for the whole test: this listener keeps accepting, so a bare TCP
    // probe would report "ready" the entire time.
    let squatter = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind foreign listener");
    let contested_port = squatter.local_addr().unwrap().port();

    let observability_token = mint_observability_token();
    let (mut child, admin_port, _stderr_path) = start_gateway_with_extra_env(
        config_path.to_str().unwrap(),
        contested_port,
        None,
        None,
        None,
        &[],
        &observability_token,
    )
    .expect("spawn gateway onto the contested port");

    let outcome =
        wait_for_owned_gateway(&mut child, admin_port, &observability_token, contested_port).await;
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", contested_port))
            .await
            .is_ok(),
        "the foreign listener must still accept connections, otherwise this test \
         proves nothing about the old bare-TCP readiness check"
    );
    drop(squatter);

    let err = outcome
        .expect_err("readiness must not accept a foreign listener as the spawned gateway")
        .to_string();
    assert!(
        err.contains("exited during startup") || err.contains("did not prove ownership"),
        "readiness must fail on child death or on the unproven ownership probe, got: {err}"
    );
    println!("test_foreign_listener_on_proxy_port_is_not_gateway_readiness PASSED");
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
            assert_ws_security_policy(response.headers());
            assert_no_ws_transport_policy_values(response.headers());
            assert_no_h1_only_websocket_headers(response.headers());
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

/// A backend-admission rejection happens after the generic reject hooks have
/// applied security_headers. The final failed-handshake boundary must retain
/// the security policy while stripping every transport-managed field it tried
/// to inject.
#[ignore]
#[tokio::test]
async fn test_websocket_backend_admission_reject_strips_transport_policy_fields() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_backend_admission_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{gateway_port}/ws-echo");
    let (mut first_ws, first_response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("first WebSocket should hold the backend-admission permit");
    assert_ws_security_policy(first_response.headers());

    let mut second_request = url
        .as_str()
        .into_client_request()
        .expect("valid second WebSocket request");
    second_request
        .headers_mut()
        .insert("x-ws-reject-order", "later-response-hook".parse().unwrap());
    let second = tokio_tungstenite::connect_async(second_request).await;
    match second {
        Err(WsError::Http(response)) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_ws_security_policy(response.headers());
            assert_ws_later_reject_hook_wins(response.headers());
            assert_no_ws_transport_policy_values(response.headers());
            assert_no_h1_only_websocket_headers(response.headers());
            assert_no_failed_websocket_negotiation_headers(response.headers());
            assert_failed_websocket_handshake_framing(response.headers());
            let body_bytes = response.body().as_ref().cloned().unwrap_or_default();
            // The H1 reject must stay a valid HTTP/1.1 response whose length the
            // gateway derives itself: tungstenite rejects HTTP/1.0 handshake
            // responses outright (RFC 6455 §4.1).
            assert_authoritative_content_length(response.headers(), body_bytes.len());
            let body = String::from_utf8_lossy(&body_bytes).to_string();
            assert!(
                body.contains("Upstream concurrency limit reached"),
                "unexpected rejection body: {body}"
            );
        }
        Ok(_) => panic!("second WebSocket should be rejected by backend admission"),
        Err(err) => panic!("unexpected second WebSocket error: {err:?}"),
    }

    first_ws
        .send(Message::Close(None))
        .await
        .expect("close first WebSocket");
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// H3 backend-admission rejection headers have already completed the ordered
/// reject-hook chain. The transport boundary strips handshake-only fields but
/// must not replay security_headers after a later response hook.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_backend_admission_preserves_later_reject_hook_order() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_backend_admission_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";
    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;
    let url = format!("https://localhost:{gateway_https_port}/ws-echo");

    let first_client = Http3Client::insecure().expect("first H3 client");
    let mut first_ws = first_client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("first H3 WebSocket should hold the backend-admission permit");
    assert_eq!(first_ws.status, StatusCode::OK);
    assert_ws_security_policy(&first_ws.headers);

    let second_client = Http3Client::insecure().expect("second H3 client");
    let mut rejected = second_client
        .websocket(
            &url,
            WebSocketOptions {
                headers: vec![(
                    "x-ws-reject-order".to_string(),
                    "later-response-hook".to_string(),
                )],
                ..WebSocketOptions::default()
            },
        )
        .await
        .expect("second H3 WebSocket rejection response");
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_ws_security_policy(&rejected.headers);
    assert_ws_later_reject_hook_wins(&rejected.headers);
    assert_no_ws_transport_policy_values(&rejected.headers);
    assert_no_h1_only_websocket_headers(&rejected.headers);
    assert_no_failed_websocket_negotiation_headers(&rejected.headers);
    assert!(
        !rejected.headers.contains_key(http::header::CONTENT_TYPE),
        "the final H3 reject writer must preserve policy removal of content-type"
    );
    assert_failed_websocket_handshake_framing(&rejected.headers);
    let rejected_headers = rejected.headers.clone();
    let rejected_body = rejected
        .recv_body_text()
        .await
        .expect("backend-admission rejection body");
    assert!(rejected_body.contains("Upstream concurrency limit reached"));
    // RFC 9220 failed Extended CONNECT: negotiation fields are stripped, but the
    // gateway-derived representation length stays authoritative.
    assert_authoritative_content_length(&rejected_headers, rejected_body.len());

    first_ws
        .send_close()
        .await
        .expect("close first H3 WebSocket");
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// A failed backend dial opens the breaker, then the next Extended CONNECT is
/// rejected in `handle_h3_request` before the dedicated WebSocket handler. The
/// final flavor-aware writer must still remove every transport-owned header
/// injected by response policy after the circuit-breaker reject hooks run.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_open_circuit_reject_strips_transport_policy_fields() {
    let dead_backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind non-responsive backend listener");
    let dead_backend_port = dead_backend_listener.local_addr().unwrap().port();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_circuit_breaker_config(&config_path, dead_backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";
    build_gateway().expect("Failed to build gateway");
    let (mut gateway, _gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;
    let url = format!("https://localhost:{gateway_https_port}/ws-echo");

    let first_client = Http3Client::insecure().expect("first H3 client");
    let first_rejected = first_client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("initial failed backend handshake response");
    assert_eq!(first_rejected.status, StatusCode::BAD_GATEWAY);

    let second_client = Http3Client::insecure().expect("second H3 client");
    let mut circuit_rejected = second_client
        .websocket(&url, WebSocketOptions::default())
        .await
        .expect("open-circuit H3 WebSocket rejection response");
    assert_eq!(circuit_rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_ws_security_policy(&circuit_rejected.headers);
    assert_no_ws_transport_policy_values(&circuit_rejected.headers);
    assert_no_h1_only_websocket_headers(&circuit_rejected.headers);
    assert_no_failed_websocket_negotiation_headers(&circuit_rejected.headers);
    assert_failed_websocket_handshake_framing(&circuit_rejected.headers);
    let circuit_headers = circuit_rejected.headers.clone();
    let circuit_body = circuit_rejected
        .recv_body_text()
        .await
        .expect("open-circuit rejection body");
    assert!(circuit_body.contains("circuit breaker open"));
    assert_authoritative_content_length(&circuit_headers, circuit_body.len());

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Route method filtering runs before ordinary plugins, but the failed
/// WebSocket handshake is already a client-visible response boundary. Both
/// frontend implementations must apply the cached security policy while
/// keeping handshake-owned fields under transport control.
#[ignore]
#[tokio::test]
async fn test_websocket_method_filter_reject_applies_security_policy_h1_h2_and_h3() {
    use bytes::Bytes;
    use http::{Method, Version};
    use http_body_util::Empty;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let backend_port = free_port().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_method_reject_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";
    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let h1_url = format!("ws://127.0.0.1:{gateway_http_port}/ws-echo");
    let h1_rejected = match tokio_tungstenite::connect_async(&h1_url).await {
        Err(WsError::Http(response)) => response,
        Ok(_) => panic!("H1 WebSocket method-filtered handshake should be rejected"),
        Err(error) => panic!("unexpected H1 WebSocket rejection: {error:?}"),
    };
    assert_eq!(h1_rejected.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        h1_rejected
            .headers()
            .get("allow")
            .and_then(|value| value.to_str().ok()),
        Some("POST")
    );
    assert_ws_security_policy(h1_rejected.headers());
    assert_no_ws_transport_policy_values(h1_rejected.headers());
    assert_no_h1_only_websocket_headers(h1_rejected.headers());
    assert_no_failed_websocket_negotiation_headers(h1_rejected.headers());

    let h2_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{gateway_http_port}"))
        .await
        .expect("connect to gateway H2 port");
    let h2_io = TokioIo::new(h2_stream);
    let (mut h2_sender, h2_connection) = http2::handshake(TokioExecutor::new(), h2_io)
        .await
        .expect("H2 handshake");
    let h2_connection_task = tokio::spawn(async move {
        let _ = h2_connection.await;
    });
    let h2_request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{gateway_http_port}/ws-echo"))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build method-filtered H2 WebSocket request");
    let h2_rejected = h2_sender
        .send_request(h2_request)
        .await
        .expect("H2 WebSocket method-filter rejection response");
    assert_eq!(h2_rejected.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        h2_rejected
            .headers()
            .get("allow")
            .and_then(|value| value.to_str().ok()),
        Some("POST")
    );
    assert_ws_security_policy(h2_rejected.headers());
    assert_no_ws_transport_policy_values(h2_rejected.headers());
    assert_no_h1_only_websocket_headers(h2_rejected.headers());
    assert_no_failed_websocket_negotiation_headers(h2_rejected.headers());
    h2_connection_task.abort();

    let h3_url = format!("https://localhost:{gateway_https_port}/ws-echo");
    let h3_client = Http3Client::insecure().expect("H3 client");
    let mut h3_rejected = h3_client
        .websocket(&h3_url, WebSocketOptions::default())
        .await
        .expect("H3 WebSocket method-filter rejection response");
    assert_eq!(h3_rejected.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        h3_rejected
            .headers
            .get("allow")
            .and_then(|value| value.to_str().ok()),
        Some("POST")
    );
    assert_ws_security_policy(&h3_rejected.headers);
    assert_no_ws_transport_policy_values(&h3_rejected.headers);
    assert_no_h1_only_websocket_headers(&h3_rejected.headers);
    assert_no_failed_websocket_negotiation_headers(&h3_rejected.headers);
    assert_failed_websocket_handshake_framing(&h3_rejected.headers);
    let h3_reject_headers = h3_rejected.headers.clone();
    let h3_reject_body = h3_rejected
        .recv_body_text()
        .await
        .expect("H3 method-filter rejection body");
    assert!(h3_reject_body.contains("Method Not Allowed"));
    assert_authoritative_content_length(&h3_reject_headers, h3_reject_body.len());

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Issue #2467: response_mock intentionally participates in every WebSocket
/// handshake frontend. Matching and default-unmatched responses must terminate
/// H1 Upgrade and H2/H3 Extended CONNECT before any backend dial or frame relay.
#[ignore]
#[tokio::test]
async fn test_response_mock_short_circuits_websocket_handshakes_h1_h2_and_h3() {
    use bytes::Bytes;
    use http::{Method, Version};
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let backend_port = free_port().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_response_mock_config(&config_path, backend_port);

    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";
    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_http_port, gateway_https_port) =
        start_gateway_tls_with_retry(config_path.to_str().unwrap(), cert_path, key_path).await;

    let h1_client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("H1 client");
    let h1_match = h1_client
        .get(format!(
            "http://127.0.0.1:{gateway_http_port}/ws-mock/match"
        ))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .send()
        .await
        .expect("matching H1 response-mock handshake");
    assert_eq!(h1_match.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
        h1_match
            .headers()
            .get("x-mock")
            .and_then(|value| value.to_str().ok()),
        Some("ws")
    );
    assert_eq!(
        h1_match.text().await.expect("matching H1 mock body"),
        r#"{"mock":"ws-handshake"}"#
    );

    let h1_miss = h1_client
        .get(format!("http://127.0.0.1:{gateway_http_port}/ws-mock/miss"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .send()
        .await
        .expect("unmatched H1 response-mock handshake");
    assert_eq!(h1_miss.status(), StatusCode::NOT_FOUND);
    assert!(
        h1_miss
            .text()
            .await
            .expect("unmatched H1 mock body")
            .contains("no mock rule matched")
    );

    let h2_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{gateway_http_port}"))
        .await
        .expect("connect to gateway H2 port");
    let h2_io = TokioIo::new(h2_stream);
    let (mut h2_sender, h2_connection) = http2::handshake(TokioExecutor::new(), h2_io)
        .await
        .expect("H2 handshake");
    let h2_connection_task = tokio::spawn(async move {
        let _ = h2_connection.await;
    });

    let h2_match_request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "http://127.0.0.1:{gateway_http_port}/ws-mock/match"
        ))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build matching H2 WebSocket request");
    let h2_match = h2_sender
        .send_request(h2_match_request)
        .await
        .expect("matching H2 response-mock handshake");
    let (h2_match_parts, h2_match_body) = h2_match.into_parts();
    assert_eq!(h2_match_parts.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        h2_match_parts
            .headers
            .get("x-mock")
            .and_then(|value| value.to_str().ok()),
        Some("ws")
    );
    let h2_match_body = h2_match_body
        .collect()
        .await
        .expect("matching H2 mock body")
        .to_bytes();
    assert_eq!(h2_match_body.as_ref(), br#"{"mock":"ws-handshake"}"#);

    let h2_miss_request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{gateway_http_port}/ws-mock/miss"))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build unmatched H2 WebSocket request");
    let h2_miss = h2_sender
        .send_request(h2_miss_request)
        .await
        .expect("unmatched H2 response-mock handshake");
    let (h2_miss_parts, h2_miss_body) = h2_miss.into_parts();
    assert_eq!(h2_miss_parts.status, StatusCode::NOT_FOUND);
    let h2_miss_body = h2_miss_body
        .collect()
        .await
        .expect("unmatched H2 mock body")
        .to_bytes();
    assert!(String::from_utf8_lossy(&h2_miss_body).contains("no mock rule matched"));
    h2_connection_task.abort();

    let h3_match_url = format!("https://localhost:{gateway_https_port}/ws-mock/match");
    let h3_match_client = Http3Client::insecure().expect("matching H3 client");
    let mut h3_match = h3_match_client
        .websocket(&h3_match_url, WebSocketOptions::default())
        .await
        .expect("matching H3 response-mock handshake");
    assert_eq!(h3_match.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        h3_match
            .headers
            .get("x-mock")
            .and_then(|value| value.to_str().ok()),
        Some("ws")
    );
    assert_eq!(
        h3_match
            .recv_body_text()
            .await
            .expect("matching H3 mock body"),
        r#"{"mock":"ws-handshake"}"#
    );

    let h3_miss_url = format!("https://localhost:{gateway_https_port}/ws-mock/miss");
    let h3_miss_client = Http3Client::insecure().expect("unmatched H3 client");
    let mut h3_miss = h3_miss_client
        .websocket(&h3_miss_url, WebSocketOptions::default())
        .await
        .expect("unmatched H3 response-mock handshake");
    assert_eq!(h3_miss.status, StatusCode::NOT_FOUND);
    assert!(
        h3_miss
            .recv_body_text()
            .await
            .expect("unmatched H3 mock body")
            .contains("no mock rule matched")
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Test HTTP/3 WebSocket (RFC 9220 Extended CONNECT) proxying through the
/// gateway, including unmasked compliant frames, binary frames, and strict
/// RFC 9220 rejection of masked client frames.
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
    assert_ws_security_policy(&ws.headers);
    assert_generated_ws_request_id(&ws.headers);
    assert_no_ws_transport_policy_values(&ws.headers);
    assert_no_h1_only_websocket_headers(&ws.headers);
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

    ws.send_masked_text("masked but rejected")
        .await
        .expect("send masked text");
    match ws.recv_frame().await.expect("protocol close") {
        H3WebSocketFrame::Close(payload) => {
            assert!(
                payload.len() >= 2,
                "protocol close payload must include a status code"
            );
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            assert_eq!(code, 1002, "masked H3 frames must close as protocol error");
        }
        other => panic!("expected protocol close after masked frame, got {other:?}"),
    }

    let preserved_id = "h3-preserved-websocket-id";
    let mut preserved_ws = client
        .websocket(
            &url,
            WebSocketOptions {
                headers: vec![("x-request-id".to_string(), preserved_id.to_string())],
                ..WebSocketOptions::default()
            },
        )
        .await
        .expect("preserved-ID H3 WebSocket connect");
    assert_eq!(preserved_ws.status, StatusCode::OK);
    assert_preserved_ws_request_id(&preserved_ws.headers, preserved_id);
    preserved_ws
        .send_close()
        .await
        .expect("close preserved-ID H3 WebSocket");

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
    assert_ws_security_policy(&with_subprotocol.headers);
    assert_no_ws_transport_policy_values(&with_subprotocol.headers);
    assert_no_h1_only_websocket_headers(&with_subprotocol.headers);
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
    assert_ws_security_policy(&without_subprotocol.headers);
    assert_no_ws_transport_policy_values(&without_subprotocol.headers);
    assert_no_h1_only_websocket_headers(&without_subprotocol.headers);
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
    assert_ws_security_policy(&missing_origin.headers);
    assert_no_ws_transport_policy_values(&missing_origin.headers);
    assert_no_h1_only_websocket_headers(&missing_origin.headers);
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
    assert_ws_security_policy(&blocked_origin.headers);
    assert_no_ws_transport_policy_values(&blocked_origin.headers);
    assert_no_h1_only_websocket_headers(&blocked_origin.headers);
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
    assert_ws_security_policy(&allowed_origin.headers);
    assert_no_ws_transport_policy_values(&allowed_origin.headers);
    assert_no_h1_only_websocket_headers(&allowed_origin.headers);
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
    assert_ws_security_policy(&ws.headers);
    assert_no_ws_transport_policy_values(&ws.headers);
    assert_no_h1_only_websocket_headers(&ws.headers);
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

/// Idle-timeout teardown must publish one defined policy Close (1001) so both
/// peers observe a meaningful status instead of asymmetric 1005/1006.
#[ignore]
#[tokio::test]
async fn test_websocket_idle_timeout_sends_symmetric_1001_close() {
    use tokio::sync::mpsc;

    let reservation = crate::scaffolding::reserve_port()
        .await
        .expect("reserve idle-timeout backend port");
    let backend_port = reservation.port;
    let (close_tx, mut backend_closes) = mpsc::unbounded_channel::<(CloseCode, String)>();
    let echo_handle = tokio::spawn(async move {
        let listener = reservation.into_listener();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let close_tx = close_tx.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    match msg {
                        Message::Text(text) => {
                            let echo = format!("Echo: {text}");
                            if ws.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(Some(close)) => {
                            let _ = close_tx.send((close.code, close.reason.to_string()));
                            let _ = ws.send(Message::Close(Some(close))).await;
                            break;
                        }
                        Message::Close(None) => {
                            let _ = close_tx.send((CloseCode::Status, String::new()));
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => {}
                    }
                }
            });
        }
    });

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

    ws.send(Message::Text("hello".into()))
        .await
        .expect("Failed to send text");
    let reply = ws.next().await.expect("No reply").expect("Error reading");
    assert_eq!(reply, Message::Text("Echo: hello".into()));

    let client_close = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(close)))) => break close,
                Some(Ok(Message::Close(None))) => {
                    panic!("idle timeout closed client with 1005/no status")
                }
                Some(Ok(_)) => continue,
                Some(Err(err)) => panic!("idle timeout reset client transport: {err}"),
                None => panic!("idle timeout ended client stream without Close"),
            }
        }
    })
    .await
    .expect("client idle-timeout Close timed out");
    assert_eq!(client_close.code, CloseCode::Away);
    assert_eq!(client_close.reason.as_str(), "idle timeout");

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_closes.recv())
            .await
            .expect("backend idle-timeout Close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Away);
    assert_eq!(backend_reason, "idle timeout");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Issue #2963: client→backend Ping must not produce a local gateway Pong when
/// the backend never answers. Shared `run_websocket_proxy` path (H1 Upgrade).
#[ignore]
#[tokio::test]
async fn test_websocket_ping_unresponsive_backend_yields_no_local_pong() {
    let backend_port = free_port().await;
    let backend_handle = tokio::spawn(start_ws_silent_ping_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Prove the session is live, then Ping an unresponsive far side.
    ws.send(Message::Text("alive".into()))
        .await
        .expect("send alive");
    assert_eq!(
        ws.next().await.expect("alive reply").expect("alive ok"),
        Message::Text("Echo: alive".into())
    );

    let payload = vec![0x71, 0x75, 0x78];
    ws.send(Message::Ping(payload.clone().into()))
        .await
        .expect("send Ping");

    match next_ws_message_within(&mut ws, Duration::from_millis(750)).await {
        None => {}
        Some(Ok(Message::Pong(data))) => {
            panic!("gateway must not auto-Pong when backend is silent; got Pong {data:?}")
        }
        Some(other) => panic!("unexpected frame while waiting for silence: {other:?}"),
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend_handle.abort();
}

/// Issue #2963: a responsive backend yields exactly one Pong (no local double).
#[ignore]
#[tokio::test]
async fn test_websocket_ping_responsive_backend_yields_exactly_one_pong() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_ping_responsive_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    let payload = vec![0x61, 0x62, 0x63];
    ws.send(Message::Ping(payload.clone().into()))
        .await
        .expect("send Ping");

    let first = next_ws_message_within(&mut ws, Duration::from_secs(2))
        .await
        .expect("expected one Pong")
        .expect("Pong read ok");
    assert_eq!(first, Message::Pong(payload.clone().into()));

    match next_ws_message_within(&mut ws, Duration::from_millis(500)).await {
        None => {}
        Some(Ok(Message::Pong(data))) => {
            panic!("exactly one Pong expected; got a second Pong {data:?}")
        }
        Some(other) => panic!("unexpected trailing frame: {other:?}"),
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Issue #2963 (backend→client): unresponsive client yields no local gateway
/// Pong toward the backend.
#[ignore]
#[tokio::test]
async fn test_websocket_backend_ping_unresponsive_client_yields_no_local_pong() {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let backend_port = free_port().await;
    let pongs = Arc::new(AtomicUsize::new(0));
    let backend_handle = tokio::spawn(start_ws_backend_ping_server(
        backend_port,
        false,
        b"b2c-ping",
        pongs.clone(),
    ));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    // Client also disables auto_pong and ignores Ping so the far side is silent.
    let mut client_cfg = WebSocketConfig::default();
    client_cfg.auto_pong = false;
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_with_config(&url, Some(client_cfg), false)
            .await
            .expect("Failed to connect WebSocket");

    let ping = next_ws_message_within(&mut ws, Duration::from_secs(2))
        .await
        .expect("expected backend Ping")
        .expect("Ping read ok");
    assert_eq!(ping, Message::Ping(b"b2c-ping".to_vec().into()));
    // Do not answer. Gateway must not invent a Pong toward the backend.
    sleep(Duration::from_millis(750)).await;
    assert_eq!(
        pongs.load(Ordering::SeqCst),
        0,
        "gateway must not auto-Pong an unresponsive client"
    );

    let _ = ws.send(Message::Close(None)).await;
    let _ = gateway.kill();
    let _ = gateway.wait();
    backend_handle.abort();
}

/// Issue #2963 (backend→client): responsive client yields exactly one Pong.
#[ignore]
#[tokio::test]
async fn test_websocket_backend_ping_responsive_client_yields_exactly_one_pong() {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let backend_port = free_port().await;
    let pongs = Arc::new(AtomicUsize::new(0));
    let backend_handle = tokio::spawn(start_ws_backend_ping_server(
        backend_port,
        false,
        b"b2c-ok",
        pongs.clone(),
    ));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    // Disable client auto_pong so we can assert exactly one explicit reply
    // (and so a gateway-local auto-Pong would still be distinguishable as a
    // second Pong if the bug returned).
    let mut client_cfg = WebSocketConfig::default();
    client_cfg.auto_pong = false;
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_with_config(&url, Some(client_cfg), false)
            .await
            .expect("Failed to connect WebSocket");

    let ping = next_ws_message_within(&mut ws, Duration::from_secs(2))
        .await
        .expect("expected backend Ping")
        .expect("Ping read ok");
    assert_eq!(ping, Message::Ping(b"b2c-ok".to_vec().into()));
    ws.send(Message::Pong(b"b2c-ok".to_vec().into()))
        .await
        .expect("send single client Pong");

    tokio::time::timeout(Duration::from_secs(2), async {
        while pongs.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("backend did not receive client Pong");
    sleep(Duration::from_millis(400)).await;
    assert_eq!(
        pongs.load(Ordering::SeqCst),
        1,
        "exactly one Pong must reach the backend"
    );

    let _ = ws.send(Message::Close(None)).await;
    let _ = gateway.kill();
    let _ = gateway.wait();
    backend_handle.abort();
}

/// Same C2B transparency contract over H2 Extended CONNECT (shared relay).
#[ignore]
#[tokio::test]
async fn test_h2_websocket_ping_unresponsive_backend_yields_no_local_pong() {
    use bytes::Bytes;
    use http::{Method, Version};
    use http_body_util::Empty;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    let backend_port = free_port().await;
    let backend_handle = tokio::spawn(start_ws_silent_ping_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", gateway_port))
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
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
        .expect("build H2 WebSocket CONNECT");
    let response = sender.send_request(request).await.expect("send H2 CONNECT");
    assert_eq!(response.status(), http::StatusCode::OK);
    let upgraded = hyper::upgrade::on(response).await.expect("H2 upgrade");
    let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;

    ws.send(Message::Ping(vec![9, 6, 3].into()))
        .await
        .expect("send H2 Ping");
    match next_ws_message_within(&mut ws, Duration::from_millis(750)).await {
        None => {}
        Some(Ok(Message::Pong(data))) => {
            panic!("H2 path must not auto-Pong silent backend; got {data:?}")
        }
        Some(other) => panic!("unexpected H2 frame: {other:?}"),
    }

    drop(ws);
    conn_task.abort();
    let _ = gateway.kill();
    let _ = gateway.wait();
    backend_handle.abort();
}

/// Same C2B responsive contract over H2 Extended CONNECT.
#[ignore]
#[tokio::test]
async fn test_h2_websocket_ping_responsive_backend_yields_exactly_one_pong() {
    use bytes::Bytes;
    use http::{Method, Version};
    use http_body_util::Empty;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_ping_responsive_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), None, None, None).await;

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", gateway_port))
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
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
        .expect("build H2 WebSocket CONNECT");
    let response = sender.send_request(request).await.expect("send H2 CONNECT");
    assert_eq!(response.status(), http::StatusCode::OK);
    let upgraded = hyper::upgrade::on(response).await.expect("H2 upgrade");
    let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;

    let payload = vec![4, 5, 6];
    ws.send(Message::Ping(payload.clone().into()))
        .await
        .expect("send H2 Ping");
    let first = next_ws_message_within(&mut ws, Duration::from_secs(2))
        .await
        .expect("expected one H2 Pong")
        .expect("H2 Pong read ok");
    assert_eq!(first, Message::Pong(payload.into()));
    match next_ws_message_within(&mut ws, Duration::from_millis(500)).await {
        None => {}
        Some(Ok(Message::Pong(data))) => panic!("second H2 Pong: {data:?}"),
        Some(other) => panic!("unexpected trailing H2 frame: {other:?}"),
    }

    drop(ws);
    conn_task.abort();
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Same C2B transparency contract over H3 Extended CONNECT (shared relay).
#[ignore]
#[tokio::test]
async fn test_h3_websocket_ping_unresponsive_backend_yields_no_local_pong() {
    let backend_port = free_port().await;
    let backend_handle = tokio::spawn(start_ws_silent_ping_server(backend_port));
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

    ws.send_fragment(0x9, &[0x68, 0x33], true)
        .await
        .expect("send H3 Ping");
    match tokio::time::timeout(Duration::from_millis(750), ws.recv_frame()).await {
        Err(_) => {}
        Ok(Ok(H3WebSocketFrame::Pong(data))) => {
            panic!("H3 path must not auto-Pong silent backend; got {data:?}")
        }
        Ok(Ok(other)) => panic!("unexpected H3 frame: {other:?}"),
        Ok(Err(err)) => panic!("H3 recv error while expecting silence: {err}"),
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend_handle.abort();
}

/// Same C2B responsive contract over H3 Extended CONNECT.
#[ignore]
#[tokio::test]
async fn test_h3_websocket_ping_responsive_backend_yields_exactly_one_pong() {
    let backend_port = free_port().await;
    let echo_handle = tokio::spawn(start_ws_ping_responsive_server(backend_port));
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

    let payload = [0x68, 0x33, 0x70];
    ws.send_fragment(0x9, &payload, true)
        .await
        .expect("send H3 Ping");
    match tokio::time::timeout(Duration::from_secs(2), ws.recv_frame())
        .await
        .expect("H3 Pong timed out")
        .expect("H3 Pong read")
    {
        H3WebSocketFrame::Pong(data) => assert_eq!(data, payload),
        other => panic!("expected H3 Pong, got {other:?}"),
    }
    match tokio::time::timeout(Duration::from_millis(500), ws.recv_frame()).await {
        Err(_) => {}
        Ok(Ok(H3WebSocketFrame::Pong(data))) => panic!("second H3 Pong: {data:?}"),
        Ok(Ok(other)) => panic!("unexpected trailing H3 frame: {other:?}"),
        Ok(Err(err)) => panic!("H3 recv error after first Pong: {err}"),
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}
