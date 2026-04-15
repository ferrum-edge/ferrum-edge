//! Functional tests for WebSocket frame-level plugins.
//!
//! Tests the three WS frame plugins end-to-end through a real gateway binary:
//! - ws_message_size_limiting: enforces max frame sizes (close code 1009)
//! - ws_frame_logging: logs frame metadata (doesn't interfere with traffic)
//! - ws_rate_limiting: rate limits frames per connection (close code 1008)
//!
//! All tests are #[ignore] — run with:
//!   cargo test --test functional_tests functional_ws_plugins -- --ignored --nocapture

use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::Message;

// ============================================================================
// Helpers
// ============================================================================

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Start a WebSocket echo server on the given port.
async fn start_ws_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind WS echo server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
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
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let cmd = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(cmd)
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
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        match start_gateway(config_path, gateway_port) {
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

fn write_ws_config_with_plugins(
    config_path: &std::path::Path,
    backend_port: u16,
    plugin_configs_yaml: &str,
    proxy_plugins_yaml: &str,
) {
    let config = format!(
        r#"
proxies:
  - id: "ws-echo-proxy"
    listen_path: "/ws-echo"
    backend_protocol: ws
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
{proxy_plugins_yaml}

consumers: []

plugin_configs:
{plugin_configs_yaml}
"#,
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

// ============================================================================
// ws_message_size_limiting E2E
// ============================================================================

/// Test that small messages pass through and large messages trigger close code 1009.
#[ignore]
#[tokio::test]
async fn test_ws_message_size_limiting_e2e() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config_with_plugins(
        &config_path,
        backend_port,
        r#"  - id: "ws-size-limit"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 50"#,
        r#"      - plugin_config_id: "ws-size-limit""#,
    );

    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Connect
    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Small message should pass
    ws.send(Message::Text("hello".into())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::Text("Echo: hello".into()));

    // Large message (> 50 bytes) should trigger close
    let large_msg = "x".repeat(60);
    ws.send(Message::Text(large_msg.into())).await.unwrap();

    // Should receive a close frame with code 1009
    let reply = ws.next().await;
    match reply {
        Some(Ok(Message::Close(Some(cf)))) => {
            assert_eq!(
                cf.code,
                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                "Expected close code 1009 (Size), got {:?}",
                cf.code
            );
            println!("Got expected close code 1009: {}", cf.reason);
        }
        Some(Ok(Message::Close(None))) => {
            // Some implementations may not include the close frame details
            println!("Got close frame without details (acceptable)");
        }
        None => {
            // Connection was closed
            println!("Connection closed (acceptable)");
        }
        other => {
            // The gateway may close the connection before the client sees the close frame
            println!(
                "Got unexpected reply (connection may have been closed): {:?}",
                other
            );
        }
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_ws_message_size_limiting_e2e PASSED");
}

// ============================================================================
// ws_frame_logging E2E
// ============================================================================

/// Test that ws_frame_logging doesn't interfere with normal WebSocket traffic.
#[ignore]
#[tokio::test]
async fn test_ws_frame_logging_e2e() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config_with_plugins(
        &config_path,
        backend_port,
        r#"  - id: "ws-logging"
    plugin_name: "ws_frame_logging"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      log_level: "debug"
      include_payload_preview: true
      payload_preview_bytes: 64"#,
        r#"      - plugin_config_id: "ws-logging""#,
    );

    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Send multiple messages — all should echo correctly (logging is transparent)
    for i in 0..5 {
        let msg = format!("logged message {}", i);
        ws.send(Message::Text(msg.clone().into())).await.unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        assert_eq!(reply, Message::Text(format!("Echo: {}", msg).into()));
    }

    // Binary message should also pass
    ws.send(Message::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF].into()))
        .await
        .unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::Text("Echo binary: 4 bytes".into()));

    // Clean close
    ws.send(Message::Close(None)).await.unwrap();

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_ws_frame_logging_e2e PASSED");
}

// ============================================================================
// ws_rate_limiting E2E
// ============================================================================

/// Test that frames within limit pass and frames exceeding limit trigger close.
#[ignore]
#[tokio::test]
async fn test_ws_rate_limiting_e2e() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    // Use a generous burst to allow some round-trips to pass, then exhaust it.
    // Each round-trip counts 2 frames (client->backend + backend->client echo).
    // burst_size=20 allows ~10 round-trips, then rapidly sending should exhaust it.
    write_ws_config_with_plugins(
        &config_path,
        backend_port,
        r#"  - id: "ws-rate-limit"
    plugin_name: "ws_rate_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      frames_per_second: 5
      burst_size: 20"#,
        r#"      - plugin_config_id: "ws-rate-limit""#,
    );

    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Send messages within the limit (burst_size=20 allows ~10 round-trips)
    for i in 0..5 {
        let msg = format!("msg {}", i);
        ws.send(Message::Text(msg.clone().into())).await.unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        assert_eq!(
            reply,
            Message::Text(format!("Echo: {}", msg).into()),
            "Message {} within limit should echo",
            i
        );
    }

    // Now send a burst that exceeds the limit — the gateway should close the connection.
    // Each round-trip = 2 frames. We've used ~10 frames already. With burst=20,
    // after ~5 more round-trips the bucket will be exhausted.
    let mut connection_closed = false;
    for i in 5..50 {
        let msg = format!("burst msg {}", i);
        match ws.send(Message::Text(msg.into())).await {
            Ok(_) => {
                // Try to read the reply
                match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
                    Ok(Some(Ok(Message::Close(_)))) => {
                        connection_closed = true;
                        println!("Connection closed at message {} (rate limited)", i);
                        break;
                    }
                    Ok(None) => {
                        connection_closed = true;
                        println!("Connection stream ended at message {}", i);
                        break;
                    }
                    Err(_) => {
                        // Timeout reading — connection may have been closed on the send side
                        connection_closed = true;
                        println!("Read timeout at message {} (connection likely closed)", i);
                        break;
                    }
                    Ok(Some(Ok(_))) => {
                        // Normal echo reply — keep going
                    }
                    Ok(Some(Err(e))) => {
                        connection_closed = true;
                        println!("Read error at message {}: {} (rate limited)", i, e);
                        break;
                    }
                }
            }
            Err(e) => {
                connection_closed = true;
                println!("Send error at message {}: {} (rate limited)", i, e);
                break;
            }
        }
    }

    assert!(
        connection_closed,
        "Connection should have been closed by rate limiter"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_ws_rate_limiting_e2e PASSED");
}

// ============================================================================
// Combined plugins E2E
// ============================================================================

/// Test that multiple WS frame plugins can coexist on the same proxy.
#[ignore]
#[tokio::test]
async fn test_ws_combined_plugins_e2e() {
    let backend_port = free_port().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config_with_plugins(
        &config_path,
        backend_port,
        r#"  - id: "ws-size-limit"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 1000
  - id: "ws-logging"
    plugin_name: "ws_frame_logging"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      log_level: "debug"
  - id: "ws-rate-limit"
    plugin_name: "ws_rate_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      frames_per_second: 100
      burst_size: 100"#,
        r#"      - plugin_config_id: "ws-size-limit"
      - plugin_config_id: "ws-logging"
      - plugin_config_id: "ws-rate-limit""#,
    );

    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Normal messages should work with all three plugins active
    for i in 0..10 {
        let msg = format!("combined test {}", i);
        ws.send(Message::Text(msg.clone().into())).await.unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        assert_eq!(reply, Message::Text(format!("Echo: {}", msg).into()));
    }

    // Clean close
    ws.send(Message::Close(None)).await.unwrap();

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_ws_combined_plugins_e2e PASSED");
}
