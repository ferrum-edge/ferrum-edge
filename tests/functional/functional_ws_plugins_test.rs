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
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};

// ============================================================================
// Helpers
// ============================================================================

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

async fn bind_ws_backend_listener() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind WS backend");
    let port = listener
        .local_addr()
        .expect("WS backend local address")
        .port();
    (port, listener)
}

/// Start a WebSocket echo server on an already-bound listener.
// The `Message::Ping(data)` arm consumes `data` (a `Bytes`) when forwarding
// to `Message::Pong(data)`. Collapsing into a match guard is rejected by the
// borrow checker (E0507) because variables bound in patterns cannot be moved
// from inside a pattern guard.
#[allow(clippy::collapsible_match)]
async fn start_ws_echo_server(listener: TcpListener) {
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

async fn start_ws_echo_server_recording_close(
    listener: TcpListener,
    close_tx: mpsc::UnboundedSender<(CloseCode, String)>,
) {
    loop {
        let Ok((stream, _addr)) = listener.accept().await else {
            continue;
        };
        let close_tx = close_tx.clone();
        tokio::spawn(async move {
            let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await else {
                return;
            };
            let (mut sink, mut source) = ws_stream.split();
            while let Some(Ok(msg)) = source.next().await {
                let outgoing = match msg {
                    Message::Text(text) if text == "__backend_oversized_frame__" => {
                        if sink
                            .send(Message::Frame(Frame::message(
                                vec![8u8; 10],
                                OpCode::Data(Data::Binary),
                                false,
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        Some(Message::Frame(Frame::message(
                            vec![9u8; 60],
                            OpCode::Data(Data::Continue),
                            true,
                        )))
                    }
                    Message::Text(text) => Some(Message::Text(format!("Echo: {text}").into())),
                    Message::Binary(data) => Some(Message::Text(
                        format!("Echo binary: {} bytes", data.len()).into(),
                    )),
                    Message::Ping(data) => Some(Message::Pong(data)),
                    Message::Close(Some(close)) => {
                        let _ = close_tx.send((close.code, close.reason.to_string()));
                        let _ = sink.send(Message::Close(Some(close))).await;
                        break;
                    }
                    Message::Close(None) => break,
                    _ => None,
                };
                if let Some(outgoing) = outgoing
                    && sink.send(outgoing).await.is_err()
                {
                    break;
                }
            }
        });
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
    // Fresh admin HTTP port + admin HTTPS disabled so parallel gateways in the
    // same shard never contend on the default admin ports (9000/9443); an admin
    // bind failure aborts startup. These tests do not use the admin API.
    let admin_http_port = std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);
    let cmd = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_http_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(cmd)
}

/// Wait for the gateway to become ready by sending a complete HTTP probe.
async fn wait_for_gateway(gateway_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = format!("127.0.0.1:{}", gateway_port);
    let mut last_err = String::new();

    loop {
        if Instant::now() >= deadline {
            return Err(format!("Gateway did not start within 30 seconds: {last_err}").into());
        }
        match probe_gateway_http(&addr).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_err = error.to_string();
                sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

async fn probe_gateway_http(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = tokio::time::timeout(
        Duration::from_millis(750),
        tokio::net::TcpStream::connect(addr),
    )
    .await??;
    let _ = stream.set_nodelay(true);
    tokio::time::timeout(
        Duration::from_secs(1),
        stream.write_all(
            b"GET /__ferrum_startup_probe HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        ),
    )
    .await??;
    let mut buf = [0u8; 12];
    let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await??;
    if n == 0 {
        return Err("gateway closed startup probe without a response".into());
    }
    if !buf[..n].starts_with(b"HTTP/") {
        return Err(format!(
            "gateway startup probe returned non-HTTP bytes: {:?}",
            &buf[..n]
        )
        .into());
    }
    Ok(())
}

fn child_exit_status(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("could not inspect gateway child status: {error}");
            None
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
                Ok(()) => {
                    if let Some(status) = child_exit_status(&mut child) {
                        last_err = format!("gateway exited immediately after readiness: {status}");
                        eprintln!(
                            "Gateway startup attempt {}/{} failed (port {}): {}",
                            attempt, MAX_ATTEMPTS, gateway_port, last_err
                        );
                        let _ = child.wait();
                    } else {
                        return (child, gateway_port);
                    }
                }
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
version: "1"
proxies:
  - id: "ws-echo-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
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
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;

    let (backend_close_tx, mut backend_close_rx) = mpsc::unbounded_channel();
    let echo_handle = tokio::spawn(start_ws_echo_server_recording_close(
        backend_listener,
        backend_close_tx,
    ));

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
      max_frame_bytes: 50
      max_message_bytes: 200
      close_reason: "payload exceeds gateway limit""#,
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

    // A cumulative 80-byte binary message split into two valid 40-byte frames
    // must pass. Interleaved control traffic must not reset reassembly state.
    ws.send(Message::Frame(Frame::message(
        vec![1u8; 40],
        OpCode::Data(Data::Binary),
        false,
    )))
    .await
    .expect("send first binary fragment");
    ws.send(Message::Ping(vec![7, 8, 9].into()))
        .await
        .expect("send interleaved ping");
    ws.send(Message::Frame(Frame::message(
        vec![2u8; 40],
        OpCode::Data(Data::Continue),
        true,
    )))
    .await
    .expect("send final continuation");
    let fragmented_reply = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) if text == "Echo binary: 80 bytes" => {
                    break text.to_string();
                }
                Some(Ok(Message::Pong(_))) => continue,
                other => panic!("unexpected fragmented-message reply: {other:?}"),
            }
        }
    })
    .await
    .expect("fragmented message reply timed out");
    assert_eq!(fragmented_reply, "Echo binary: 80 bytes");

    // An oversized continuation must be rejected as its own frame before the
    // partial message can be extended or forwarded.
    ws.send(Message::Frame(Frame::message(
        vec![3u8; 10],
        OpCode::Data(Data::Binary),
        false,
    )))
    .await
    .expect("send partial message before oversized continuation");
    ws.send(Message::Frame(Frame::message(
        vec![4u8; 51],
        OpCode::Data(Data::Continue),
        true,
    )))
    .await
    .expect("send oversized continuation header/payload");

    // Should receive a close frame with code 1009
    let client_close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(close @ Message::Close(_))) => break close,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => panic!("unexpected reply before policy close: {other:?}"),
            }
        }
    })
    .await
    .expect("client close timed out");
    let Message::Close(Some(client_close)) = client_close else {
        panic!("offending client did not receive detailed close");
    };
    assert_eq!(client_close.code, CloseCode::Size);
    assert_eq!(
        client_close.reason.as_str(),
        "payload exceeds gateway limit"
    );

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_close_rx.recv())
            .await
            .expect("backend close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert_eq!(backend_reason, "payload exceeds gateway limit");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_ws_message_size_limiting_e2e PASSED");
}

/// Backend-originated violations use the same strictest-instance parser limit
/// and deliver the configured 1009 details to both peers.
#[ignore]
#[tokio::test]
async fn test_ws_message_size_limiting_backend_direction_and_instances_e2e() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let (backend_close_tx, mut backend_close_rx) = mpsc::unbounded_channel();
    let echo_handle = tokio::spawn(start_ws_echo_server_recording_close(
        backend_listener,
        backend_close_tx,
    ));

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config_with_plugins(
        &config_path,
        backend_port,
        r#"  - id: "ws-size-loose"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 100
      close_reason: "loose limit"
  - id: "ws-size-strict"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 50
      max_message_bytes: 200
      close_reason: "strict proxy limit""#,
        r#"      - plugin_config_id: "ws-size-loose"
      - plugin_config_id: "ws-size-strict""#,
    );

    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let url = format!("ws://127.0.0.1:{gateway_port}/ws-echo");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect WebSocket");

    ws.send(Message::Text("__backend_oversized_frame__".into()))
        .await
        .expect("request oversized backend frame");

    let client_close = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("client close timed out")
        .expect("client stream ended before close")
        .expect("client close read failed");
    let Message::Close(Some(client_close)) = client_close else {
        panic!("client did not receive backend-policy close");
    };
    assert_eq!(client_close.code, CloseCode::Size);
    assert_eq!(client_close.reason.as_str(), "strict proxy limit");

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_close_rx.recv())
            .await
            .expect("offending backend close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert_eq!(backend_reason, "strict proxy limit");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// Continuation accumulation is bounded independently from the per-frame cap.
#[ignore]
#[tokio::test]
async fn test_ws_message_size_limiting_reassembly_bound_e2e() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let (backend_close_tx, mut backend_close_rx) = mpsc::unbounded_channel();
    let echo_handle = tokio::spawn(start_ws_echo_server_recording_close(
        backend_listener,
        backend_close_tx,
    ));

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config_with_plugins(
        &config_path,
        backend_port,
        r#"  - id: "ws-frame-limit"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 50
      max_message_bytes: 100
      close_reason: "frame limit"
  - id: "ws-message-limit"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 50
      max_message_bytes: 50
      close_reason: "reassembly limit""#,
        r#"      - plugin_config_id: "ws-frame-limit"
      - plugin_config_id: "ws-message-limit""#,
    );

    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let url = format!("ws://127.0.0.1:{gateway_port}/ws-echo");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect WebSocket");

    // Equal numeric ceilings must still retain the parser check that fired.
    // A single oversized wire frame uses the frame policy and its reason.
    ws.send(Message::Frame(Frame::message(
        vec![4u8; 51],
        OpCode::Data(Data::Binary),
        true,
    )))
    .await
    .expect("send oversized single frame");
    let close = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("frame-policy client close timed out")
        .expect("client stream ended before frame-policy close")
        .expect("frame-policy client close read failed");
    let Message::Close(Some(close)) = close else {
        panic!("client did not receive frame-policy close");
    };
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(close.reason.as_str(), "frame limit");
    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_close_rx.recv())
            .await
            .expect("frame-policy backend close timed out")
            .expect("frame-policy backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert_eq!(backend_reason, "frame limit");

    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("reconnect WebSocket for reassembly policy");

    for (opcode, final_fragment) in [
        (OpCode::Data(Data::Binary), false),
        (OpCode::Data(Data::Continue), true),
    ] {
        ws.send(Message::Frame(Frame::message(
            vec![5u8; 30],
            opcode,
            final_fragment,
        )))
        .await
        .expect("send bounded continuation fragment");
    }

    let close = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("client close timed out")
        .expect("client stream ended before close")
        .expect("client close read failed");
    let Message::Close(Some(close)) = close else {
        panic!("client did not receive reassembly close");
    };
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(close.reason.as_str(), "reassembly limit");

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_close_rx.recv())
            .await
            .expect("backend close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert_eq!(backend_reason, "reassembly limit");

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

// ============================================================================
// ws_frame_logging E2E
// ============================================================================

/// Test that ws_frame_logging doesn't interfere with normal WebSocket traffic.
#[ignore]
#[tokio::test]
async fn test_ws_frame_logging_e2e() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_listener));

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

/// Concurrent sessions must share one process-local `connection_id` between
/// frame and disconnect `ws_frame_log` events (issue #2560).
#[ignore]
#[tokio::test]
async fn test_ws_frame_logging_connection_id_correlates_frame_and_disconnect() {
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Mutex};

    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_listener));

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
      log_level: "info""#,
        r#"      - plugin_config_id: "ws-logging""#,
    );

    let admin_http_port = std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);
    let gateway_port = free_port().await;
    let log_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_lines_reader = Arc::clone(&log_lines);

    let mut gateway = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
        .env("FERRUM_PROXY_HTTP_PORT", gateway_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_http_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        // Admit info-level ws_frame_log records (frame + disconnect).
        .env("FERRUM_LOG_LEVEL", "info")
        .env("RUST_LOG", "ws_frame_log=info")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn gateway");

    let stdout = gateway.stdout.take().expect("piped stdout");
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if line.contains("ws_frame_log") || line.contains("connection_id") {
                log_lines_reader.lock().unwrap().push(line);
            }
        }
    });

    wait_for_gateway(gateway_port)
        .await
        .expect("gateway readiness");

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws_a, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect session A");
    let (mut ws_b, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect session B");

    ws_a.send(Message::Text("a1".into())).await.unwrap();
    ws_b.send(Message::Text("b1".into())).await.unwrap();
    let _ = ws_a.next().await.unwrap().unwrap();
    let _ = ws_b.next().await.unwrap().unwrap();

    ws_b.send(Message::Close(None)).await.unwrap();
    let _ = ws_b.next().await;
    ws_a.send(Message::Close(None)).await.unwrap();
    let _ = ws_a.next().await;

    // Allow disconnect hooks to flush structured logs.
    sleep(Duration::from_millis(500)).await;

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();

    let logs = log_lines.lock().unwrap().clone();
    assert!(
        !logs.is_empty(),
        "expected ws_frame_log output; got none (check FERRUM_LOG_LEVEL / RUST_LOG)"
    );

    let mut frame_ids = std::collections::HashSet::new();
    let mut disconnect_ids = std::collections::HashSet::new();
    for line in &logs {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("target").and_then(|t| t.as_str()) != Some("ws_frame_log") {
            continue;
        }
        let Some(id) = value.get("connection_id").and_then(|v| v.as_u64()) else {
            continue;
        };
        let is_disconnect = value.get("event").and_then(|e| e.as_str()) == Some("disconnect")
            || value
                .get("message")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m.contains("session ended"));
        if is_disconnect {
            disconnect_ids.insert(id);
        } else if value.get("frame_type").is_some()
            || value
                .get("message")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m.contains("WebSocket frame"))
        {
            frame_ids.insert(id);
        }
    }

    assert!(
        frame_ids.len() >= 2,
        "expected distinct frame connection_ids for concurrent sessions; frames={frame_ids:?} logs={logs:?}"
    );
    assert_eq!(
        disconnect_ids, frame_ids,
        "each session's disconnect must reuse its frame-stream connection_id; frames={frame_ids:?} disconnects={disconnect_ids:?} logs={logs:?}"
    );

    println!("test_ws_frame_logging_connection_id_correlates_frame_and_disconnect PASSED");
}

// ============================================================================
// ws_rate_limiting E2E
// ============================================================================

/// Test that frames within limit pass and frames exceeding limit trigger close.
#[ignore]
#[tokio::test]
async fn test_ws_rate_limiting_e2e() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_listener));

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
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_listener));

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
