//! Functional tests for WebSocket frame-level plugins.
//!
//! Tests the three WS frame plugins end-to-end through a real gateway binary:
//! - ws_message_size_limiting: enforces max frame sizes (close code 1009)
//! - ws_frame_logging: logs frame metadata (doesn't interfere with traffic)
//! - ws_rate_limiting: rate limits frames per connection (close code 1008)
//!
//! All tests are #[ignore] — run with:
//!   cargo test --test functional_tests functional_ws_plugins -- --ignored --nocapture

use crate::common::{TestGateway, TestGatewayBuilder};

use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};

// ============================================================================
// Helpers
// ============================================================================

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

fn ws_plugins_config_yaml(
    backend_port: u16,
    plugin_configs_yaml: &str,
    proxy_plugins_yaml: &str,
) -> String {
    format!(
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
    )
}

fn ws_plugins_gateway_builder(
    backend_port: u16,
    plugin_configs_yaml: &str,
    proxy_plugins_yaml: &str,
) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(ws_plugins_config_yaml(
            backend_port,
            plugin_configs_yaml,
            proxy_plugins_yaml,
        ))
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
}

async fn spawn_ws_plugins_gateway(
    backend_port: u16,
    plugin_configs_yaml: &str,
    proxy_plugins_yaml: &str,
) -> TestGateway {
    ws_plugins_gateway_builder(backend_port, plugin_configs_yaml, proxy_plugins_yaml)
        .spawn()
        .await
        .expect("spawn ws plugins gateway")
}

fn ws_frame_log_connection_ids(output: &str) -> (HashSet<u64>, HashSet<u64>) {
    let mut frame_ids = HashSet::new();
    let mut disconnect_ids = HashSet::new();
    for line in output.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("target").and_then(|target| target.as_str()) != Some("ws_frame_log") {
            continue;
        }
        let fields = value.get("fields").unwrap_or(&value);
        let Some(id) = fields.get("connection_id").and_then(|value| value.as_u64()) else {
            continue;
        };
        let is_disconnect = fields.get("event").and_then(|event| event.as_str())
            == Some("disconnect")
            || fields
                .get("message")
                .and_then(|message| message.as_str())
                .is_some_and(|message| message.contains("session ended"));
        if is_disconnect {
            disconnect_ids.insert(id);
        } else if fields.get("frame_type").is_some()
            || fields
                .get("message")
                .and_then(|message| message.as_str())
                .is_some_and(|message| message.contains("WebSocket frame"))
        {
            frame_ids.insert(id);
        }
    }
    (frame_ids, disconnect_ids)
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

    let gateway = spawn_ws_plugins_gateway(
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
    )
    .await;
    let gateway_port = gateway.proxy_port;

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

    let gateway = spawn_ws_plugins_gateway(
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
    )
    .await;
    let gateway_port = gateway.proxy_port;
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

    let gateway = spawn_ws_plugins_gateway(
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
    )
    .await;
    let gateway_port = gateway.proxy_port;
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

    let gateway = spawn_ws_plugins_gateway(
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
    )
    .await;
    let gateway_port = gateway.proxy_port;

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

    echo_handle.abort();
    println!("test_ws_frame_logging_e2e PASSED");
}

/// Concurrent sessions must share one process-local `connection_id` between
/// frame and disconnect `ws_frame_log` events (issue #2560).
#[ignore]
#[tokio::test]
async fn test_ws_frame_logging_connection_id_correlates_frame_and_disconnect() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_listener));

    let gateway = ws_plugins_gateway_builder(
        backend_port,
        r#"  - id: "ws-logging"
    plugin_name: "ws_frame_logging"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      log_level: "info""#,
        r#"      - plugin_config_id: "ws-logging""#,
    )
    .capture_output()
    .env("RUST_LOG", "ws_frame_log=info")
    .spawn()
    .await
    .expect("spawn ws frame logging gateway");
    let gateway_port = gateway.proxy_port;

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

    let captured = gateway
        .wait_for_captured_output(
            |output| {
                let (frame_ids, disconnect_ids) = ws_frame_log_connection_ids(output);
                frame_ids.len() >= 2 && disconnect_ids == frame_ids
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap_or_default();
    let logs: Vec<String> = captured
        .lines()
        .filter(|line| line.contains("ws_frame_log") || line.contains("connection_id"))
        .map(str::to_string)
        .collect();
    echo_handle.abort();

    assert!(
        !logs.is_empty(),
        "expected ws_frame_log output; got none (check FERRUM_LOG_LEVEL / RUST_LOG)"
    );

    let (frame_ids, disconnect_ids) = ws_frame_log_connection_ids(&captured);

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

/// Peer Close must produce a delivered `frame_type=close` record with code /
/// reason length (never raw reason), and the disconnect record must carry
/// success-only byte totals plus `io_side` (issues #2554 / #2556 / #2563).
#[ignore]
#[tokio::test]
async fn test_ws_frame_logging_peer_close_and_disconnect_fields() {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_listener));

    let gateway = ws_plugins_gateway_builder(
        backend_port,
        r#"  - id: "ws-logging"
    plugin_name: "ws_frame_logging"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      log_level: "info""#,
        r#"      - plugin_config_id: "ws-logging""#,
    )
    .capture_output()
    .env("RUST_LOG", "ws_frame_log=info")
    .spawn()
    .await
    .expect("spawn ws frame logging gateway");
    let gateway_port = gateway.proxy_port;

    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    ws.send(Message::Text("hello-close".into()))
        .await
        .expect("send text");
    let _ = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("echo timeout")
        .expect("echo stream ended")
        .expect("echo error");

    let secret_reason = "password=should-never-appear-in-logs";
    ws.send(Message::Close(Some(CloseFrame {
        code: CloseCode::Normal,
        reason: secret_reason.into(),
    })))
    .await
    .expect("send close");
    // Drain until the peer acknowledges close / stream ends.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = ws.next().await {}
    })
    .await;

    let captured = gateway
        .wait_for_captured_output(
            |output| {
                let close_delivered = output.lines().any(|line| {
                    line.contains("ws_frame_log")
                        && line.contains("frame_type")
                        && line.contains("close")
                        && line.contains("outcome")
                        && line.contains("delivered")
                        && line.contains("close_code")
                        && line.contains("1000")
                });
                let disconnect_complete = output.lines().any(|line| {
                    line.contains("ws_frame_log")
                        && line.contains("event")
                        && line.contains("disconnect")
                        && line.contains("bytes_c2b")
                        && line.contains("bytes_b2c")
                        && line.contains("io_side")
                        && line.contains("frames_c2b")
                });
                close_delivered && disconnect_complete
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap_or_default();
    let logs: Vec<String> = captured
        .lines()
        .filter(|line| line.contains("ws_frame_log"))
        .map(str::to_string)
        .collect();
    let close_lines: Vec<_> = logs
        .iter()
        .filter(|line| line.contains("frame_type") && line.contains("close"))
        .cloned()
        .collect();
    assert!(
        !close_lines.is_empty(),
        "expected a delivered close frame log; logs={logs:?}"
    );
    assert!(
        close_lines.iter().any(|line| {
            line.contains("outcome")
                && line.contains("delivered")
                && line.contains("close_code")
                && line.contains("1000")
        }),
        "close log must carry outcome=delivered and close_code=1000; close_lines={close_lines:?}"
    );
    assert!(
        logs.iter()
            .all(|line| !line.contains("should-never-appear")),
        "raw Close reason must never appear in logs; logs={logs:?}"
    );

    let disconnect_lines: Vec<_> = logs
        .iter()
        .filter(|line| line.contains("event") && line.contains("disconnect"))
        .cloned()
        .collect();
    assert!(
        !disconnect_lines.is_empty(),
        "expected a disconnect record; logs={logs:?}"
    );
    assert!(
        disconnect_lines.iter().any(|line| {
            line.contains("bytes_c2b")
                && line.contains("bytes_b2c")
                && line.contains("io_side")
                && line.contains("frames_c2b")
        }),
        "disconnect must expose success-only byte totals and io_side; disconnect_lines={disconnect_lines:?}"
    );

    echo_handle.abort();
    println!("test_ws_frame_logging_peer_close_and_disconnect_fields PASSED");
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

    let gateway = spawn_ws_plugins_gateway(
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
    )
    .await;
    let gateway_port = gateway.proxy_port;

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

    let gateway = spawn_ws_plugins_gateway(
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
    )
    .await;
    let gateway_port = gateway.proxy_port;

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

    echo_handle.abort();
    println!("test_ws_combined_plugins_e2e PASSED");
}

/// Exhaust the rate bucket, then violate the size limit. The parser-level 1009
/// Close must win; the later rate limiter must not rewrite it to 1008.
#[ignore]
#[tokio::test]
async fn test_ws_size_rejection_preserved_over_exhausted_rate_limiter_e2e() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let (backend_close_tx, mut backend_close_rx) = mpsc::unbounded_channel();
    let echo_handle = tokio::spawn(start_ws_echo_server_recording_close(
        backend_listener,
        backend_close_tx,
    ));

    let gateway = spawn_ws_plugins_gateway(
        backend_port,
        r#"  - id: "ws-size"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 16
      close_reason: "message too large"
  - id: "ws-rate"
    plugin_name: "ws_rate_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      frames_per_second: 1
      burst_size: 2
      close_reason: "frame rate exceeded""#,
        r#"      - plugin_config_id: "ws-size"
      - plugin_config_id: "ws-rate""#,
    )
    .await;
    let gateway_port = gateway.proxy_port;
    let url = format!("ws://127.0.0.1:{gateway_port}/ws-echo");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect WebSocket");

    // Consume both connection-wide rate tokens with the small request and its
    // backend-to-client echo, leaving the bucket exhausted in both directions.
    ws.send(Message::Text("ok".into()))
        .await
        .expect("send small frame");
    let reply = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("echo timed out")
        .expect("stream ended before echo")
        .expect("echo read failed");
    assert_eq!(reply, Message::Text("Echo: ok".into()));

    // Oversized frame: parser-level size policy closes with 1009 before any
    // post-reassembly rate accounting can rewrite the terminal Close.
    ws.send(Message::Text("this payload exceeds sixteen".into()))
        .await
        .expect("send oversized frame");

    let client_close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(close @ Message::Close(_))) => break close,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => panic!("unexpected reply before size close: {other:?}"),
            }
        }
    })
    .await
    .expect("client close timed out");
    let Message::Close(Some(client_close)) = client_close else {
        panic!("client did not receive detailed size close");
    };
    assert_eq!(
        client_close.code,
        CloseCode::Size,
        "1009 size rejection must not become 1008"
    );
    assert_eq!(client_close.reason.as_str(), "message too large");

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_close_rx.recv())
            .await
            .expect("backend close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert_eq!(backend_reason, "message too large");

    echo_handle.abort();
    println!("test_ws_size_rejection_preserved_over_exhausted_rate_limiter_e2e PASSED");
}

/// Backend-originated oversized frames with an exhausted rate bucket still
/// close both peers with 1009 through the shared relay.
#[ignore]
#[tokio::test]
async fn test_ws_size_rejection_preserved_over_rate_limiter_backend_direction_e2e() {
    let (backend_port, backend_listener) = bind_ws_backend_listener().await;
    let (backend_close_tx, mut backend_close_rx) = mpsc::unbounded_channel();
    let echo_handle = tokio::spawn(start_ws_echo_server_recording_close(
        backend_listener,
        backend_close_tx,
    ));

    let gateway = spawn_ws_plugins_gateway(
        backend_port,
        r#"  - id: "ws-size"
    plugin_name: "ws_message_size_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      max_frame_bytes: 16
      close_reason: "message too large"
  - id: "ws-rate"
    plugin_name: "ws_rate_limiting"
    scope: "proxy"
    proxy_id: "ws-echo-proxy"
    enabled: true
    config:
      frames_per_second: 1
      burst_size: 3
      close_reason: "frame rate exceeded""#,
        r#"      - plugin_config_id: "ws-size"
      - plugin_config_id: "ws-rate""#,
    )
    .await;
    let gateway_port = gateway.proxy_port;
    let url = format!("ws://127.0.0.1:{gateway_port}/ws-echo");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect WebSocket");

    // The shared bucket counts both directions. The small request and echo use
    // two tokens; the trigger request below uses the third, so the backend's
    // oversized response reaches parser-level size rejection with no rate
    // budget left to overwrite its terminal 1009 decision.
    ws.send(Message::Text("ok".into()))
        .await
        .expect("send small frame");
    let reply = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("echo timed out")
        .expect("stream ended before echo")
        .expect("echo read failed");
    assert_eq!(reply, Message::Text("Echo: ok".into()));

    ws.send(Message::Text("__backend_oversized_frame__".into()))
        .await
        .expect("request oversized backend frame");

    let client_close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(close @ Message::Close(_))) => break close,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Text(_))) => continue,
                other => panic!("unexpected reply before size close: {other:?}"),
            }
        }
    })
    .await
    .expect("client close timed out");
    let Message::Close(Some(client_close)) = client_close else {
        panic!("client did not receive detailed size close");
    };
    assert_eq!(client_close.code, CloseCode::Size);
    assert_eq!(client_close.reason.as_str(), "message too large");

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_close_rx.recv())
            .await
            .expect("backend close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert_eq!(backend_reason, "message too large");

    echo_handle.abort();
}
