//! Tests for ws_logging plugin

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, Plugin, PluginHttpClient, PluginResult, WsDisconnectContext,
    ws_logging::WsLogging,
};
use ferrum_edge::proxy::tcp_proxy::StreamIoSide;
use ferrum_edge::retry::ErrorClass;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing_subscriber::fmt::MakeWriter;

use super::plugin_utils::{
    create_test_context, create_test_stream_transaction_summary, create_test_transaction_summary,
};

#[derive(Clone, Default)]
struct SharedWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct SharedGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn test_ws_disconnect_context() -> WsDisconnectContext {
    let mut metadata = HashMap::new();
    metadata.insert("correlation_id".to_string(), "cid-123".to_string());
    metadata.insert("authorization".to_string(), "Bearer secret".to_string());

    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "proxy-ws".to_string(),
        proxy_name: Some("websocket-proxy".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend.local/chat".to_string(),
        listen_port: 8080,
        duration_ms: 250.0,
        frames_client_to_backend: 3,
        frames_backend_to_client: 4,
        bytes_client_to_backend: 128,
        bytes_backend_to_client: 256,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: Some(Direction::ClientToBackend),
        io_side: None,
        error_class: None,
        consumer_username: Some("alice".to_string()),
        auth_method: None,
        connection_id: 0,
        metadata,
    }
}

#[tokio::test]
async fn test_ws_logging_plugin_creation() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
    assert_eq!(plugin.priority(), 9175);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(plugin.requires_ws_disconnect_hooks());
    assert_eq!(plugin.warmup_hostnames(), vec!["localhost".to_string()]);
}

#[tokio::test]
async fn test_ws_logging_ipv6_endpoint_warmup_hostname_is_unbracketed() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://[2001:db8::1]:9300/logs"
        }),
        default_client(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::1".to_string()]);
}

#[tokio::test]
async fn test_ws_logging_plugin_creation_wss() {
    // wss:// triggers rustls ClientConfig construction, which requires
    // a crypto provider to be installed (normally done in main.rs).
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "wss://localhost:9300/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_plugin_creation_empty_config() {
    let result = WsLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(
            e.contains("endpoint_url"),
            "Expected error about endpoint_url, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when creating ws_logging without endpoint_url"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_invalid_config_shapes() {
    for config in [
        json!("not-an-object"),
        json!({"endpoint_url": 42}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "batch_size": "many"}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "flush_interval_ms": false}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "buffer_capacity": -1}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "max_retries": "3"}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "retry_delay_ms": {}}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "reconnect_delay_ms": "soon"}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "connect_timeout_ms": "slow"}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "write_timeout_ms": false}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "max_entry_bytes": 0}),
        json!({"endpoint_url": "ws://localhost:9300/logs", "buffer_max_bytes": 512}),
        json!({
            "endpoint_url": "ws://localhost:9300/logs",
            "max_entry_bytes": 1024,
            "buffer_max_bytes": 2049
        }),
        json!({
            "endpoint_url": "ws://localhost:9300/logs",
            "max_entry_bytes": 4096,
            "buffer_max_bytes": 1024
        }),
        json!({"endpoint_url": "ws://user:pass@localhost:9300/logs"}),
        json!({"endpoint_url": "ws://@localhost:9300/logs"}),
    ] {
        assert!(
            WsLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_malformed_endpoint_url() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "not a valid url"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("invalid 'endpoint_url'")),
        Ok(_) => panic!("Expected malformed endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_non_ws_scheme() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "http://127.0.0.1:9000/logs"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("ws:// or wss://")),
        Ok(_) => panic!("Expected non-ws endpoint_url to be rejected"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_tcp_scheme() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "tcp://127.0.0.1:9000/logs"
        }),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("ws:// or wss://")),
        Ok(_) => panic!("Expected tcp scheme to be rejected"),
    }
}

#[tokio::test]
async fn test_ws_logging_rejects_missing_hostname() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "ws://"
        }),
        default_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ws_logging_rejects_empty_authority_endpoint() {
    let result = WsLogging::new(
        &json!({
            "endpoint_url": "ws:///logs"
        }),
        default_client(),
    );
    let err = result.err().expect("empty authority endpoint should fail");
    assert!(
        err.contains("hostname or IP address"),
        "expected hostname validation error, got: {err}"
    );
}

#[tokio::test]
async fn test_ws_logging_log_does_not_panic() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();

    // Should not panic — entry goes into channel and is drained
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_ws_logging_ws_disconnect_does_not_panic() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 1
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let ctx = test_ws_disconnect_context();

    plugin.on_ws_disconnect(&ctx).await;
    plugin.on_ws_disconnect(&ctx).await;
}

#[tokio::test]
async fn test_ws_logging_ws_disconnect_with_auth_method() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 1
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = test_ws_disconnect_context();
    ctx.auth_method = Some("jwt_auth");

    plugin.on_ws_disconnect(&ctx).await;
}

#[tokio::test]
async fn test_ws_logging_custom_schema_applies_to_ws_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");
    let (payload_tx, payload_rx) = tokio::sync::oneshot::channel::<String>();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let (_sink, mut read) = ws.split();
        let payload = match read.next().await {
            Some(Ok(Message::Text(payload))) => payload.to_string(),
            other => panic!("expected text log batch, got {other:?}"),
        };
        let _ = payload_tx.send(payload);
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 100,
            "buffer_capacity": 16,
            "schema": {
                "summary_type": "http",
                "rename": {
                    "event": "kind",
                    "frames_client_to_backend": "upstream_frames",
                    "direction": "disconnect_direction",
                    "io_side": "failure_side"
                },
                "omit": ["frames_backend_to_client", "proxy_name"],
                "order": ["kind", "upstream_frames", "*"],
                "static_fields": { "service": "edge-ws" },
                "derived_fields": [
                    { "name": "record_type", "kind": "summary_kind" },
                    { "name": "outcome", "kind": "outcome" },
                    { "name": "backend_host", "kind": "backend_host" }
                ],
                "metadata": { "mode": "flatten", "prefix": "meta_" }
            }
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let mut ctx = test_ws_disconnect_context();
    ctx.auth_method = Some("jwt_auth");
    ctx.error_class = Some(ErrorClass::ConnectionReset);
    ctx.io_side = Some(StreamIoSide::Write);
    plugin.on_ws_disconnect(&ctx).await;

    let payload = await_within("custom-schema disconnect batch", payload_rx)
        .await
        .expect("payload channel closed");
    let batch: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON batch");
    let entry = &batch[0];

    assert_eq!(entry["kind"], "websocket_disconnect");
    assert_eq!(entry["upstream_frames"], 3);
    assert_eq!(entry["bytes_client_to_backend"], 128);
    assert_eq!(entry["bytes_backend_to_client"], 256);
    assert_eq!(entry["timestamp_connected"], "2026-01-01T00:00:00+00:00");
    assert_eq!(entry["timestamp_disconnected"], "2026-01-01T00:00:01+00:00");
    assert_eq!(entry["disconnect_direction"], "client_to_backend");
    assert_eq!(entry["failure_side"], "write");
    assert_eq!(entry["service"], "edge-ws");
    assert_eq!(entry["record_type"], "websocket_disconnect");
    assert_eq!(entry["outcome"], "error");
    assert_eq!(entry["backend_host"], "backend.local");
    assert_eq!(entry["meta_correlation_id"], "cid-123");
    assert_eq!(entry["meta_authorization"], "[REDACTED]");
    assert!(entry.get("event").is_none());
    assert!(entry.get("frames_client_to_backend").is_none());
    assert!(entry.get("frames_backend_to_client").is_none());
    assert!(entry.get("proxy_name").is_none());
    assert!(entry.get("metadata").is_none());

    drop(plugin);
    let _ = await_within("custom-schema server shutdown", server).await;
}

#[tokio::test]
async fn test_ws_logging_stream_disconnect_does_not_panic() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 1
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    plugin.on_stream_disconnect(&summary).await;
}

#[tokio::test]
async fn test_ws_logging_unreachable_endpoint_does_not_panic() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 100
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();

    plugin.log(&summary).await;

    // Give the background flush task time to attempt delivery
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
}

#[tokio::test]
async fn test_ws_logging_default_lifecycle_phases() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable"
        }),
        default_client(),
    )
    .unwrap();

    let mut ctx = create_test_context();
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_ws_logging_batch_config_defaults() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_custom_batch_config() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs",
            "batch_size": 100,
            "flush_interval_ms": 5000,
            "max_retries": 5,
            "retry_delay_ms": 2000,
            "reconnect_delay_ms": 10000,
            "buffer_capacity": 50000
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert_eq!(plugin.name(), "ws_logging");
}

#[tokio::test]
async fn test_ws_logging_buffer_accepts_multiple_entries() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_ws_logging_buffer_full_drops_gracefully() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://127.0.0.1:1/unreachable",
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        default_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let summary = create_test_transaction_summary();
    // Send more entries than buffer_capacity — excess should be dropped
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
    // Should not panic — overflow entries are dropped with a warning
}

// ============================================================================
// Drain-task regression tests (PR 852 follow-up)
//
// The plugin spawns a background task that drains the WebSocket read half so
// `tokio_tungstenite` can service Ping / Pong / server-initiated Close frames
// internally. Two invariants are tested here:
//
// 1. While the connection is alive, server-issued Pings receive a Pong back —
//    if they didn't, the server's keepalive would tear the connection down.
// 2. When the plugin is dropped, the underlying TCP stream is released
//    promptly. `futures_util::stream::split` keeps the underlying
//    `WebSocketStream` alive via a `BiLock` while either half lives, so
//    aborting the drain task on connection drop is what releases the read
//    half. Without that abort, the server-side socket would linger until the
//    OS keepalive timer fired (minutes-to-hours).
// ============================================================================

/// Wait for a tokio task with a small budget, panicking with the supplied
/// label if the future doesn't complete in time.
async fn await_within<F: std::future::Future>(label: &str, fut: F) -> F::Output {
    match tokio::time::timeout(Duration::from_secs(5), fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out waiting for {label}"),
    }
}

#[tokio::test]
async fn test_ws_logging_drain_task_replies_to_server_ping() {
    // Server: accept one connection, send a Ping, wait for the Pong reply.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");

    let (pong_tx, pong_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let (mut sink, mut read) = ws.split();

        // First inbound message is the log batch from the plugin — drop it.
        let _ = read.next().await;

        // Ask the client to keep the connection alive.
        sink.send(Message::Ping(b"ferrum-keepalive".to_vec().into()))
            .await
            .expect("send Ping");

        // The drain task should respond with a Pong carrying the same
        // payload. Anything else (or `None` / `Err`) means the read half
        // wasn't being polled.
        while let Some(msg) = read.next().await {
            if let Ok(Message::Pong(data)) = msg {
                let _ = pong_tx.send(data.to_vec());
                return;
            }
        }
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 100,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    // Trigger the first flush so the connection is established.
    plugin.log(&create_test_transaction_summary()).await;

    let pong = await_within("server Pong", pong_rx)
        .await
        .expect("Pong channel closed without a reply");
    assert_eq!(pong, b"ferrum-keepalive");

    drop(plugin);
    let _ = await_within("server shutdown", server).await;
}

#[tokio::test]
async fn test_ws_logging_drop_releases_underlying_stream() {
    // Server: accept the connection, wait for the first log frame, then sit
    // quietly with no further traffic. If the plugin's drain task is
    // properly aborted on drop, the read side returns `None` (EOF) almost
    // immediately. If the drain task lingers, the underlying TCP stream
    // stays alive via `BiLock` and the server's `read.next()` blocks until
    // the OS keepalive fires — well past the 5-second budget below.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");

    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let (_sink, mut read) = ws.split();

        // Drain everything the client sends. The plugin only writes one
        // batch then is dropped — so `read.next()` should observe EOF /
        // Close shortly after `drop(plugin)`.
        while let Some(msg) = read.next().await {
            if matches!(msg, Ok(Message::Close(_))) {
                break;
            }
            if msg.is_err() {
                break;
            }
        }
        let _ = eof_tx.send(());
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 100,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;

    // Give the flush loop a moment to actually deliver the batch so we know
    // the connection is established before we drop the plugin.
    tokio::time::sleep(Duration::from_millis(200)).await;

    drop(plugin);

    // Without the abort-on-drop fix the drain task would keep polling and
    // hold the read half alive via `BiLock`, so the server's stream would
    // not see EOF and this would time out.
    await_within("server EOF after plugin drop", eof_rx)
        .await
        .expect("server task ended without signalling EOF");
    let _ = await_within("server shutdown", server).await;
}

#[tokio::test]
async fn test_ws_logging_reconnects_after_server_close() {
    // Server: accept two connections sequentially. The first connection's
    // TCP stream is dropped immediately after the initial frame is read —
    // simulating a broken-pipe scenario. The plugin's next `send` errors,
    // which clears `Option<WsConnection>` (aborting the drain task in the
    // process) and the reconnect path establishes connection #2.
    //
    // This exercises the send-failure → reconnect path with the new
    // connection wrapper end-to-end: if the wrapper's Drop misbehaved or
    // the abort-handle plumbing was wrong, either the first reconnect
    // would hang on the lingering drain task or the second accept would
    // never arrive.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");

    let (second_tx, second_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        // First connection: read one frame, then yank the socket out from
        // under the WebSocket layer. The client's next write will surface
        // an I/O error (broken pipe / connection reset).
        let (stream, _) = listener.accept().await.expect("accept #1");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake #1");
        let (sink, mut read) = ws.split();
        let _ = read.next().await;
        drop(sink);
        drop(read);

        // Second connection: just notify and drain.
        let (stream, _) = listener.accept().await.expect("accept #2");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake #2");
        let _ = second_tx.send(());
        let (_sink, mut read) = ws.split();
        while let Some(msg) = read.next().await {
            if matches!(msg, Ok(Message::Close(_))) || msg.is_err() {
                break;
            }
        }
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 2,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    // First entry establishes connection #1.
    plugin.log(&create_test_transaction_summary()).await;
    // Wait long enough for the server to read the first frame and drop the
    // socket so the next send observes broken pipe.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Pump entries until the reconnect path runs. The first send after the
    // server drop fails (closing the stale connection), and the retry
    // budget then connects to the second listener.
    for _ in 0..5 {
        plugin.log(&create_test_transaction_summary()).await;
        // Pace above the admitted flush interval so reconnect attempts can flush.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    await_within("second accept", second_rx)
        .await
        .expect("plugin did not reconnect to the second listener");

    drop(plugin);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_ws_logging_native_disconnect_preserves_bytes_and_timestamps() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");
    let (payload_tx, payload_rx) = tokio::sync::oneshot::channel::<String>();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let (_sink, mut read) = ws.split();
        let payload = match read.next().await {
            Some(Ok(Message::Text(payload))) => payload.to_string(),
            other => panic!("expected text log batch, got {other:?}"),
        };
        let _ = payload_tx.send(payload);
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 100,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    let mut ctx = test_ws_disconnect_context();
    ctx.frames_client_to_backend = 0;
    ctx.frames_backend_to_client = 0;
    ctx.bytes_client_to_backend = 4096;
    ctx.bytes_backend_to_client = 8192;
    ctx.timestamp_connected = "2026-07-20T12:00:00+00:00".to_string();
    ctx.timestamp_disconnected = "2026-07-20T12:00:05+00:00".to_string();
    plugin.on_ws_disconnect(&ctx).await;

    let payload = await_within("native disconnect batch", payload_rx)
        .await
        .expect("payload channel closed");
    let batch: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON batch");
    let entry = &batch[0];
    assert_eq!(entry["event"], "websocket_disconnect");
    assert_eq!(entry["frames_client_to_backend"], 0);
    assert_eq!(entry["frames_backend_to_client"], 0);
    assert_eq!(entry["bytes_client_to_backend"], 4096);
    assert_eq!(entry["bytes_backend_to_client"], 8192);
    assert_eq!(entry["timestamp_connected"], "2026-07-20T12:00:00+00:00");
    assert_eq!(entry["timestamp_disconnected"], "2026-07-20T12:00:05+00:00");

    drop(plugin);
    let _ = await_within("native disconnect server shutdown", server).await;
}

#[tokio::test]
async fn test_ws_logging_connect_timeout_against_silent_tcp_peer() {
    // Accept TCP but never complete the WebSocket Upgrade. Establishment must
    // fail within connect_timeout_ms; a later accept proves the delivery worker
    // recovered enough to keep making queue progress.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");
    let (first_tx, first_rx) = tokio::sync::oneshot::channel::<()>();
    let (retry_tx, retry_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        // First TCP accept: hold the socket open without speaking Upgrade.
        let (stream1, _) = listener.accept().await.expect("accept #1");
        let _ = first_tx.send(());
        let hold = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream1);
        });

        // Second accept is the observable recovery signal: establishment timed
        // out and the worker advanced into another connect attempt.
        let (stream2, _) = listener.accept().await.expect("accept #2");
        let _ = retry_tx.send(());
        hold.abort();
        drop(stream2);
        // Absorb any further reconnect attempts without racing test teardown.
        while listener.accept().await.is_ok() {}
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 1,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "connect_timeout_ms": 200,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    await_within("silent TCP first accept", first_rx)
        .await
        .expect("peer never accepted TCP");
    await_within("silent TCP retry accept after connect_timeout", retry_rx)
        .await
        .expect("worker did not retry after Upgrade-phase connect timeout");

    // Another enqueue after bounded establishment failure proves the flush
    // loop is still consuming the queue (not permanently wedged on Upgrade).
    plugin.log(&create_test_transaction_summary()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    drop(plugin);
    server.abort();
}

#[tokio::test]
async fn test_ws_logging_write_timeout_against_slow_reader_then_recovers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    // Set this on the listener before the TCP handshake so accepted sockets
    // inherit a small receive window. Hosted runners otherwise autotune
    // loopback buffers into the multi-MiB range and never exert backpressure.
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(8 * 1024)
        .expect("cap slow-peer SO_RCVBUF");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");
    let (second_tx, second_rx) = tokio::sync::oneshot::channel::<String>();

    let server = tokio::spawn(async move {
        // First connection: handshake then stop reading so write buffers fill
        // and write_timeout_ms fires on the client.
        let (stream, _) = listener.accept().await.expect("accept #1");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake #1");
        let (_sink, _read) = ws.split();
        let stall = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        // Second connection: read the recovered batch after reconnect.
        let (stream, _) = listener.accept().await.expect("accept #2");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake #2");
        let (_sink, mut read) = ws.split();
        let payload = match read.next().await {
            Some(Ok(Message::Text(payload))) => payload.to_string(),
            other => panic!("expected recovered text batch, got {other:?}"),
        };
        let _ = second_tx.send(payload);
        stall.abort();
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 16,
            "flush_interval_ms": 100,
            "max_retries": 3,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "write_timeout_ms": 200,
            "connect_timeout_ms": 1000,
            "max_entry_bytes": 1_048_576,
            "buffer_capacity": 64,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    // Build one roughly 14 MiB batch against the capped, non-reading peer. The
    // frame exceeds the hosted Linux sender's kernel buffering, so the send
    // must block long enough for the production write timeout to invalidate
    // connection #1; the retry is the only path that can establish #2.
    let mut summary = create_test_transaction_summary();
    summary.request_path = format!("/{}", "x".repeat(900_000));
    for _ in 0..16 {
        plugin.log(&summary).await;
    }

    let payload = await_within("recovered batch after write timeout", second_rx)
        .await
        .expect("plugin did not recover onto a fresh connection");
    let batch: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
    assert!(batch.as_array().is_some_and(|a| !a.is_empty()));

    drop(plugin);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_ws_logging_application_frame_invalidates_and_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");
    let (second_tx, second_rx) = tokio::sync::oneshot::channel::<()>();
    let (pong_tx, pong_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

    let server = tokio::spawn(async move {
        // Generation 1: Text application ack. Keep the socket open so a hard
        // TCP close cannot be mistaken for the invalidation signal; only the
        // drain-completion path may cause a prompt reconnect.
        let stale_gen1 = {
            let (stream, _) = listener.accept().await.expect("accept #1");
            let ws = tokio_tungstenite::accept_async(stream)
                .await
                .expect("handshake #1");
            let (mut sink, mut read) = ws.split();
            let _ = read.next().await;
            sink.send(Message::Text("ack".into()))
                .await
                .expect("send ack");
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sink);
                drop(read);
            })
        };

        // Generation 2: after Text-ack invalidation/reconnect, Ping must get a Pong.
        let (stream, _) = listener.accept().await.expect("accept #2");
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake #2");
        let (mut sink, mut read) = ws.split();
        let _ = second_tx.send(());
        let _ = read.next().await;
        sink.send(Message::Ping(b"alive".to_vec().into()))
            .await
            .expect("send Ping");
        while let Some(msg) = read.next().await {
            if let Ok(Message::Pong(data)) = msg {
                let _ = pong_tx.send(data.to_vec());
                break;
            }
        }

        stale_gen1.abort();
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 2,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    // Establish gen1 (Text ack), then pump until gen2 appears while gen1 stays
    // physically open. Reconnect must be driven by drain-completion notification.
    plugin.log(&create_test_transaction_summary()).await;
    for _ in 0..6 {
        plugin.log(&create_test_transaction_summary()).await;
        // Pace above the admitted flush interval so reconnect attempts can flush.
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    await_within("reconnect after application frame", second_rx)
        .await
        .expect("plugin did not reconnect after Text acknowledgement");
    let pong = await_within("Pong on fresh connection", pong_rx)
        .await
        .expect("fresh connection did not answer Ping");
    assert_eq!(pong, b"alive");

    drop(plugin);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_ws_logging_connect_timeout_against_silent_tls_peer() {
    // WSS peer accepts TCP but withholds TLS handshake progress. The same
    // connect_timeout_ms bound must cover the TLS phase; a later accept proves
    // the delivery worker recovered enough to keep making queue progress.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("wss://{addr}/logs");
    let (first_tx, first_rx) = tokio::sync::oneshot::channel::<()>();
    let (retry_tx, retry_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        // First TCP accept: hold the socket open without speaking TLS.
        let (stream1, _) = listener.accept().await.expect("accept #1");
        let _ = first_tx.send(());
        let hold = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream1);
        });

        // Second accept is the observable recovery signal: establishment timed
        // out and the worker advanced into another connect attempt.
        let (stream2, _) = listener.accept().await.expect("accept #2");
        let _ = retry_tx.send(());
        hold.abort();
        drop(stream2);
        // Absorb any further reconnect attempts without racing test teardown.
        while listener.accept().await.is_ok() {}
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 1,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "connect_timeout_ms": 200,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    await_within("silent TLS first accept", first_rx)
        .await
        .expect("TLS-silent peer never accepted TCP");
    await_within("silent TLS retry accept after connect_timeout", retry_rx)
        .await
        .expect("worker did not retry after TLS-phase connect timeout");

    // Another enqueue after bounded establishment failure proves the flush
    // loop is still consuming the queue (not permanently wedged on TLS).
    plugin.log(&create_test_transaction_summary()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    drop(plugin);
    server.abort();
}

#[tokio::test]
async fn test_ws_logging_binary_and_repeated_ack_generations() {
    // Extend beyond a single Text acknowledgement: Binary then Text acks across
    // reconnect generations, with a stale first socket kept alive server-side,
    // then Ping/Pong + Close on the latest generation. Proves delivery keeps
    // moving and control-frame ownership stays on the selected generation.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("ws://{addr}/logs");
    let (gen2_tx, gen2_rx) = tokio::sync::oneshot::channel::<()>();
    let (gen3_tx, gen3_rx) = tokio::sync::oneshot::channel::<()>();
    let (pong_tx, pong_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        // Generation 1: Binary application ack. Keep the socket open so a hard
        // TCP close cannot be mistaken for the invalidation signal.
        let stale_gen1 = {
            let (stream, _) = listener.accept().await.expect("accept #1");
            let ws = tokio_tungstenite::accept_async(stream)
                .await
                .expect("handshake #1");
            let (mut sink, mut read) = ws.split();
            let _ = read.next().await;
            sink.send(Message::Binary(b"ack-bin".to_vec().into()))
                .await
                .expect("send Binary ack");
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sink);
                drop(read);
            })
        };

        // Generation 2: Text ack on the next reconnect generation.
        let stale_gen2 = {
            let (stream, _) = listener.accept().await.expect("accept #2");
            let _ = gen2_tx.send(());
            let ws = tokio_tungstenite::accept_async(stream)
                .await
                .expect("handshake #2");
            let (mut sink, mut read) = ws.split();
            let _ = read.next().await;
            sink.send(Message::Text("ack-text".into()))
                .await
                .expect("send Text ack");
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sink);
                drop(read);
            })
        };

        // Generation 3: fresh drain must answer Ping and observe Close.
        {
            let (stream, _) = listener.accept().await.expect("accept #3");
            let _ = gen3_tx.send(());
            let ws = tokio_tungstenite::accept_async(stream)
                .await
                .expect("handshake #3");
            let (mut sink, mut read) = ws.split();
            let _ = read.next().await;
            sink.send(Message::Ping(b"gen3-alive".to_vec().into()))
                .await
                .expect("send Ping on gen3");
            let mut pong_tx = Some(pong_tx);
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Pong(data)) => {
                        if let Some(pong_tx) = pong_tx.take() {
                            let _ = pong_tx.send(data.to_vec());
                            let _ = sink.send(Message::Close(None)).await;
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => {
                        let _ = close_tx.send(());
                        break;
                    }
                    _ => {}
                }
            }
        }

        stale_gen1.abort();
        stale_gen2.abort();
    });

    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 2,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "buffer_capacity": 32,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    // Establish gen1 (Binary ack), then pump until gen2 appears.
    plugin.log(&create_test_transaction_summary()).await;
    for _ in 0..6 {
        plugin.log(&create_test_transaction_summary()).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    await_within("reconnect generation #2 after Binary ack", gen2_rx)
        .await
        .expect("plugin did not reconnect after Binary acknowledgement");

    // Pump again across the Text-ack invalidation until gen3 appears.
    for _ in 0..6 {
        plugin.log(&create_test_transaction_summary()).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    await_within("reconnect generation #3 after repeated acks", gen3_rx)
        .await
        .expect("plugin stopped delivering across repeated ack generations");

    let pong = await_within("Pong on generation #3", pong_rx)
        .await
        .expect("latest generation did not answer Ping");
    assert_eq!(pong, b"gen3-alive");
    await_within("Close observed on generation #3", close_rx)
        .await
        .expect("latest generation did not observe server Close");

    drop(plugin);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_ws_logging_diagnostics_redact_endpoint_path_and_query() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let path_secret = "path-token-secret-canary";
    let query_secret = "query-token-secret-canary";
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": format!(
                "ws://127.0.0.1:1/{path_secret}/ingest?token={query_secret}"
            ),
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "reconnect_delay_ms": 50,
            "connect_timeout_ms": 100,
        }),
        default_client(),
    )
    .expect("build plugin");
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;
    // Poll long enough for admitted flush_interval_ms plus connect_timeout_ms.
    for _ in 0..150 {
        let logs = writer.contents();
        if logs.contains("failed to connect") || logs.contains("connect timeout") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(plugin);
    drop(guard);

    let logs = writer.contents();
    assert!(
        logs.contains("ws://127.0.0.1:1/redacted") || logs.contains("/redacted"),
        "expected redacted endpoint form in diagnostics: {logs}"
    );
    assert!(
        !logs.contains(path_secret),
        "path credential leaked in diagnostics: {logs}"
    );
    assert!(
        !logs.contains(query_secret),
        "query credential leaked in diagnostics: {logs}"
    );
}

#[tokio::test]
async fn test_ws_logging_accepts_timeout_and_budget_config() {
    let plugin = WsLogging::new(
        &json!({
            "endpoint_url": "ws://localhost:9300/logs",
            "connect_timeout_ms": 2500,
            "write_timeout_ms": 2500,
            "max_entry_bytes": 8192,
            "buffer_max_bytes": 65536,
            "buffer_capacity": 128,
        }),
        default_client(),
    )
    .expect("valid timeout/budget config");
    assert_eq!(plugin.name(), "ws_logging");
}
