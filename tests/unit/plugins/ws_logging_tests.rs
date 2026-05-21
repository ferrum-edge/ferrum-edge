//! Tests for ws_logging plugin

use std::collections::HashMap;
use std::time::Duration;

use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, Plugin, PluginHttpClient, PluginResult, WsDisconnectContext,
    ws_logging::WsLogging,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::Message;

use super::plugin_utils::{
    create_test_context, create_test_stream_transaction_summary, create_test_transaction_summary,
};

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
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: Some(Direction::ClientToBackend),
        io_side: None,
        error_class: None,
        consumer_username: Some("alice".to_string()),
        auth_method: None,
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
    let mut ctx = test_ws_disconnect_context();
    ctx.auth_method = Some("jwt_auth");

    plugin.on_ws_disconnect(&ctx).await;
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
            "flush_interval_ms": 50,
            "max_retries": 2,
            "retry_delay_ms": 50,
            "reconnect_delay_ms": 50,
            "buffer_capacity": 16,
        }),
        default_client(),
    )
    .expect("build plugin");

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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    await_within("second accept", second_rx)
        .await
        .expect("plugin did not reconnect to the second listener");

    drop(plugin);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
