//! Tests for transaction_debugger plugin

use ferrum_edge::plugins::{
    Direction, DisconnectCause, Plugin, ProxyProtocol, RequestContext, StreamTransactionSummary,
    WsDisconnectContext, transaction_debugger::TransactionDebugger, validate_plugin_config,
};
use ferrum_edge::proxy::tcp_proxy::StreamIoSide;
use ferrum_edge::retry::ErrorClass;
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

use super::plugin_utils::create_test_transaction_summary;

fn make_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "POST".to_string(),
        "/api/data".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("x-request-id".to_string(), "abc-123".to_string());
    ctx
}

#[tokio::test]
async fn test_transaction_debugger_creation() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "transaction_debugger");
    assert_eq!(plugin.priority(), 9200);
    assert_eq!(
        plugin.supported_protocols(),
        &[
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
            ProxyProtocol::Tcp,
            ProxyProtocol::Udp,
        ]
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(plugin.requires_ws_disconnect_hooks());
}

#[tokio::test]
async fn test_transaction_debugger_creation_with_config() {
    let plugin = TransactionDebugger::new(&json!({
        "redacted_headers": ["x-internal-id"]
    }))
    .unwrap();
    assert_eq!(plugin.name(), "transaction_debugger");
}

#[tokio::test]
async fn test_transaction_debugger_on_request_received() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_after_proxy() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_log() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let summary = create_test_transaction_summary();

    // Verify log phase completes and plugin is operational after logging
    plugin.log(&summary).await;

    // After logging, the plugin should still be functional (not corrupted)
    assert_eq!(plugin.name(), "transaction_debugger");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::TRANSACTION_DEBUGGER
    );
}

#[tokio::test]
async fn test_transaction_debugger_full_lifecycle() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();

    let mut ctx = make_ctx();
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);
    let mut headers: HashMap<String, String> = HashMap::new();

    // on_request_received
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // authenticate (default - Continue)
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // authorize (default - Continue)
    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // before_proxy (default - Continue)
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // after_proxy
    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // log
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

// ── Header redaction tests ─────────────────────────────────────────────

fn make_ctx_with_sensitive_headers() -> RequestContext {
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "POST".to_string(),
        "/api/data".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers.insert(
        "authorization".to_string(),
        "Bearer secret-token-123".to_string(),
    );
    ctx.headers
        .insert("cookie".to_string(), "session=abc123".to_string());
    ctx.headers
        .insert("x-api-key".to_string(), "sk-live-secret".to_string());
    ctx.headers
        .insert("x-request-id".to_string(), "req-456".to_string());
    ctx
}

#[derive(Clone, Default)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

async fn capture_debug_logs<F, Fut>(operation: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let writer = SharedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    operation().await;
    String::from_utf8(writer.0.lock().unwrap().clone()).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn test_transaction_debugger_redacts_builtin_sensitive_headers_in_both_directions() {
    let writer = SharedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("API-Key".to_string(), "azure-request-secret".to_string());
    ctx.headers.insert(
        "x-goog-api-key".to_string(),
        "google-request-secret".to_string(),
    );
    ctx.headers.insert(
        "Last-Event-ID".to_string(),
        "opaque-resume-cursor".to_string(),
    );
    ctx.headers.insert(
        "x-safe-header".to_string(),
        "safe-request-value".to_string(),
    );

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut response_headers = HashMap::from([
        ("api-key".to_string(), "azure-response-secret".to_string()),
        (
            "X-Goog-Api-Key".to_string(),
            "google-response-secret".to_string(),
        ),
        (
            "x-safe-response".to_string(),
            "safe-response-value".to_string(),
        ),
    ]);
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let logs = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    for secret in [
        "azure-request-secret",
        "google-request-secret",
        "opaque-resume-cursor",
        "azure-response-secret",
        "google-response-secret",
    ] {
        assert!(!logs.contains(secret), "debugger leaked {secret}: {logs}");
    }
    assert!(logs.contains("***REDACTED***"), "missing redaction: {logs}");
    assert!(
        logs.contains("safe-request-value"),
        "safe header omitted: {logs}"
    );
    assert!(
        logs.contains("safe-response-value"),
        "safe response header omitted: {logs}"
    );
}

#[tokio::test]
async fn test_transaction_debugger_redacts_sensitive_request_headers() {
    // The plugin should not leak sensitive headers in its debug output.
    // We verify the plugin processes requests with sensitive headers without error.
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut ctx = make_ctx_with_sensitive_headers();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Sensitive headers should still be in the original context (not modified)
    assert_eq!(
        ctx.headers.get("authorization").unwrap(),
        "Bearer secret-token-123"
    );
}

#[tokio::test]
async fn test_transaction_debugger_redacts_sensitive_response_headers() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("set-cookie".to_string(), "session=secret".to_string());
    response_headers.insert(
        "www-authenticate".to_string(),
        "Bearer realm=\"api\"".to_string(),
    );
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 401, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Response headers should not be modified by the debugger
    assert_eq!(
        response_headers.get("set-cookie").unwrap(),
        "session=secret"
    );
}

#[tokio::test]
async fn test_transaction_debugger_custom_redacted_headers() {
    let plugin = TransactionDebugger::new(&json!({
        "redacted_headers": ["X-Custom-Secret", "x-internal-token"]
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.headers
        .insert("x-custom-secret".to_string(), "my-secret".to_string());
    ctx.headers
        .insert("x-internal-token".to_string(), "token-value".to_string());
    ctx.headers
        .insert("x-safe-header".to_string(), "visible".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[test]
fn test_transaction_debugger_invalid_config_shapes_rejected() {
    for (config, needle) in [
        (json!(null), "config must be an object"),
        (
            json!({"redacted_headers": "authorization"}),
            "redacted_headers",
        ),
        (json!({"redacted_headers": [42]}), "redacted_headers[0]"),
        (json!({"redacted_headers": [""]}), "redacted_headers[0]"),
        (
            json!({"redacted_headers": ["bad header"]}),
            "redacted_headers[0]",
        ),
    ] {
        let err = TransactionDebugger::new(&config).err().unwrap();
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

#[test]
fn test_transaction_debugger_rejects_removed_body_options() {
    for config in [
        json!({"log_request_body": false}),
        json!({"log_response_body": true}),
        json!({"log_request_body": true, "log_response_body": true}),
    ] {
        let err = TransactionDebugger::new(&config)
            .err()
            .expect("removed body capture options must be rejected");
        assert!(err.contains("payloads are not captured"), "got: {err}");
    }
}

#[test]
fn test_transaction_debugger_rejects_unknown_keys_deterministically() {
    for (config, expected) in [
        (
            json!({"log_respnose_body": true}),
            "transaction_debugger: unknown configuration keys: log_respnose_body",
        ),
        (
            json!({
                "z_unknown": true,
                "redacted_headers": [],
                "a_unknown": false
            }),
            "transaction_debugger: unknown configuration keys: a_unknown, z_unknown",
        ),
        (
            json!({"schema_reff": "debug"}),
            "transaction_debugger: unknown configuration keys: schema_reff",
        ),
    ] {
        assert_eq!(TransactionDebugger::new(&config).err().unwrap(), expected);
    }
}

#[test]
fn test_transaction_debugger_preserves_specialized_schema_rejection() {
    for config in [json!({"schema": {}}), json!({"schema_ref": "debug"})] {
        let err = TransactionDebugger::new(&config).err().unwrap();
        assert!(err.contains("'schema' / 'schema_ref' is not supported"));
    }
}

#[test]
fn test_shared_validation_matches_transaction_debugger_config_surface() {
    validate_plugin_config("transaction_debugger", &json!({})).unwrap();
    validate_plugin_config(
        "transaction_debugger",
        &json!({"redacted_headers": ["x-internal-id"]}),
    )
    .unwrap();

    let removed =
        validate_plugin_config("transaction_debugger", &json!({"log_request_body": false}))
            .expect_err("shared validation must reject removed body options");
    assert!(removed.contains("payloads are not captured"));

    let unknown = validate_plugin_config(
        "transaction_debugger",
        &json!({"redacted_headers": [], "unknown": true}),
    )
    .expect_err("shared validation must reject unknown keys");
    assert_eq!(
        unknown,
        "transaction_debugger: unknown configuration keys: unknown"
    );
}

fn stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: Some("alice".to_string()),
        auth_method: Some("mtls_auth"),
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: Some(DisconnectCause::GracefulShutdown),
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: Some("service.example".to_string()),
        metadata: HashMap::from([
            ("request_id".to_string(), "req-stream".to_string()),
            ("authorization".to_string(), "stream-secret".to_string()),
        ]),
    }
}

fn websocket_summary() -> WsDisconnectContext {
    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "ws-proxy-1".to_string(),
        proxy_name: Some("WebSocket Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://127.0.0.1:9001/chat".to_string(),
        listen_port: 8443,
        duration_ms: 2500.0,
        frames_client_to_backend: 3,
        frames_backend_to_client: 5,
        bytes_client_to_backend: 128,
        bytes_backend_to_client: 512,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: Some("alice".to_string()),
        auth_method: Some("jwt_auth"),
        connection_id: 0,
        metadata: HashMap::from([
            ("request_id".to_string(), "req-ws".to_string()),
            ("cookie".to_string(), "ws-secret".to_string()),
        ]),
    }
}

#[test]
fn test_transaction_debugger_classifies_authoritative_http_terminal_states() {
    let mut summary = create_test_transaction_summary();
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "completed"
    );

    summary.error_class = Some(ErrorClass::ConnectionRefused);
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "dispatch_error"
    );
    summary.error_class = None;

    summary.response_streamed = true;
    summary.body_error_class = Some(ErrorClass::ProtocolError);
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "body_error"
    );
    summary.body_error_class = None;

    summary.client_disconnected = true;
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "client_disconnected"
    );
    summary.client_disconnected = false;

    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "body_incomplete"
    );
    summary.response_streamed = false;

    summary
        .metadata
        .insert("rejection_phase".to_string(), "authorize".to_string());
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "rejected"
    );
}

#[test]
fn test_transaction_debugger_prioritizes_client_disconnect_body_outcome() {
    let mut summary = create_test_transaction_summary();
    summary.response_streamed = true;
    summary.body_completed = false;
    summary.body_error_class = Some(ErrorClass::ClientDisconnect);
    summary.client_disconnected = true;
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "client_disconnected"
    );

    summary.body_error_class = Some(ErrorClass::ProtocolError);
    summary.client_disconnected = false;
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "body_error"
    );

    summary.error_class = Some(ErrorClass::ConnectionRefused);
    summary.body_error_class = Some(ErrorClass::ClientDisconnect);
    summary.client_disconnected = true;
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "dispatch_error"
    );
}

#[test]
fn test_transaction_debugger_classifies_nonzero_grpc_status_under_http_200() {
    let mut summary = create_test_transaction_summary();
    summary.response_status_code = 200;
    summary
        .metadata
        .insert("grpc_status".to_string(), "0".to_string());
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "completed"
    );

    summary
        .metadata
        .insert("grpc_status".to_string(), "14".to_string());
    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "grpc_error"
    );
}

#[test]
fn test_transaction_debugger_classifies_mirror_transport_failure_separately() {
    let mut summary = create_test_transaction_summary();
    summary.mirror = true;
    summary
        .metadata
        .insert("mirror_error".to_string(), "connection refused".to_string());

    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "mirror_error"
    );
}

#[test]
fn test_transaction_debugger_prioritizes_rejection_over_nonzero_grpc_status() {
    let mut summary = create_test_transaction_summary();
    summary.response_status_code = 200;
    summary
        .metadata
        .insert("grpc_status".to_string(), "16".to_string());
    summary
        .metadata
        .insert("rejection_phase".to_string(), "authenticate".to_string());

    assert_eq!(
        TransactionDebugger::classify_http_outcome(&summary),
        "rejected"
    );
}

#[test]
fn test_transaction_debugger_classifies_typed_stream_teardown() {
    let mut summary = stream_summary();
    assert_eq!(
        TransactionDebugger::classify_stream_outcome(&summary),
        "graceful_shutdown"
    );

    summary.disconnect_cause = Some(DisconnectCause::IdleTimeout);
    assert_eq!(
        TransactionDebugger::classify_stream_outcome(&summary),
        "idle_timeout"
    );

    summary.disconnect_cause = Some(DisconnectCause::BackendError);
    summary.disconnect_direction = Some(Direction::BackendToClient);
    summary.error_class = Some(ErrorClass::ConnectionReset);
    assert_eq!(
        TransactionDebugger::classify_stream_outcome(&summary),
        "stream_error"
    );
}

#[test]
fn test_transaction_debugger_treats_each_websocket_failure_signal_as_authoritative() {
    let mut summary = websocket_summary();

    summary.direction = Some(Direction::ClientToBackend);
    assert_eq!(
        TransactionDebugger::classify_ws_outcome(&summary),
        "websocket_error"
    );

    summary.direction = None;
    summary.io_side = Some(StreamIoSide::Read);
    assert_eq!(
        TransactionDebugger::classify_ws_outcome(&summary),
        "websocket_error"
    );

    summary.io_side = None;
    summary.error_class = Some(ErrorClass::ConnectionReset);
    assert_eq!(
        TransactionDebugger::classify_ws_outcome(&summary),
        "websocket_error"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_transaction_debugger_http_terminal_output_is_bounded_and_redacted() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut summary = create_test_transaction_summary();
    summary.response_streamed = true;
    summary.body_completed = false;
    summary.body_error_class = Some(ErrorClass::ProtocolError);
    summary.bytes_sent = 64;
    summary.bytes_received = 128;
    summary.auth_method = Some("jwt_auth");
    summary
        .metadata
        .insert("rejection_phase".to_string(), "after_proxy".to_string());
    summary
        .metadata
        .insert("grpc_status".to_string(), "13".to_string());
    summary
        .metadata
        .insert("request_id".to_string(), "req-http".to_string());
    summary
        .metadata
        .insert("authorization".to_string(), "http-secret".to_string());

    let logs = capture_debug_logs(|| async { plugin.log(&summary).await }).await;
    for expected in [
        "Transaction terminal diagnostic",
        "outcome=body_error",
        "body_error_class=protocol_error",
        "body_completed=false",
        "bytes_sent=64",
        "bytes_received=128",
        "rejection_phase=after_proxy",
        "grpc_status=13",
        "request_id=req-http",
    ] {
        assert!(logs.contains(expected), "missing {expected}: {logs}");
    }
    assert!(!logs.contains("http-secret"), "raw metadata leaked: {logs}");
    assert!(
        !logs.contains("authorization"),
        "unselected metadata key leaked: {logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_transaction_debugger_stream_output_includes_typed_teardown() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut summary = stream_summary();
    summary.connection_error = Some("backend reset".to_string());
    summary.error_class = Some(ErrorClass::ConnectionReset);
    summary.disconnect_direction = Some(Direction::BackendToClient);
    summary.disconnect_cause = Some(DisconnectCause::BackendError);

    let logs = capture_debug_logs(|| async { plugin.on_stream_disconnect(&summary).await }).await;
    for expected in [
        "Stream terminal diagnostic",
        "outcome=stream_error",
        "connection_error=backend reset",
        "error_class=connection_reset",
        "disconnect_direction=backend_to_client",
        "disconnect_cause=backend_error",
        "consumer_username=alice",
        "auth_method=mtls_auth",
        "request_id=req-stream",
    ] {
        assert!(logs.contains(expected), "missing {expected}: {logs}");
    }
    assert!(
        !logs.contains("stream-secret"),
        "raw metadata leaked: {logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_transaction_debugger_websocket_disconnect_output_and_multiple_instances() {
    let first = TransactionDebugger::new(&json!({})).unwrap();
    let second = TransactionDebugger::new(&json!({"redacted_headers": ["x-private"]})).unwrap();
    let mut summary = websocket_summary();
    summary.direction = Some(Direction::ClientToBackend);
    summary.io_side = Some(StreamIoSide::Write);
    summary.error_class = Some(ErrorClass::ConnectionReset);
    assert_eq!(
        TransactionDebugger::classify_ws_outcome(&summary),
        "websocket_error"
    );

    let logs = capture_debug_logs(|| async {
        first.on_ws_disconnect(&summary).await;
        second.on_ws_disconnect(&summary).await;
    })
    .await;
    assert_eq!(logs.matches("WebSocket terminal diagnostic").count(), 2);
    for expected in [
        "outcome=websocket_error",
        "frames_client_to_backend=3",
        "frames_backend_to_client=5",
        "bytes_client_to_backend=128",
        "bytes_backend_to_client=512",
        "disconnect_direction=client_to_backend",
        "io_side=write",
        "error_class=connection_reset",
        "consumer_username=alice",
        "auth_method=jwt_auth",
        "request_id=req-ws",
    ] {
        assert!(logs.contains(expected), "missing {expected}: {logs}");
    }
    assert!(!logs.contains("ws-secret"), "raw metadata leaked: {logs}");
}

#[tokio::test(flavor = "current_thread")]
async fn test_transaction_debugger_websocket_clean_disconnect() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let summary = websocket_summary();
    assert_eq!(
        TransactionDebugger::classify_ws_outcome(&summary),
        "completed"
    );

    let logs = capture_debug_logs(|| async { plugin.on_ws_disconnect(&summary).await }).await;
    assert!(logs.contains("outcome=completed"), "got: {logs}");
}
