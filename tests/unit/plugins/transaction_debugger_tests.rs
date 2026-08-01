//! Tests for transaction_debugger plugin

use ferrum_edge::_test_support::{
    set_request_http_flavor_for_test, set_websocket_response_boundary_for_test,
};
use ferrum_edge::HttpFlavor;
use ferrum_edge::plugins::transaction_debugger::{
    BODY_BINARY_MARKER, BODY_MALFORMED_MARKER, BODY_OVER_LIMIT_MARKER, BodyKind,
    DEFAULT_BODY_CAPTURE_BYTES, MAX_BODY_CAPTURE_BYTES, MAX_RENDERED_BODY_BYTES,
};
use ferrum_edge::plugins::{
    Direction, DisconnectCause, Plugin, ProxyProtocol, RequestContext, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext, transaction_debugger::TransactionDebugger,
    validate_plugin_config,
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

/// Run `operation` with a DEBUG-level thread-local subscriber installed.
///
/// The body-buffering predicates release bodies to streaming when the
/// `transaction_debug` DEBUG target cannot emit, so every synchronous test that
/// asserts a buffering decision has to state which side of that gate it is on.
fn with_debug_target<T>(operation: impl FnOnce() -> T) -> T {
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(SharedLogWriter::default())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    operation()
}

/// Run `operation` with the `transaction_debug` target definitively disabled.
///
/// `NoSubscriber` is used rather than a level-filtered `fmt` subscriber
/// deliberately: it reports no max-level hint, so installing it cannot lower the
/// process-wide max level out from under a debug-capturing test running
/// concurrently on another thread.
fn with_capture_target_disabled<T>(operation: impl FnOnce() -> T) -> T {
    let _guard = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
    operation()
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
fn test_transaction_debugger_accepts_bounded_body_capture_options() {
    for config in [
        json!({"log_request_body": false}),
        json!({"log_response_body": true}),
        json!({"log_request_body": true, "log_response_body": true}),
        json!({
            "log_request_body": true,
            "max_request_body_bytes": 8192,
            "redacted_body_fields": ["x_internal_field"]
        }),
        json!({
            "log_request_body": true,
            "redacted_body_fields": ["é".repeat(128)]
        }),
    ] {
        TransactionDebugger::new(&config).expect("bounded body capture options are supported");
    }
}

#[test]
fn test_transaction_debugger_body_capture_defaults_and_bounds() {
    let default = TransactionDebugger::new(&json!({})).unwrap();
    assert!(!default.log_request_body());
    assert!(!default.log_response_body());
    assert_eq!(
        default.max_request_body_bytes(),
        DEFAULT_BODY_CAPTURE_BYTES as usize
    );
    assert_eq!(
        default.max_response_body_bytes(),
        DEFAULT_BODY_CAPTURE_BYTES as usize
    );

    let configured = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "log_response_body": true,
        "max_request_body_bytes": 64,
        "max_response_body_bytes": MAX_BODY_CAPTURE_BYTES,
    }))
    .unwrap();
    assert_eq!(configured.max_request_body_bytes(), 64);
    assert_eq!(
        configured.max_response_body_bytes(),
        MAX_BODY_CAPTURE_BYTES as usize
    );
}

#[test]
fn test_transaction_debugger_rejects_invalid_body_capture_options() {
    for (config, needle) in [
        (
            json!({"log_request_body": null}),
            "'log_request_body' must be a boolean; null is not allowed",
        ),
        (
            json!({"log_response_body": "true"}),
            "'log_response_body' must be a boolean",
        ),
        (
            json!({"log_request_body": true, "max_request_body_bytes": 0}),
            "'max_request_body_bytes' must be greater than zero",
        ),
        (
            json!({"log_request_body": true, "max_request_body_bytes": 8193}),
            "'max_request_body_bytes' must be <= 8192 (got 8193)",
        ),
        (
            json!({"log_response_body": true, "max_response_body_bytes": -1}),
            "'max_response_body_bytes' must be a positive integer",
        ),
        (
            json!({"max_request_body_bytes": 128}),
            "'max_request_body_bytes' requires 'log_request_body' to be true",
        ),
        (
            json!({"log_request_body": true, "max_response_body_bytes": 128}),
            "'max_response_body_bytes' requires 'log_response_body' to be true",
        ),
        (
            json!({"redacted_body_fields": ["x"]}),
            "'redacted_body_fields' requires 'log_request_body' or 'log_response_body' to be true",
        ),
        (
            json!({"log_request_body": true, "redacted_body_fields": [""]}),
            "'redacted_body_fields[0]' must not be empty",
        ),
        (
            json!({"log_request_body": true, "redacted_body_fields": [" \t "]}),
            "'redacted_body_fields[0]' must not be empty",
        ),
        (
            json!({"log_request_body": true, "redacted_body_fields": ["x".repeat(129)]}),
            "'redacted_body_fields[0]' must be at most 128 characters",
        ),
        (
            json!({"log_request_body": true, "redacted_body_fields": [7]}),
            "'redacted_body_fields[0]' must be a string",
        ),
        (
            json!({"log_request_body": true, "redacted_body_fields": "token"}),
            "'redacted_body_fields' must be an array",
        ),
    ] {
        let err = TransactionDebugger::new(&config)
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {config}"));
        assert!(err.contains(needle), "needle={needle}, got: {err}");
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
fn test_transaction_debugger_accepts_inline_schema_and_rejects_dangling_ref() {
    // Inline schemas compile at construction against the diagnostic field
    // inventory; a `schema_ref` with no registered definition fails closed.
    TransactionDebugger::new(&json!({"schema": {}})).expect("empty inline schema compiles");
    let err = TransactionDebugger::new(&json!({"schema_ref": "definitely-not-defined"}))
        .err()
        .unwrap();
    assert!(
        err.contains("references unknown schema 'definitely-not-defined'"),
        "got: {err}"
    );
    let err = TransactionDebugger::new(&json!({"schema": {}, "schema_ref": "x"}))
        .err()
        .unwrap();
    assert!(err.contains("mutually exclusive"), "got: {err}");
}

#[test]
fn test_shared_validation_matches_transaction_debugger_config_surface() {
    validate_plugin_config("transaction_debugger", &json!({})).unwrap();
    validate_plugin_config(
        "transaction_debugger",
        &json!({"redacted_headers": ["x-internal-id"]}),
    )
    .unwrap();

    validate_plugin_config(
        "transaction_debugger",
        &json!({"log_request_body": true, "max_request_body_bytes": 512}),
    )
    .expect("shared validation must accept bounded body capture");

    let over_limit = validate_plugin_config(
        "transaction_debugger",
        &json!({"log_request_body": true, "max_request_body_bytes": 1_000_000}),
    )
    .expect_err("shared validation must reject an out-of-range capture budget");
    assert!(over_limit.contains("must be <= 8192"));

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
        proxy_lifecycle_generation: None,
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
        proxy_lifecycle_generation: None,
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

// ── Bounded body capture (issue #3316) ─────────────────────────────────

fn body_headers(content_type: &str, len: usize) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), content_type.to_string());
    headers.insert("content-length".to_string(), len.to_string());
    headers
}

fn capture_plugin() -> TransactionDebugger {
    TransactionDebugger::new(&json!({
        "log_request_body": true,
        "log_response_body": true,
        "max_request_body_bytes": 512,
        "max_response_body_bytes": 512,
    }))
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn test_body_capture_disabled_by_default_is_zero_cost() {
    let plugin = TransactionDebugger::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("content-length".to_string(), "12".to_string());

    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.should_buffer_request_body(&ctx));
    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.needs_request_body_text());
    assert_eq!(
        plugin
            .request_body_capture_decision(&ctx.headers)
            .skip_reason(),
        Some("disabled")
    );

    let headers = body_headers("application/json", 12);
    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .on_final_request_body(&headers, br#"{"a":"bcde"}"#)
            .await;
    })
    .await;
    assert!(
        logs.is_empty(),
        "disabled capture must emit nothing: {logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_small_json_request_body_is_captured_and_redacted() {
    let plugin = capture_plugin();
    let headers = body_headers("application/json; charset=utf-8", 64);
    let body = br#"{"user":"alice","password":"hunter2","note":"ok"}"#;

    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.request_body_capture_decision(&headers).is_capture());

    let logs = capture_debug_logs(|| async {
        let _ = plugin.on_final_request_body(&headers, body).await;
    })
    .await;

    assert!(logs.contains("Bounded body capture"), "got: {logs}");
    assert!(logs.contains("direction=request"), "got: {logs}");
    assert!(logs.contains("capture=captured"), "got: {logs}");
    assert!(logs.contains("body_kind=json"), "got: {logs}");
    assert!(logs.contains("truncated=false"), "got: {logs}");
    assert!(logs.contains("alice"), "non-sensitive field lost: {logs}");
    assert!(!logs.contains("hunter2"), "secret leaked: {logs}");
    assert!(logs.contains("***REDACTED***"), "got: {logs}");
}

#[tokio::test(flavor = "current_thread")]
async fn test_json_response_body_capture_covers_error_responses() {
    let plugin = capture_plugin();
    let mut ctx = make_ctx();
    let headers = body_headers("application/problem+json", 48);
    let body = br#"{"title":"upstream failed","detail":"pool exhausted"}"#;

    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .on_final_response_body(&mut ctx, 500, &headers, body)
            .await;
    })
    .await;
    assert!(logs.contains("direction=response"), "got: {logs}");
    assert!(logs.contains("upstream failed"), "got: {logs}");
    assert!(logs.contains("pool exhausted"), "got: {logs}");
}

#[tokio::test(flavor = "current_thread")]
async fn test_credential_shaped_values_are_redacted_regardless_of_field_name() {
    let plugin = capture_plugin();
    let body = br#"{"note":"upstream said Authorization: Bearer sk-live-abcdefghijklmnop","basic":"prefix Basic dXNlcjpwYXNz","jot":"embedded eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}"#;
    let headers = body_headers("application/json", body.len());

    let logs = capture_debug_logs(|| async {
        let _ = plugin.on_final_request_body(&headers, body).await;
    })
    .await;
    assert!(!logs.contains("sk-live-abcdefghijklmnop"), "got: {logs}");
    assert!(!logs.contains("dXNlcjpwYXNz"), "got: {logs}");
    assert!(!logs.contains("eyJhbGciOiJIUzI1NiJ9"), "got: {logs}");
}

#[test]
fn test_padded_jwt_values_are_redacted_from_structured_bodies() {
    let plugin = capture_plugin();
    let credential = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0=.sig";

    let json_body = serde_json::to_vec(&json!({"note": credential})).unwrap();
    let json = plugin.render_captured_body(&json_body, BodyKind::Json, 512);
    assert!(!json.rendered.contains(credential), "{}", json.rendered);
    assert!(
        json.rendered.contains("***REDACTED***"),
        "{}",
        json.rendered
    );

    let form_body = b"note=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0%3D.sig";
    let form = plugin.render_captured_body(form_body, BodyKind::Form, 512);
    assert!(
        !form.rendered.contains("eyJhbGciOiJIUzI1NiJ9"),
        "{}",
        form.rendered
    );
    assert_eq!(form.rendered, "note=***REDACTED***");
}

#[test]
fn test_many_jwt_prefixes_without_compact_serialization_remain_visible() {
    let plugin = capture_plugin();
    let benign = format!("{}tail", "eyJ".repeat(1_000));
    let body = serde_json::to_vec(&json!({"note": benign})).unwrap();
    let rendered = plugin.render_captured_body(&body, BodyKind::Json, 8_192);

    assert_eq!(rendered.state, "captured");
    assert!(!rendered.rendered.contains("***REDACTED***"));
    assert!(rendered.rendered.contains(&"eyJ".repeat(16)));
}

#[test]
fn test_form_and_text_body_redaction() {
    let plugin = capture_plugin();

    let form_body = b"user=alice&client_secret=shhh&note=fine";
    let form = plugin.render_captured_body(form_body, BodyKind::Form, 512);
    assert_eq!(form.kind, "form");
    assert!(form.rendered.contains("user=alice"), "{}", form.rendered);
    assert!(!form.rendered.contains("shhh"), "{}", form.rendered);
    assert!(form.rendered.contains("note=fine"), "{}", form.rendered);

    let embedded_credential = b"note=prefix+Bearer+secret-token&message=keep";
    let form = plugin.render_captured_body(embedded_credential, BodyKind::Form, 512);
    assert!(!form.rendered.contains("secret-token"), "{}", form.rendered);
    assert!(form.rendered.contains("message=keep"), "{}", form.rendered);

    let text_body = b"line one is fine\nauthorization: Bearer abc\nline three is fine";
    let text = plugin.render_captured_body(text_body, BodyKind::Text, 512);
    assert_eq!(text.kind, "text");
    assert!(text.rendered.contains("line one is fine"));
    assert!(text.rendered.contains("line three is fine"));
    assert!(!text.rendered.contains("Bearer abc"), "{}", text.rendered);
}

#[test]
fn test_configured_extra_body_fields_are_redacted() {
    let plugin = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "redacted_body_fields": ["Tenant_Ref"],
    }))
    .unwrap();
    let body = br#"{"tenant_ref":"acme-9","keep":"yes"}"#;
    let sample = plugin.render_captured_body(body, BodyKind::Json, 512);
    assert!(!sample.rendered.contains("acme-9"), "{}", sample.rendered);
    assert!(sample.rendered.contains("yes"), "{}", sample.rendered);
}

#[test]
fn test_capture_decision_exact_cap_and_cap_plus_one() {
    let plugin = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "max_request_body_bytes": 64,
    }))
    .unwrap();

    let at_cap = body_headers("application/json", 64);
    assert!(plugin.request_body_capture_decision(&at_cap).is_capture());
    let over_cap = body_headers("application/json", 65);
    assert_eq!(
        plugin
            .request_body_capture_decision(&over_cap)
            .skip_reason(),
        Some("over_capture_limit")
    );
    let empty = body_headers("application/json", 0);
    assert_eq!(
        plugin.request_body_capture_decision(&empty).skip_reason(),
        Some("empty_body")
    );
}

#[test]
fn test_capture_decision_excludes_streaming_encoded_and_binary_traffic() {
    let plugin = capture_plugin();

    let mut chunked = HashMap::new();
    chunked.insert("content-type".to_string(), "application/json".to_string());
    chunked.insert("transfer-encoding".to_string(), "chunked".to_string());
    assert_eq!(
        plugin.request_body_capture_decision(&chunked).skip_reason(),
        Some("unknown_length")
    );

    let mut encoded = body_headers("application/json", 32);
    encoded.insert("content-encoding".to_string(), "gzip".to_string());
    assert_eq!(
        plugin.request_body_capture_decision(&encoded).skip_reason(),
        Some("content_encoding")
    );

    let mut identity = body_headers("application/json", 32);
    identity.insert("content-encoding".to_string(), "identity".to_string());
    assert!(plugin.request_body_capture_decision(&identity).is_capture());

    for (content_type, reason) in [
        ("application/grpc+proto", "protocol_excluded"),
        ("text/event-stream", "protocol_excluded"),
        ("application/octet-stream", "content_type_excluded"),
        ("multipart/form-data; boundary=x", "content_type_excluded"),
        ("image/png", "content_type_excluded"),
        ("text/html", "content_type_excluded"),
    ] {
        let headers = body_headers(content_type, 32);
        assert_eq!(
            plugin.request_body_capture_decision(&headers).skip_reason(),
            Some(reason),
            "content_type={content_type}"
        );
    }

    let mut upgrade = body_headers("application/json", 32);
    upgrade.insert("upgrade".to_string(), "websocket".to_string());
    assert_eq!(
        plugin.request_body_capture_decision(&upgrade).skip_reason(),
        Some("protocol_excluded")
    );

    let bare = HashMap::new();
    assert_eq!(
        plugin.request_body_capture_decision(&bare).skip_reason(),
        Some("no_content_type")
    );
}

#[test]
fn test_response_buffering_predicates_only_narrow() {
    let plugin = capture_plugin();
    let ctx = make_ctx();
    assert!(plugin.requires_response_body_buffering());
    with_debug_target(|| {
        assert!(plugin.should_buffer_response_body(&ctx));

        // Header-time refinement keeps unknown-length and non-textual responses
        // on the streaming path.
        assert!(plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &body_headers("application/json", 32),
        ));
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &body_headers("text/event-stream", 32),
        ));
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &HashMap::new(),
        ));

        // A client that asked for a stream is never pinned onto the buffered
        // path. The `Accept` screen is ASCII-case-insensitive without
        // lowercasing the header value.
        let mut sse_ctx = make_ctx();
        sse_ctx
            .headers
            .insert("accept".to_string(), "Text/Event-Stream".to_string());
        assert!(!plugin.should_buffer_response_body(&sse_ctx));

        let mut ws_ctx = make_ctx();
        ws_ctx
            .headers
            .insert("upgrade".to_string(), "websocket".to_string());
        assert!(!plugin.should_buffer_response_body(&ws_ctx));

        let mut grpc_ctx = make_ctx();
        grpc_ctx
            .headers
            .insert("content-type".to_string(), "application/grpc".to_string());
        assert!(!plugin.should_buffer_response_body(&grpc_ctx));
    });
}

#[test]
fn test_typed_request_provenance_excludes_native_grpc_and_extended_connect_websockets() {
    let plugin = capture_plugin();

    with_debug_target(|| {
        // Native gRPC whose request `Content-Type` was rewritten by an earlier
        // plugin: only the typed flavor stamped on the protocol entry path
        // still witnesses the protocol.
        let mut grpc_ctx = make_ctx();
        grpc_ctx
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
        set_request_http_flavor_for_test(&mut grpc_ctx, HttpFlavor::Grpc);
        assert!(
            !plugin.should_buffer_response_body(&grpc_ctx),
            "native gRPC must never be pinned onto the buffered path"
        );

        // H2/H3 Extended CONNECT WebSocket: there is no `Upgrade` header at all,
        // so the header screen alone would have admitted it.
        let mut ws_ctx = make_ctx();
        set_request_http_flavor_for_test(&mut ws_ctx, HttpFlavor::WebSocket);
        assert!(
            !ws_ctx.headers.contains_key("upgrade"),
            "extended CONNECT carries no Upgrade header"
        );
        assert!(
            !plugin.should_buffer_response_body(&ws_ctx),
            "extended CONNECT WebSockets must keep streaming"
        );

        // The response-boundary flag is authoritative on its own.
        let mut boundary_ctx = make_ctx();
        set_websocket_response_boundary_for_test(&mut boundary_ctx, true);
        assert!(!plugin.should_buffer_response_body(&boundary_ctx));

        // A plain request with none of those typed signals still buffers.
        let plain_ctx = make_ctx();
        assert!(plugin.should_buffer_response_body(&plain_ctx));
    });
}

#[test]
fn test_buffering_is_released_when_the_debug_target_cannot_emit() {
    let plugin = capture_plugin();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("content-length".to_string(), "32".to_string());

    // The config-level capability still describes what the configuration asks
    // for — it must not be weakened by the runtime filter.
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());

    // With the `transaction_debug` DEBUG target disabled no capture record can
    // be emitted, so the per-request predicates release the bodies to streaming
    // instead of buffering them for nothing.
    with_capture_target_disabled(|| {
        assert!(!plugin.should_buffer_request_body(&ctx));
        assert!(!plugin.should_buffer_response_body(&ctx));
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &body_headers("application/json", 32),
        ));
    });

    with_debug_target(|| {
        assert!(plugin.should_buffer_request_body(&ctx));
        assert!(plugin.should_buffer_response_body(&ctx));
        assert!(plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &body_headers("application/json", 32),
        ));
    });
}

#[test]
fn test_render_binary_unicode_and_truncation_markers() {
    let plugin = capture_plugin();

    let binary = plugin.render_captured_body(&[0xff, 0xfe, 0x00, 0x01], BodyKind::Text, 512);
    assert_eq!(binary.state, "binary");
    assert_eq!(binary.kind, "binary");
    assert_eq!(binary.rendered, BODY_BINARY_MARKER);
    assert!(!binary.truncated);

    // Redaction can make the rendering longer than the source body, and the
    // byte cap is applied to the *redacted* text. The cut lands inside a
    // two-byte `é`, so it backs off to the preceding character boundary.
    let body = "token=abc\nééé".as_bytes();
    assert_eq!(body.len(), 16);
    let unicode = plugin.render_captured_body(body, BodyKind::Text, 16);
    assert!(unicode.truncated);
    assert_eq!(unicode.state, "truncated");
    assert_eq!(unicode.rendered, "***REDACTED***\\n");
    assert_eq!(unicode.original_bytes, 16);

    // Bidi-spoofing, invisible formatting, line separators, and control
    // characters are escaped, never emitted raw.
    let spoof = plugin.render_captured_body(
        "a\u{061C}b\u{2028}c\u{2029}d\u{202E}e\u{2060}f\u{0007}".as_bytes(),
        BodyKind::Text,
        512,
    );
    for (raw, escaped) in [
        ('\u{061C}', "\\u{061c}"),
        ('\u{2028}', "\\u{2028}"),
        ('\u{2029}', "\\u{2029}"),
        ('\u{202E}', "\\u{202e}"),
        ('\u{2060}', "\\u{2060}"),
        ('\u{0007}', "\\u{0007}"),
    ] {
        assert!(!spoof.rendered.contains(raw), "{}", spoof.rendered);
        assert!(spoof.rendered.contains(escaped), "{}", spoof.rendered);
    }
}

#[test]
fn test_incomplete_utf8_tail_renders_only_the_binary_marker() {
    let plugin = capture_plugin();
    // A valid ASCII prefix followed by an incomplete multibyte sequence. At a
    // final body hook the slice is complete, so this is invalid UTF-8, not a
    // capture-truncation artifact, and the prefix must never be logged.
    let mut body = b"visible-prefix".to_vec();
    body.push(0xc3);
    let sample = plugin.render_captured_body(&body, BodyKind::Text, 512);
    assert_eq!(sample.state, "binary");
    assert_eq!(sample.kind, "binary");
    assert_eq!(sample.rendered, BODY_BINARY_MARKER);
    assert!(!sample.rendered.contains("visible-prefix"));

    // The same holds for a truncated multibyte sequence in a JSON body.
    let mut json = br#"{"a":"b"#.to_vec();
    json.extend_from_slice(&[0xe2, 0x82]);
    let sample = plugin.render_captured_body(&json, BodyKind::Json, 512);
    assert_eq!(sample.rendered, BODY_BINARY_MARKER);
}

#[test]
fn test_malformed_json_fails_closed_to_a_content_free_marker() {
    let plugin = capture_plugin();
    // A split-line secret: line-level fallback would have redacted the marker
    // line and logged the value on the next line.
    let body = b"{\n  \"password\":\n  \"hunter2\"\n";
    let sample = plugin.render_captured_body(body, BodyKind::Json, 512);
    assert_eq!(sample.state, "omitted");
    assert_eq!(sample.kind, "json");
    assert_eq!(sample.rendered, BODY_MALFORMED_MARKER);
    assert!(!sample.rendered.contains("hunter2"), "{}", sample.rendered);

    // Truncated JSON is the same fail-closed path, not a partial rendering.
    let truncated =
        plugin.render_captured_body(br#"{"password":"hunter2","x":"#, BodyKind::Json, 512);
    assert_eq!(truncated.rendered, BODY_MALFORMED_MARKER);
}

#[test]
fn test_structured_families_without_a_structure_aware_redactor_are_not_capturable() {
    let plugin = capture_plugin();
    // XML and GraphQL secrets live in structural positions that line-level
    // redaction cannot reach, so they are excluded outright rather than
    // advertised as controlled.
    for content_type in [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/graphql",
    ] {
        let headers = body_headers(content_type, 32);
        assert_eq!(
            plugin.request_body_capture_decision(&headers).skip_reason(),
            Some("content_type_excluded"),
            "content_type={content_type}"
        );
        assert_eq!(
            plugin
                .response_body_capture_decision(&headers)
                .skip_reason(),
            Some("content_type_excluded"),
            "content_type={content_type}"
        );
    }

    // `text/plain` stays capturable as the documented coarse, operator-opt-in
    // line-level family.
    let plain = body_headers("text/plain; charset=utf-8", 32);
    assert!(plugin.request_body_capture_decision(&plain).is_capture());
    let text = plugin.render_captured_body(
        b"line one is fine\nauthorization: Bearer abc\nline three is fine",
        BodyKind::Text,
        512,
    );
    assert!(text.rendered.contains("line one is fine"));
    assert!(!text.rendered.contains("Bearer abc"), "{}", text.rendered);
}

#[test]
fn test_render_helper_is_bounded_for_hostile_direct_callers() {
    let plugin = capture_plugin();
    // A direct caller cannot widen the ceiling: the body is never scanned,
    // parsed, or allocated from, and the rendering carries no content.
    let oversized = vec![b'a'; MAX_BODY_CAPTURE_BYTES as usize + 1];
    let sample = plugin.render_captured_body(&oversized, BodyKind::Text, usize::MAX);
    assert_eq!(sample.state, "omitted");
    assert_eq!(sample.kind, "omitted");
    assert_eq!(sample.rendered, BODY_OVER_LIMIT_MARKER);
    assert_eq!(sample.original_bytes, oversized.len());

    // A body one byte over the configured direction cap is refused too.
    let over_configured = vec![b'a'; 513];
    let sample = plugin.render_captured_body(&over_configured, BodyKind::Text, 512);
    assert_eq!(sample.rendered, BODY_OVER_LIMIT_MARKER);
}

#[test]
fn test_render_ceiling_is_exact_under_control_and_bidi_expansion() {
    let plugin = capture_plugin();
    let cap = MAX_BODY_CAPTURE_BYTES as usize;

    // Worst-case expansion per source byte: every byte is a C0 control that
    // escapes to `\u{0007}` (8 output bytes). A maximal capture therefore
    // lands exactly on the render ceiling and never past it.
    let controls = vec![0x07u8; cap];
    let sample = plugin.render_captured_body(&controls, BodyKind::Text, cap);
    assert_eq!(sample.original_bytes, cap);
    assert_eq!(
        sample.rendered.len(),
        MAX_RENDERED_BODY_BYTES,
        "the render ceiling must be reached exactly, never overshot"
    );
    assert!(!sample.rendered.contains('\u{0007}'));
    assert!(
        !sample.truncated,
        "an exactly-fitting capture is not truncated"
    );

    // Bidi-spoofing characters expand 3 source bytes into 8 output bytes and
    // stay inside the same ceiling.
    let bidi = "\u{202E}".repeat(cap / 3);
    let sample = plugin.render_captured_body(bidi.as_bytes(), BodyKind::Text, cap);
    assert!(sample.rendered.len() <= MAX_RENDERED_BODY_BYTES);
    assert!(!sample.rendered.contains('\u{202E}'));
    assert!(sample.rendered.starts_with("\\u{202e}"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_omission_records_are_emitted_with_stable_reasons() {
    let plugin = capture_plugin();
    let mut ctx = make_ctx();
    let mut headers = body_headers("application/octet-stream", 32);

    let logs = capture_debug_logs(|| async {
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    })
    .await;
    assert!(logs.contains("Bounded body capture omitted"), "got: {logs}");
    assert!(logs.contains("capture=omitted"), "got: {logs}");
    assert!(logs.contains("reason=content_type_excluded"), "got: {logs}");

    let mut response_headers = body_headers("text/event-stream", 32);
    let mut ctx = make_ctx();
    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
    })
    .await;
    assert!(logs.contains("direction=response"), "got: {logs}");
    assert!(logs.contains("reason=protocol_excluded"), "got: {logs}");
}

#[tokio::test(flavor = "current_thread")]
async fn test_final_request_hook_fails_closed_when_the_actual_body_exceeds_the_cap() {
    let plugin = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "max_request_body_bytes": 64,
    }))
    .unwrap();

    // `Content-Length` declares a capturable 32 bytes but the backend-visible
    // body is far larger — a stale/lying header, or a request transform that
    // grew the body after the header-time screen ran.
    let headers = body_headers("application/json", 32);
    let body = format!(r#"{{"password":"hunter2","pad":"{}"}}"#, "q".repeat(4096));
    assert!(plugin.request_body_capture_decision(&headers).is_capture());

    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .on_final_request_body(&headers, body.as_bytes())
            .await;
    })
    .await;

    assert!(logs.contains("capture=omitted"), "got: {logs}");
    assert!(logs.contains("reason=over_capture_limit"), "got: {logs}");
    assert!(logs.contains("direction=request"), "got: {logs}");
    assert!(!logs.contains("hunter2"), "secret leaked: {logs}");
    assert!(!logs.contains("qqqq"), "body content leaked: {logs}");
    assert!(
        !logs.contains("body_bytes"),
        "length metadata leaked: {logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_final_response_hook_fails_closed_on_transformation_length_drift() {
    let plugin = TransactionDebugger::new(&json!({
        "log_response_body": true,
        "max_response_body_bytes": 128,
    }))
    .unwrap();
    let mut ctx = make_ctx();

    // The response headers still carry the pre-transform length; a response
    // transform (templating, envelope wrapping, decompression) grew the
    // client-visible body past the configured cap.
    let headers = body_headers("application/json", 96);
    let body = format!(
        r#"{{"api_key":"resp-secret","detail":"{}"}}"#,
        "z".repeat(2048)
    );
    assert!(plugin.response_body_capture_decision(&headers).is_capture());

    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .on_final_response_body(&mut ctx, 200, &headers, body.as_bytes())
            .await;
    })
    .await;

    assert!(logs.contains("capture=omitted"), "got: {logs}");
    assert!(logs.contains("reason=over_capture_limit"), "got: {logs}");
    assert!(logs.contains("direction=response"), "got: {logs}");
    assert!(!logs.contains("resp-secret"), "secret leaked: {logs}");
    assert!(!logs.contains("zzzz"), "body content leaked: {logs}");

    // A body that actually fits is still captured on the same path.
    let small = br#"{"detail":"ok"}"#;
    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .on_final_response_body(&mut ctx, 200, &headers, small)
            .await;
    })
    .await;
    assert!(logs.contains("capture=captured"), "got: {logs}");
    assert!(logs.contains("ok"), "got: {logs}");
}

#[tokio::test(flavor = "current_thread")]
async fn test_final_hooks_report_a_declared_but_absent_body_as_empty_not_malformed() {
    // `Content-Length` can overstate the message as easily as it can understate
    // it: a `HEAD` or `304` response declares the length of a body it never
    // sends, so the header screen admits it and the final hook receives an
    // empty slice. Handing that to the structured renderer would report
    // `<malformed-structured-body-omitted>` — telling the operator the backend
    // emitted broken JSON when it correctly emitted nothing at all.
    let plugin = capture_plugin();
    let mut ctx = make_ctx();
    let headers = body_headers("application/json", 50);
    let empty: &[u8] = b"";
    assert!(plugin.response_body_capture_decision(&headers).is_capture());

    let logs = capture_debug_logs(|| async {
        let _ = plugin
            .on_final_response_body(&mut ctx, 304, &headers, empty)
            .await;
    })
    .await;
    assert!(logs.contains("capture=omitted"), "got: {logs}");
    assert!(logs.contains("reason=empty_body"), "got: {logs}");
    assert!(logs.contains("direction=response"), "got: {logs}");
    assert!(
        !logs.contains(BODY_MALFORMED_MARKER),
        "an absent body must not be reported as a malformed one: {logs}"
    );

    // Same rule on the request side, where a `before_proxy` transform can empty
    // a body the header screen already admitted.
    let logs = capture_debug_logs(|| async {
        let _ = plugin.on_final_request_body(&headers, empty).await;
    })
    .await;
    assert!(logs.contains("capture=omitted"), "got: {logs}");
    assert!(logs.contains("reason=empty_body"), "got: {logs}");
    assert!(logs.contains("direction=request"), "got: {logs}");
    assert!(!logs.contains(BODY_MALFORMED_MARKER), "got: {logs}");

    // Exactly one record either way: the omission replaces the sample, it does
    // not accompany one.
    assert_eq!(
        logs.matches("Bounded body capture").count(),
        1,
        "an empty body must emit exactly one record: {logs}"
    );

    // The unstructured families take the same path rather than reporting an
    // empty `captured` sample that reads like a real one.
    let text = body_headers("text/plain", 50);
    let logs = capture_debug_logs(|| async {
        let _ = plugin.on_final_request_body(&text, empty).await;
    })
    .await;
    assert!(logs.contains("reason=empty_body"), "got: {logs}");
    assert!(!logs.contains("capture=captured"), "got: {logs}");
}

#[test]
fn test_reload_style_reconfiguration_changes_capture_behavior() {
    // A rebuilt plugin cache constructs a fresh instance; the new configuration
    // must govern buffering immediately, with no shared state from the old one.
    let before = TransactionDebugger::new(&json!({})).unwrap();
    let after = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "max_request_body_bytes": 32,
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("content-length".to_string(), "16".to_string());
    with_debug_target(|| {
        assert!(!before.should_buffer_request_body(&ctx));
        assert!(after.should_buffer_request_body(&ctx));
    });
    assert!(!before.requires_request_body_buffering());
    assert!(after.requires_request_body_buffering());
}

#[test]
fn test_retry_enabled_proxies_release_responses_the_debugger_will_not_sample() {
    // A retry-enabled proxy keeps every response buffered unless each active
    // buffering plugin opts a concrete response out after headers arrive. The
    // debugger must apply the same capture screen there, or enabling
    // `log_response_body` would pin SSE and every other long-lived,
    // unknown-length, or encoded response onto the buffered path.
    let plugin = capture_plugin();
    let ctx = make_ctx();

    with_debug_target(|| {
        assert!(
            plugin.may_release_response_body_under_retries(&ctx),
            "the debugger must participate in the after-headers retry opt-in"
        );

        // Server-sent events: released, never held for the retry window.
        let mut sse = HashMap::new();
        sse.insert("content-type".to_string(), "text/event-stream".to_string());
        assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &sse));

        // Unknown length (chunked), non-identity encoding, oversized, and
        // non-textual responses are all released for the same reason.
        let mut chunked = HashMap::new();
        chunked.insert("content-type".to_string(), "application/json".to_string());
        assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &chunked));

        let mut encoded = body_headers("application/json", 32);
        encoded.insert("content-encoding".to_string(), "gzip".to_string());
        assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &encoded));

        assert!(plugin.should_release_response_body_under_retries(
            &ctx,
            200,
            &body_headers("application/json", 4096),
        ));
        assert!(plugin.should_release_response_body_under_retries(
            &ctx,
            200,
            &body_headers("application/octet-stream", 32),
        ));

        // A response that will actually be sampled stays buffered, so mid-body
        // retry remains possible for it.
        assert!(!plugin.should_release_response_body_under_retries(
            &ctx,
            200,
            &body_headers("application/json", 32),
        ));
    });

    // With capture disabled the plugin is not an active buffering plugin at
    // all, so it never claims the retry opt-in.
    let disabled = TransactionDebugger::new(&json!({})).unwrap();
    with_debug_target(|| {
        assert!(!disabled.may_release_response_body_under_retries(&ctx));
        assert!(!disabled.should_release_response_body_under_retries(
            &ctx,
            200,
            &body_headers("application/json", 32),
        ));
    });
}

#[tokio::test(flavor = "current_thread")]
async fn test_request_capture_record_carries_method_and_path_from_context() {
    // The backend-visible hook header map carries no `:method` / `:path`
    // pseudo-headers on H1/H2, so without the hook context the record could
    // only ever report `-` and would not be correlatable with its request.
    let plugin = capture_plugin();
    assert!(
        plugin.needs_final_request_body_context(),
        "capture must opt into the hook context to report method/path"
    );
    assert!(
        !TransactionDebugger::new(&json!({}))
            .unwrap()
            .needs_final_request_body_context(),
        "a disabled debugger must not ask the proxy to build a hook context"
    );

    let headers = body_headers("application/json", 24);
    let body = br#"{"user":"alice"}"#;

    let logs = capture_debug_logs(|| async {
        let mut ctx = make_ctx();
        let _ = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await;
    })
    .await;
    assert!(logs.contains("capture=captured"), "got: {logs}");
    assert!(logs.contains("method=POST"), "got: {logs}");
    assert!(logs.contains("path=/api/data"), "got: {logs}");

    // The context-free hook still works and still emits a bounded record.
    let logs = capture_debug_logs(|| async {
        let _ = plugin.on_final_request_body(&headers, body).await;
    })
    .await;
    assert!(logs.contains("capture=captured"), "got: {logs}");
    assert!(logs.contains("alice"), "got: {logs}");
}

// ---------------------------------------------------------------------------
// Terminal-diagnostic schema projection (issue #3314)
// ---------------------------------------------------------------------------

fn projected_http(config: serde_json::Value, summary: &TransactionSummary) -> serde_json::Value {
    let plugin = TransactionDebugger::new(&config).expect("schema compiles");
    let rendered = plugin
        .project_http_for_tests(summary)
        .expect("schema applies to HTTP diagnostics");
    serde_json::from_str(&rendered).expect("projection is valid JSON")
}

#[test]
fn test_debugger_default_diagnostic_field_inventory_is_projected_verbatim() {
    let mut summary = create_test_transaction_summary();
    summary.proxy_id = None;
    let value = projected_http(json!({ "schema": { "summary_type": "http" } }), &summary);
    let object = value.as_object().expect("object");

    // Exactly the diagnostic inventory — the debugger's own names, not the
    // transaction-summary names.
    for key in [
        "outcome",
        "namespace",
        "timestamp_received",
        "client_ip",
        "method",
        "path",
        "status",
        "proxy_id",
        "proxy_name",
        "backend_target",
        "backend_resolved_ip",
        "consumer_username",
        "auth_method",
        "error_class",
        "body_error_class",
        "response_streamed",
        "body_completed",
        "client_disconnected",
        "bytes_sent",
        "bytes_received",
        "rejection_phase",
        "grpc_status",
        "request_id",
        "trace_id",
        "latency_total_ms",
        "latency_backend_ttfb_ms",
        "latency_backend_total_ms",
        "latency_plugin_ms",
        "latency_gw_overhead_ms",
        "metadata",
    ] {
        assert!(object.contains_key(key), "missing diagnostic field `{key}`");
    }
    assert_eq!(object.len(), 30, "unexpected diagnostic field: {object:?}");
    // Absent optionals keep the default record's `-` placeholder rather than
    // vanishing, so `order` completeness stays meaningful.
    assert_eq!(object["proxy_id"], json!("-"));
    // Summary-only names are NOT part of this family.
    assert!(!object.contains_key("request_user_agent"));
    assert!(!object.contains_key("mirror"));
}

#[test]
fn test_debugger_projection_renames_omits_and_adds_fields() {
    let summary = create_test_transaction_summary();
    let value = projected_http(
        json!({
            "schema": {
                "summary_type": "http",
                "rename": { "path": "http.url", "status": "http.status_code" },
                "omit": ["latency_gw_overhead_ms", "latency_plugin_ms"],
                "static_fields": { "service": "ferrum-edge" },
                "derived_fields": [
                    { "name": "status_group", "kind": "status_class" },
                    { "name": "record_kind", "kind": "summary_kind" }
                ]
            }
        }),
        &summary,
    );
    assert_eq!(value["http.url"], json!(summary.request_path));
    assert!(value.get("path").is_none());
    assert_eq!(
        value["http.status_code"],
        json!(summary.response_status_code)
    );
    assert!(value.get("latency_gw_overhead_ms").is_none());
    assert!(value.get("latency_plugin_ms").is_none());
    assert_eq!(value["service"], json!("ferrum-edge"));
    assert_eq!(value["status_group"], json!("2xx"));
    assert_eq!(value["record_kind"], json!("http"));
}

#[test]
fn test_debugger_projection_orders_output_keys() {
    let summary = create_test_transaction_summary();
    let plugin = TransactionDebugger::new(&json!({
        "schema": {
            "summary_type": "http",
            "order": ["status", "method", "*"]
        }
    }))
    .expect("schema compiles");
    let rendered = plugin
        .project_http_for_tests(&summary)
        .expect("schema applies");
    let status_at = rendered.find("\"status\"").expect("status present");
    let method_at = rendered.find("\"method\"").expect("method present");
    let namespace_at = rendered.find("\"namespace\"").expect("namespace present");
    assert!(
        status_at < method_at && method_at < namespace_at,
        "{rendered}"
    );
}

#[test]
fn test_debugger_projection_redacts_metadata_through_rename_and_flatten() {
    let mut summary = create_test_transaction_summary();
    summary
        .metadata
        .insert("authorization".to_string(), "Bearer abc".to_string());
    summary
        .metadata
        .insert("trace_id".to_string(), "t-1".to_string());
    summary
        .metadata
        .insert("_dedup_key".to_string(), "internal".to_string());

    // Renamed outer metadata field: redaction still applies.
    let renamed = projected_http(
        json!({
            "schema": { "summary_type": "http", "rename": { "metadata": "attrs" } }
        }),
        &summary,
    );
    assert_eq!(renamed["attrs"]["authorization"], json!("[REDACTED]"));
    assert_eq!(renamed["attrs"]["trace_id"], json!("t-1"));
    assert!(renamed["attrs"].get("_dedup_key").is_none());

    // Flattened metadata: redaction and internal-only stripping survive.
    let flattened = projected_http(
        json!({
            "schema": {
                "summary_type": "http",
                "metadata": { "mode": "flatten", "prefix": "meta_" }
            }
        }),
        &summary,
    );
    assert_eq!(flattened["meta_authorization"], json!("[REDACTED]"));
    assert_eq!(flattened["meta_trace_id"], json!("t-1"));
    assert!(flattened.get("meta__dedup_key").is_none());
    assert!(flattened.get("metadata").is_none());

    // Omitted metadata drops the map entirely.
    let omitted = projected_http(
        json!({
            "schema": { "summary_type": "http", "metadata": { "mode": "omit" } }
        }),
        &summary,
    );
    assert!(omitted.get("metadata").is_none());
    assert!(omitted.get("authorization").is_none());
}

#[test]
fn test_debugger_projection_converts_timestamps() {
    let mut summary = create_test_transaction_summary();
    summary.timestamp_received = "2026-05-11T12:00:00Z".to_string();
    let value = projected_http(
        json!({
            "schema": { "summary_type": "http", "timestamp_format": "epoch_ms" }
        }),
        &summary,
    );
    assert_eq!(value["timestamp_received"], json!(1778500800000_i64));
}

#[test]
fn test_debugger_projection_covers_stream_and_websocket_entry_kinds() {
    let plugin = TransactionDebugger::new(&json!({
        "schema": { "rename": { "outcome": "terminal_state" } }
    }))
    .expect("schema compiles");

    let rendered = plugin
        .project_stream_for_tests(&stream_summary())
        .expect("stream projected");
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["terminal_state"], json!("graceful_shutdown"));
    assert_eq!(value["protocol"], json!("tcp"));
    assert_eq!(value["disconnect_cause"], json!("graceful_shutdown"));
    assert!(value.get("outcome").is_none());
    // The hand-picked correlation field keeps its existing redaction, and the
    // full metadata map is redacted by the shared serializer.
    assert_eq!(value["request_id"], json!("req-stream"));
    assert_eq!(value["metadata"]["authorization"], json!("[REDACTED]"));

    let rendered = plugin
        .project_ws_for_tests(&websocket_summary())
        .expect("ws projected");
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["terminal_state"], json!("completed"));
    assert_eq!(value["frames_client_to_backend"], json!(3));
    assert_eq!(value["io_side"], json!("-"));
    assert_eq!(value["metadata"]["cookie"], json!("[REDACTED]"));
    // WebSocket-only names never leak into the stream diagnostic and vice
    // versa: each entry kind serializes only what it owns.
    assert!(value.get("disconnect_cause").is_none());
}

/// The stream record carries the same silent-drop risk that
/// `test_debugger_default_diagnostic_field_inventory_is_projected_verbatim`
/// closes for the HTTP record: a name added to a family inventory without a
/// matching `serialize_native` arm falls into the catch-all `_ => Ok(())` and
/// vanishes from the projected record while the default `tracing` diagnostic
/// still carries it. The registry drift guard in
/// `tests/integration/log_schema_registry_tests.rs` cannot see that — these
/// families have no serde struct to compare against.
///
/// The default (`both`) schema is used deliberately: its compiled spec list is
/// the union of all three families, so an exact key count also proves that
/// names owned by another entry kind never leak into this record.
#[test]
fn test_debugger_projected_stream_record_emits_its_whole_inventory() {
    let config = json!({ "schema": {} });
    let plugin = TransactionDebugger::new(&config).expect("schema compiles");
    let rendered = plugin
        .project_stream_for_tests(&stream_summary())
        .expect("stream projected");
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    let object = value.as_object().expect("object");

    for key in [
        "outcome",
        "namespace",
        "protocol",
        "proxy_id",
        "proxy_name",
        "client_ip",
        "listen_port",
        "backend_target",
        "backend_resolved_ip",
        "consumer_username",
        "auth_method",
        "connection_error",
        "error_class",
        "disconnect_direction",
        "disconnect_cause",
        "duration_ms",
        "bytes_sent",
        "bytes_received",
        "timestamp_connected",
        "timestamp_disconnected",
        "sni_hostname",
        "request_id",
        "trace_id",
        "metadata",
    ] {
        assert!(object.contains_key(key), "missing diagnostic field `{key}`");
    }
    assert_eq!(object.len(), 24, "unexpected diagnostic field: {object:?}");
}

/// WebSocket-disconnect counterpart of
/// `test_debugger_projected_stream_record_emits_its_whole_inventory`.
#[test]
fn test_debugger_projected_ws_record_emits_its_whole_inventory() {
    let config = json!({ "schema": {} });
    let plugin = TransactionDebugger::new(&config).expect("schema compiles");
    let rendered = plugin
        .project_ws_for_tests(&websocket_summary())
        .expect("ws projected");
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    let object = value.as_object().expect("object");

    for key in [
        "outcome",
        "namespace",
        "proxy_id",
        "proxy_name",
        "client_ip",
        "listen_port",
        "backend_target",
        "consumer_username",
        "auth_method",
        "duration_ms",
        "frames_client_to_backend",
        "frames_backend_to_client",
        "bytes_client_to_backend",
        "bytes_backend_to_client",
        "disconnect_direction",
        "io_side",
        "error_class",
        "request_id",
        "trace_id",
        "metadata",
    ] {
        assert!(object.contains_key(key), "missing diagnostic field `{key}`");
    }
    assert_eq!(object.len(), 20, "unexpected diagnostic field: {object:?}");
}

#[test]
fn test_debugger_schema_summary_type_scopes_entry_kinds() {
    // `summary_type: stream` leaves HTTP and WebSocket diagnostics on the
    // native path, exactly like every log-shipping plugin.
    let plugin = TransactionDebugger::new(&json!({ "schema": { "summary_type": "stream" } }))
        .expect("schema compiles");
    assert!(
        plugin
            .project_http_for_tests(&create_test_transaction_summary())
            .is_none()
    );
}

#[test]
fn test_debugger_schema_rejects_unrepresentable_shapes_with_field_diagnostics() {
    for (config, needle) in [
        (
            json!({"schema": {"omit": ["request_user_agent"]}}),
            "schema omit references unknown field 'request_user_agent'",
        ),
        (
            json!({"schema": {"rename": {"outcome": "authorization"}}}),
            "matches a sensitive-data substring",
        ),
        (
            json!({"schema": {"static_fields": {"outcome": "x"}, "summary_type": "http"}}),
            "duplicate output key 'outcome'",
        ),
        (
            json!({"schema": {"derived_fields": [{"name": "k", "kind": "not_a_kind"}]}}),
            "unknown derived kind 'not_a_kind'",
        ),
        (
            json!({"schema": {"summary_type": "sideways"}}),
            "'summary_type' must be 'http', 'stream', or 'both'",
        ),
    ] {
        let err = TransactionDebugger::new(&config)
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {config}"));
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}
