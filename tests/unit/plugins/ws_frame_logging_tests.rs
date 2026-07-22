//! Tests for ws_frame_logging plugin

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ferrum_edge::plugins::correlation_id::CorrelationId;
use ferrum_edge::plugins::ws_frame_logging::{
    DEFAULT_LOG_LEVEL, MAX_PAYLOAD_PREVIEW_BYTES, WS_FRAME_LOGGING_CONFIG_KEYS, WsFrameLogging,
};
use ferrum_edge::plugins::{
    Plugin, PluginFailurePolicy, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection,
    WsDisconnectContext, plugin_failure_policy, validate_plugin_config,
};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

#[derive(Clone, Debug, Default)]
struct CapturedWsLog {
    preview: Option<String>,
    event: Option<String>,
    correlation_id: Option<String>,
    connection_id: Option<u64>,
    configured_level: Option<String>,
}

#[derive(Clone, Default)]
struct WsLogCapture {
    events: Arc<Mutex<Vec<CapturedWsLog>>>,
}

impl WsLogCapture {
    fn layer(&self) -> WsLogCaptureLayer {
        WsLogCaptureLayer {
            events: Arc::clone(&self.events),
        }
    }

    fn events(&self) -> Vec<CapturedWsLog> {
        self.events.lock().unwrap().clone()
    }

    fn previews(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|event| event.preview)
            .collect()
    }
}

struct WsLogCaptureLayer {
    events: Arc<Mutex<Vec<CapturedWsLog>>>,
}

impl<S> tracing_subscriber::Layer<S> for WsLogCaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "ws_frame_log" {
            return;
        }

        let mut visitor = WsLogVisitor::default();
        event.record(&mut visitor);
        self.events.lock().unwrap().push(CapturedWsLog {
            preview: visitor.preview,
            event: visitor.event,
            correlation_id: visitor.correlation_id,
            connection_id: visitor.connection_id,
            configured_level: visitor.configured_level,
        });
    }
}

#[derive(Default)]
struct WsLogVisitor {
    preview: Option<String>,
    event: Option<String>,
    correlation_id: Option<String>,
    connection_id: Option<u64>,
    configured_level: Option<String>,
}

impl tracing::field::Visit for WsLogVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "connection_id" {
            self.connection_id = Some(value);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "connection_id" && value >= 0 {
            self.connection_id = Some(value as u64);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "preview" {
            self.preview = Some(value.to_string());
        } else if field.name() == "event" {
            self.event = Some(value.to_string());
        } else if field.name() == "correlation_id" {
            self.correlation_id = Some(value.to_string());
        } else if field.name() == "configured_level" {
            self.configured_level = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "preview" {
            self.preview = Some(format!("{value:?}").trim_matches('"').to_string());
        } else if field.name() == "event" {
            self.event = Some(format!("{value:?}").trim_matches('"').to_string());
        } else if field.name() == "correlation_id" {
            self.correlation_id = Some(format!("{value:?}").trim_matches('"').to_string());
        } else if field.name() == "configured_level" {
            self.configured_level = Some(format!("{value:?}").trim_matches('"').to_string());
        } else if field.name() == "connection_id" {
            let rendered = format!("{value:?}").trim_matches('"').to_string();
            if let Ok(parsed) = rendered.parse::<u64>() {
                self.connection_id = Some(parsed);
            }
        }
    }
}

fn preview_plugin(preview_bytes: u64) -> WsFrameLogging {
    WsFrameLogging::new(&json!({
        "include_payload_preview": true,
        "payload_preview_bytes": preview_bytes,
    }))
    .expect("valid config")
}

fn install_ws_log_capture(capture: &WsLogCapture) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::registry().with(capture.layer());
    tracing::subscriber::set_default(subscriber)
}

/// Install a capture subscriber filtered like the gateway EnvFilter
/// (`FERRUM_LOG_LEVEL` / `RUST_LOG` directive, default `warn`).
///
/// Construction admission is probed via the active dispatcher's
/// `register_callsite` (not process-global `tracing::enabled!` interest), so
/// this helper only needs to rebuild interest so the construction `warn!`
/// itself is not stuck at cached `Interest::never` from earlier bare
/// constructions in the parallel suite.
fn install_filtered_ws_log_capture(
    directive: &str,
    capture: &WsLogCapture,
) -> tracing::subscriber::DefaultGuard {
    let subscriber =
        tracing_subscriber::registry().with(capture.layer().with_filter(EnvFilter::new(directive)));
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    guard
}

fn disconnect_context(metadata: HashMap<String, String>) -> WsDisconnectContext {
    disconnect_context_with_id(0, metadata)
}

fn disconnect_context_with_id(
    connection_id: u64,
    metadata: HashMap<String, String>,
) -> WsDisconnectContext {
    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "ws-proxy".to_string(),
        proxy_name: Some("websocket".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://127.0.0.1:9001/socket".to_string(),
        listen_port: 8000,
        connection_id,
        duration_ms: 1.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 4,
        bytes_backend_to_client: 4,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        metadata,
    }
}

async fn log_frame(plugin: &WsFrameLogging, connection_id: u64, message: &Message) {
    plugin
        .on_ws_frame(
            "test-proxy",
            connection_id,
            WebSocketFrameDirection::ClientToBackend,
            message,
        )
        .await;
}

fn assert_fingerprint_shape(preview: &str, len: usize) {
    let len_suffix = format!(" len={len}");
    assert!(preview.starts_with("hmac-sha256:"), "got: {preview}");
    assert!(preview.ends_with(&len_suffix), "got: {preview}");

    let digest = preview
        .strip_prefix("hmac-sha256:")
        .and_then(|value| value.strip_suffix(&len_suffix))
        .expect("fingerprint digest segment");
    let hex_part = digest.strip_suffix('+').unwrap_or(digest);
    assert_eq!(hex_part.len(), 12, "expected 12 hex chars, got: {hex_part}");
    assert!(
        hex_part.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "non-hex chars in fingerprint: {hex_part}"
    );
}

// === Plugin creation and metadata ===

#[test]
fn test_creation_defaults() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ws_frame_logging");
    assert_eq!(plugin.priority(), 9050);
    assert_eq!(plugin.configured_log_level(), DEFAULT_LOG_LEVEL);
    assert_eq!(plugin.configured_log_level(), "info");
    assert_eq!(plugin.payload_preview_bytes(), 128);
    assert!(plugin.requires_ws_frame_hooks());
    assert_eq!(
        plugin_failure_policy("ws_frame_logging"),
        Some(PluginFailurePolicy::OptionalFailOpen)
    );
}

// === Config validation ===

#[test]
fn test_creation_rejects_unknown_log_level() {
    let result = WsFrameLogging::new(&json!({"log_level": "error"}));
    assert!(result.is_err());
    let msg = result.err().unwrap();
    assert!(msg.contains("log_level"), "msg: {msg}");
    assert!(msg.contains("error"), "msg: {msg}");
}

#[test]
fn test_creation_rejects_unknown_config_keys() {
    let err = WsFrameLogging::new(&json!({"log_levle": "debug"}))
        .err()
        .expect("typo keys must be rejected");
    assert!(err.contains("unknown configuration key"), "got: {err}");
    assert!(err.contains("log_levle"), "got: {err}");
    for key in WS_FRAME_LOGGING_CONFIG_KEYS {
        assert!(err.contains(key), "allowed-key list missing {key}: {err}");
    }

    let err = validate_plugin_config("ws_frame_logging", &json!({"payload_preview_byte": 64}))
        .expect_err("shared validation must reject unknown keys");
    assert!(err.contains("payload_preview_byte"), "got: {err}");
}

#[test]
fn test_creation_rejects_null_field_values() {
    for (config, field) in [
        (json!({"log_level": null}), "log_level"),
        (
            json!({"include_payload_preview": null}),
            "include_payload_preview",
        ),
        (
            json!({"payload_preview_bytes": null}),
            "payload_preview_bytes",
        ),
        (json!({"log_ping_pong": null}), "log_ping_pong"),
    ] {
        let err = WsFrameLogging::new(&config)
            .err()
            .unwrap_or_else(|| panic!("null {field} must be rejected"));
        assert!(err.contains(field), "got: {err}");
        assert!(err.contains("null"), "got: {err}");
    }
}

#[test]
fn test_creation_rejects_non_object_config() {
    let result = WsFrameLogging::new(&json!("not-an-object"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("JSON object"));
}

#[test]
fn test_creation_rejects_uppercase_log_level() {
    // Per plugin-validation rules, exact-match lowercase only.
    let result = WsFrameLogging::new(&json!({"log_level": "INFO"}));
    assert!(result.is_err());
}

#[test]
fn test_creation_rejects_non_string_log_level() {
    let result = WsFrameLogging::new(&json!({"log_level": 1}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("log_level"));
}

#[test]
fn test_creation_accepts_valid_log_levels() {
    for level in ["trace", "debug", "info", "warn"] {
        let plugin = WsFrameLogging::new(&json!({"log_level": level})).unwrap_or_else(|e| {
            panic!("expected '{level}' to be accepted but got: {e}");
        });
        assert_eq!(plugin.configured_log_level(), level);
    }
}

#[test]
fn test_creation_rejects_non_bool_include_payload_preview() {
    let result = WsFrameLogging::new(&json!({"include_payload_preview": "yes"}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("include_payload_preview"));
}

#[test]
fn test_creation_rejects_non_bool_log_ping_pong() {
    let result = WsFrameLogging::new(&json!({"log_ping_pong": 1}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("log_ping_pong"));
}

#[test]
fn test_creation_rejects_non_integer_payload_preview_bytes() {
    let result = WsFrameLogging::new(&json!({"payload_preview_bytes": "128"}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("payload_preview_bytes"));
}

#[test]
fn test_supported_protocols_websocket_only() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, WS_ONLY_PROTOCOLS);
    assert!(protocols.contains(&ProxyProtocol::WebSocket));
    assert!(!protocols.contains(&ProxyProtocol::Http));
    assert!(!protocols.contains(&ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ProxyProtocol::Tcp));
    assert!(!protocols.contains(&ProxyProtocol::Udp));
}

#[test]
fn test_requires_ws_frame_hooks() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    assert!(plugin.requires_ws_frame_hooks());
}

#[tokio::test]
async fn correlation_id_composition_reaches_generated_and_preserved_disconnect_logs() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let correlation = CorrelationId::new(&json!({})).expect("valid correlation config");
    let external_correlation = CorrelationId::new(&json!({
        "header_name": "x-external-correlation-id"
    }))
    .expect("valid external correlation config");
    let logger = WsFrameLogging::new(&json!({})).expect("valid WebSocket logger config");

    for inbound in [None, Some("ws-preserved-id")] {
        let mut request_ctx = super::plugin_utils::create_test_context();
        if let Some(inbound) = inbound {
            request_ctx
                .headers
                .insert("x-request-id".to_string(), inbound.to_string());
        }
        request_ctx.headers.insert(
            "x-external-correlation-id".to_string(),
            "attacker-controlled-alias".to_string(),
        );
        correlation.on_request_received(&mut request_ctx).await;
        external_correlation
            .on_request_received(&mut request_ctx)
            .await;
        let expected = request_ctx
            .metadata
            .get(ferrum_edge::plugins::REQUEST_ID_METADATA_KEY)
            .expect("canonical request ID")
            .clone();
        assert_ne!(expected, "attacker-controlled-alias");

        logger
            .on_ws_disconnect(&disconnect_context(request_ctx.metadata.clone()))
            .await;

        let event = capture
            .events()
            .into_iter()
            .rev()
            .find(|event| event.event.as_deref() == Some("disconnect"))
            .expect("disconnect log event");
        assert_eq!(event.correlation_id.as_deref(), Some(expected.as_str()));
        if inbound.is_none() {
            assert!(uuid::Uuid::parse_str(&expected).is_ok());
        }
    }
}

#[tokio::test]
async fn disconnect_log_falls_back_to_legacy_custom_correlation_metadata() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let logger = WsFrameLogging::new(&json!({})).expect("valid WebSocket logger config");

    logger
        .on_ws_disconnect(&disconnect_context(HashMap::from([(
            "correlation_id".to_string(),
            "legacy-custom-id".to_string(),
        )])))
        .await;

    let event = capture
        .events()
        .into_iter()
        .find(|event| event.event.as_deref() == Some("disconnect"))
        .expect("disconnect log event");
    assert_eq!(event.correlation_id.as_deref(), Some("legacy-custom-id"));

    logger
        .on_ws_disconnect(&disconnect_context(HashMap::from([
            ("request_id".to_string(), "canonical-request-id".to_string()),
            ("correlation_id".to_string(), "legacy-custom-id".to_string()),
        ])))
        .await;
    let event = capture
        .events()
        .into_iter()
        .rev()
        .find(|event| event.event.as_deref() == Some("disconnect"))
        .expect("disconnect log event");
    assert_eq!(
        event.correlation_id.as_deref(),
        Some("canonical-request-id")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_sessions_share_connection_id_across_frame_and_disconnect() {
    // Issue #2560: frame events already carry connection_id; disconnect must
    // emit the same admission ID so interleaved concurrent sessions remain
    // joinable without a per-frame lookup map.
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let logger = WsFrameLogging::new(&json!({})).expect("valid WebSocket logger config");

    let session_a = 41u64;
    let session_b = 42u64;
    let msg_a = Message::Text("alpha".into());
    let msg_b = Message::Text("beta".into());

    log_frame(&logger, session_a, &msg_a).await;
    log_frame(&logger, session_b, &msg_b).await;
    log_frame(&logger, session_a, &msg_a).await;
    logger
        .on_ws_disconnect(&disconnect_context_with_id(session_b, HashMap::new()))
        .await;
    logger
        .on_ws_disconnect(&disconnect_context_with_id(session_a, HashMap::new()))
        .await;

    let events = capture.events();
    let frames: Vec<_> = events
        .iter()
        .filter(|e| e.event.is_none())
        .collect();
    let disconnects: Vec<_> = events
        .iter()
        .filter(|e| e.event.as_deref() == Some("disconnect"))
        .collect();

    assert_eq!(frames.len(), 3, "expected three frame events: {events:?}");
    assert_eq!(
        disconnects.len(),
        2,
        "expected two disconnect events: {events:?}"
    );
    assert_eq!(frames[0].connection_id, Some(session_a));
    assert_eq!(frames[1].connection_id, Some(session_b));
    assert_eq!(frames[2].connection_id, Some(session_a));
    assert_eq!(disconnects[0].connection_id, Some(session_b));
    assert_eq!(disconnects[1].connection_id, Some(session_a));

    for &id in &[session_a, session_b] {
        let frame_ids: Vec<_> = frames
            .iter()
            .filter_map(|e| e.connection_id)
            .filter(|cid| *cid == id)
            .collect();
        assert!(
            !frame_ids.is_empty(),
            "session {id} must appear in frame stream"
        );
        assert!(
            disconnects.iter().any(|e| e.connection_id == Some(id)),
            "session {id} disconnect must reuse frame-stream connection_id"
        );
    }
}

// === on_ws_frame always returns None (never transforms) ===

#[tokio::test]
async fn test_text_frame_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Text("hello world".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(
        result.is_none(),
        "ws_frame_logging must never transform frames"
    );
}

#[tokio::test]
async fn test_binary_frame_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Binary(vec![1, 2, 3, 4, 5].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_backend_to_client_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Text("response data".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::BackendToClient,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Ping/Pong logging control ===

#[tokio::test]
async fn test_ping_skipped_by_default() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Ping(vec![1, 2, 3].into());
    // Should still return None (passthrough), just doesn't log
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_pong_skipped_by_default() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Pong(vec![1, 2, 3].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_ping_logged_when_enabled() {
    let plugin = WsFrameLogging::new(&json!({"log_ping_pong": true})).unwrap();
    let msg = Message::Ping(vec![1, 2, 3].into());
    // Still returns None — logging is a side effect
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Config variations ===

#[tokio::test]
async fn test_with_payload_preview_enabled() {
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 10}))
            .unwrap();
    let msg = Message::Text("this is a longer message that should be truncated".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_binary_payload_preview() {
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 4}))
            .unwrap();
    let msg = Message::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_log_level_debug() {
    let plugin = WsFrameLogging::new(&json!({"log_level": "debug"})).unwrap();
    let msg = Message::Text("test".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_log_level_trace() {
    let plugin = WsFrameLogging::new(&json!({"log_level": "trace"})).unwrap();
    let msg = Message::Text("test".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Different connection IDs ===

#[tokio::test]
async fn test_different_connection_ids_all_passthrough() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    let msg = Message::Text("test".into());

    for conn_id in 0..5 {
        let result = plugin
            .on_ws_frame(
                "test-proxy",
                conn_id,
                WebSocketFrameDirection::ClientToBackend,
                &msg,
            )
            .await;
        assert!(result.is_none());
    }
}

// === UTF-8 payload fingerprinting ===

#[tokio::test]
async fn test_payload_preview_truncates_at_utf8_boundary() {
    // "héllo" is 6 bytes: h(1) é(2) l(1) l(1) o(1)
    // With payload_preview_bytes=3, the hashed byte prefix lands on a UTF-8 boundary.
    // The fingerprint path must not interpret the prefix as text or panic.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 3}))
            .unwrap();
    let msg = Message::Text("héllo".into());
    // Should not panic even though earlier raw-preview logic had to slice text.
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_payload_preview_with_4byte_emoji() {
    // The emoji is 4 bytes. A 2-byte fingerprint budget cuts through it, which
    // is safe because the preview hashes bytes instead of slicing a string.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 2}))
            .unwrap();
    let msg = Message::Text("🦀hello".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_payload_preview_exact_char_boundary() {
    // "abc" is 3 bytes. With preview_bytes=3, the full text is hashed.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 3}))
            .unwrap();
    let msg = Message::Text("abc".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[test]
fn test_payload_preview_bytes_zero_rejected_when_preview_enabled() {
    let err =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 0}))
            .err()
            .expect("zero-byte payload fingerprints must be rejected");
    assert!(err.contains("payload_preview_bytes"), "got: {err}");
}

#[test]
fn test_payload_preview_bytes_accepts_exact_maximum() {
    let plugin = WsFrameLogging::new(&json!({
        "include_payload_preview": true,
        "payload_preview_bytes": MAX_PAYLOAD_PREVIEW_BYTES,
    }))
    .expect("exact OpenAPI maximum must be accepted");
    assert_eq!(
        plugin.payload_preview_bytes(),
        MAX_PAYLOAD_PREVIEW_BYTES as usize
    );
}

#[test]
fn test_payload_preview_bytes_rejects_above_maximum() {
    for oversize in [MAX_PAYLOAD_PREVIEW_BYTES + 1, 999_999_999] {
        let err = WsFrameLogging::new(&json!({
            "include_payload_preview": true,
            "payload_preview_bytes": oversize,
        }))
        .err()
        .unwrap_or_else(|| panic!("{oversize} must be rejected, not clamped"));
        assert!(err.contains("payload_preview_bytes"), "got: {err}");
        assert!(err.contains(&oversize.to_string()), "got: {err}");

        let err = validate_plugin_config(
            "ws_frame_logging",
            &json!({
                "include_payload_preview": true,
                "payload_preview_bytes": oversize,
            }),
        )
        .err()
        .unwrap_or_else(|| panic!("shared validation must reject {oversize}"));
        assert!(err.contains("payload_preview_bytes"), "got: {err}");
    }
}

#[tokio::test]
async fn test_payload_preview_all_multibyte_chars() {
    // All 2-byte characters: "ñ" = 2 bytes each. "ñññ" = 6 bytes.
    // With preview_bytes=5, the hashed byte prefix cuts through the final char.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 5}))
            .unwrap();
    let msg = Message::Text("ñññ".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Empty frames ===

#[tokio::test]
async fn test_empty_text_frame() {
    let plugin = WsFrameLogging::new(&json!({"include_payload_preview": true})).unwrap();
    let msg = Message::Text(String::new().into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_empty_binary_frame() {
    let plugin = WsFrameLogging::new(&json!({"include_payload_preview": true})).unwrap();
    let msg = Message::Binary(vec![].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none());
}

// === Payload fingerprint logging ===

#[tokio::test(flavor = "current_thread")]
async fn test_text_payload_preview_logs_fingerprint_without_raw_payload() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(4096);
    let secret = "Bearer sk-live-supersecret-token-AKIA1234567890";
    let raw = format!("{{\"type\":\"connection_init\",\"Authorization\":\"{secret}\"}}");

    log_frame(&plugin, 1, &Message::Text(raw.clone().into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 1, "expected one preview log");
    let preview = &previews[0];
    assert_fingerprint_shape(preview, raw.len());
    for leaked in [
        secret,
        "supersecret",
        "Bearer",
        "Authorization",
        "connection_init",
        raw.as_str(),
    ] {
        assert!(
            !preview.contains(leaked),
            "preview leaked sensitive content {leaked:?}: {preview}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_binary_payload_preview_logs_fingerprint_without_raw_hex() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(4096);
    let payload: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];

    log_frame(&plugin, 1, &Message::Binary(payload.clone().into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 1, "expected one preview log");
    let preview = &previews[0];
    assert_fingerprint_shape(preview, payload.len());
    assert!(
        !preview.contains("deadbeefcafe"),
        "binary payload hex leaked: {preview}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_payload_preview_correlates_within_plugin_instance() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(4096);

    log_frame(&plugin, 1, &Message::Text("hello world".into())).await;
    log_frame(&plugin, 2, &Message::Text("hello world".into())).await;
    log_frame(&plugin, 3, &Message::Text("different".into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 3, "expected three preview logs");
    assert_eq!(
        previews[0], previews[1],
        "identical payloads must share a fingerprint"
    );
    assert_ne!(
        previews[0], previews[2],
        "different payloads must not share a fingerprint"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_payload_preview_key_differs_between_plugin_instances() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let first = preview_plugin(4096);
    let second = preview_plugin(4096);
    let payload = Message::Text("{\"type\":\"connection_init\",\"password\":\"guessable\"}".into());

    log_frame(&first, 1, &payload).await;
    log_frame(&second, 2, &payload).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 2, "expected two preview logs");
    assert_ne!(
        previews[0], previews[1],
        "same payload should not be confirmable across plugin keys"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_truncated_payload_preview_is_flagged_and_reports_full_len() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let plugin = preview_plugin(8);
    let raw = "0123456789abcdef";

    log_frame(&plugin, 1, &Message::Text(raw.into())).await;
    log_frame(&plugin, 2, &Message::Text("12345678".into())).await;

    let previews = capture.previews();
    assert_eq!(previews.len(), 2, "expected two preview logs");
    assert_fingerprint_shape(&previews[0], raw.len());
    assert!(
        previews[0].contains("+ len=16"),
        "truncated digest must carry a '+' marker, got: {}",
        previews[0]
    );
    assert!(
        !previews[0].contains(raw),
        "raw content leaked: {}",
        previews[0]
    );
    assert_fingerprint_shape(&previews[1], 8);
    assert!(
        !previews[1].contains('+'),
        "non-truncated digest must not carry '+': {}",
        previews[1]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_payload_preview_omitted_when_disabled_or_control_frame() {
    let capture = WsLogCapture::default();
    let _guard = install_ws_log_capture(&capture);
    let disabled = WsFrameLogging::new(&json!({})).expect("valid config");
    let control = WsFrameLogging::new(&json!({
        "include_payload_preview": true,
        "log_ping_pong": true,
    }))
    .expect("valid config");

    log_frame(&disabled, 1, &Message::Text("anything".into())).await;
    log_frame(&control, 2, &Message::Ping(vec![1, 2].into())).await;
    log_frame(&control, 3, &Message::Pong(vec![3, 4].into())).await;
    log_frame(&control, 4, &Message::Close(None)).await;

    let events = capture.events();
    assert_eq!(events.len(), 4, "expected four ws_frame_log events");
    assert!(
        events.iter().all(|event| event.preview.is_none()),
        "preview should be omitted for disabled previews and control frames: {events:?}"
    );
}

// === Default gateway filter visibility (#2617) ===

#[tokio::test(flavor = "current_thread")]
async fn default_empty_config_warns_when_default_gateway_filter_hides_records() {
    let capture = WsLogCapture::default();
    let _guard = install_filtered_ws_log_capture("warn", &capture);
    let plugin = WsFrameLogging::new(&json!({})).expect("empty config");
    assert_eq!(plugin.configured_log_level(), "info");
    assert!(
        plugin.requires_ws_frame_hooks(),
        "enabled plugin must keep the parsed/frame-hook path (H1 raw tunnel unavailable)"
    );

    let construction_events = capture.events();
    assert_eq!(
        construction_events.len(),
        1,
        "default warn filter must retain one actionable construction warning: {construction_events:?}"
    );
    assert_eq!(
        construction_events[0].configured_level.as_deref(),
        Some("info")
    );

    log_frame(&plugin, 1, &Message::Text("hello".into())).await;
    plugin
        .on_ws_disconnect(&disconnect_context(HashMap::new()))
        .await;

    assert_eq!(
        capture.events().len(),
        1,
        "healthy info frame/disconnect records must remain filtered at warn"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_levels_respect_gateway_filter_combinations() {
    for (plugin_level, filter, expect_visible) in [
        ("trace", "warn", false),
        ("debug", "warn", false),
        ("info", "warn", false),
        ("warn", "warn", true),
        ("trace", "trace", true),
        ("debug", "debug", true),
        ("info", "info", true),
        ("warn", "error", false),
    ] {
        // Construct before installing the filtered subscriber so construction
        // diagnostics cannot contaminate per-frame visibility assertions.
        let plugin = WsFrameLogging::new(&json!({"log_level": plugin_level}))
            .unwrap_or_else(|e| panic!("level {plugin_level}: {e}"));
        assert!(
            plugin.requires_ws_frame_hooks(),
            "frame-hook selection must remain true even when records are filtered"
        );

        let capture = WsLogCapture::default();
        let _guard = install_filtered_ws_log_capture(filter, &capture);
        log_frame(&plugin, 1, &Message::Text("frame".into())).await;
        let visible = !capture.events().is_empty();
        assert_eq!(
            visible, expect_visible,
            "plugin={plugin_level} filter={filter}: visibility={visible}, expected={expect_visible}"
        );
    }
}
