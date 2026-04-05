//! Tests for ws_frame_logging plugin

use ferrum_edge::plugins::ws_frame_logging::WsFrameLogging;
use ferrum_edge::plugins::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;

// === Plugin creation and metadata ===

#[test]
fn test_creation_defaults() {
    let plugin = WsFrameLogging::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ws_frame_logging");
    assert_eq!(plugin.priority(), 9050);
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

// === UTF-8 boundary truncation ===

#[tokio::test]
async fn test_payload_preview_truncates_at_utf8_boundary() {
    // "héllo" is 6 bytes: h(1) é(2) l(1) l(1) o(1)
    // With payload_preview_bytes=3, the boundary at 3 is inside the 'é' (bytes 1-2).
    // The code should back up to byte 1 ("h") rather than splitting mid-character.
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 3}))
            .unwrap();
    let msg = Message::Text("héllo".into());
    // Should not panic — produces a valid UTF-8 slice
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
    // 🦀 is 4 bytes. With preview_bytes=2, should truncate to empty (can't split emoji).
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
    // "abc" is 3 bytes. With preview_bytes=3, should get full "abc" without "...".
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

#[tokio::test]
async fn test_payload_preview_bytes_zero_produces_empty() {
    // payload_preview_bytes=0 should not panic, produces empty preview
    let plugin =
        WsFrameLogging::new(&json!({"include_payload_preview": true, "payload_preview_bytes": 0}))
            .unwrap();
    let msg = Message::Text("hello".into());
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
async fn test_payload_preview_bytes_clamped_to_max() {
    // Very large payload_preview_bytes should be clamped (not cause OOM)
    let plugin = WsFrameLogging::new(
        &json!({"include_payload_preview": true, "payload_preview_bytes": 999999999}),
    )
    .unwrap();
    let msg = Message::Binary(vec![0xAB; 100].into());
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
async fn test_payload_preview_all_multibyte_chars() {
    // All 2-byte characters: "ñ" = 2 bytes each. "ñññ" = 6 bytes.
    // With preview_bytes=5, the boundary at 5 splits "ñ" (bytes 4-5), should back up to byte 4 ("ññ").
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
