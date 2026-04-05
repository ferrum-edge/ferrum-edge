//! Tests for ws_message_size_limiting plugin

use ferrum_edge::plugins::ws_message_size_limiting::WsMessageSizeLimiting;
use ferrum_edge::plugins::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;

// === Plugin creation and metadata ===

#[test]
fn test_creation_defaults() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "ws_message_size_limiting");
    assert_eq!(plugin.priority(), 2810);
}

#[test]
fn test_supported_protocols_websocket_only() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
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
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
    assert!(plugin.requires_ws_frame_hooks());
}

// === Zero config / no-op ===

#[tokio::test]
async fn test_missing_max_frame_bytes_returns_error() {
    let result = WsMessageSizeLimiting::new(&json!({}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("max_frame_bytes"));
}

#[tokio::test]
async fn test_zero_max_frame_bytes_returns_error() {
    let result = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 0}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("max_frame_bytes"));
}

// === Text frame checks ===

#[tokio::test]
async fn test_text_frame_under_limit_passes() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 100})).unwrap();
    let msg = Message::Text("short".into());
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
async fn test_text_frame_at_limit_passes() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 5})).unwrap();
    let msg = Message::Text("12345".into()); // exactly 5 bytes
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
async fn test_text_frame_over_limit_returns_close_1009() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 5})).unwrap();
    let msg = Message::Text("123456".into()); // 6 bytes, over limit
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some());
    match result.unwrap() {
        Message::Close(Some(cf)) => {
            assert_eq!(
                cf.code,
                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size
            );
            assert_eq!(cf.reason.as_str(), "Message too large");
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

// === Binary frame checks ===

#[tokio::test]
async fn test_binary_frame_under_limit_passes() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 100})).unwrap();
    let msg = Message::Binary(vec![0u8; 50].into());
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
async fn test_binary_frame_over_limit_returns_close() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 10})).unwrap();
    let msg = Message::Binary(vec![0u8; 11].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some());
    assert!(matches!(result.unwrap(), Message::Close(Some(_))));
}

// === Ping frame checks ===

#[tokio::test]
async fn test_ping_frame_under_limit_passes() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 100})).unwrap();
    let msg = Message::Ping(vec![1, 2, 3].into());
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
async fn test_ping_frame_over_limit_returns_close() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 2})).unwrap();
    let msg = Message::Ping(vec![1, 2, 3].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some());
    assert!(matches!(result.unwrap(), Message::Close(Some(_))));
}

// === Direction independence ===

#[tokio::test]
async fn test_enforces_in_both_directions() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 5})).unwrap();
    let large_msg = Message::Text("toolarge".into());

    // Client to backend
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &large_msg,
        )
        .await;
    assert!(result.is_some());

    // Backend to client
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::BackendToClient,
            &large_msg,
        )
        .await;
    assert!(result.is_some());
}

// === Custom close reason ===

#[tokio::test]
async fn test_custom_close_reason() {
    let plugin = WsMessageSizeLimiting::new(
        &json!({"max_frame_bytes": 5, "close_reason": "Payload exceeds proxy limit"}),
    )
    .unwrap();
    let msg = Message::Text("123456".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    match result.unwrap() {
        Message::Close(Some(cf)) => {
            assert_eq!(cf.reason.as_str(), "Payload exceeds proxy limit");
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

#[tokio::test]
async fn test_close_reason_is_truncated_to_websocket_limit() {
    let long_reason = "payload-".repeat(20);
    let plugin =
        WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 5, "close_reason": long_reason}))
            .unwrap();
    let msg = Message::Text("123456".into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    match result.unwrap() {
        Message::Close(Some(cf)) => {
            assert!(cf.reason.as_str().len() <= 123);
            assert!(cf.reason.as_str().starts_with("payload-"));
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

// === Close/Pong frames are not checked ===

#[tokio::test]
async fn test_close_frame_passthrough() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1})).unwrap();
    let msg = Message::Close(None);
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
async fn test_pong_frame_passthrough() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1})).unwrap();
    let msg = Message::Pong(vec![0; 100].into());
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    // Pong size is checked (100 bytes > 1 byte limit)
    assert!(result.is_some());
}

// === Large frame edge cases ===

#[tokio::test]
async fn test_empty_text_frame_always_passes() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1})).unwrap();
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
async fn test_empty_binary_frame_always_passes() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1})).unwrap();
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

#[tokio::test]
async fn test_large_binary_frame_rejected() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 65536})).unwrap();
    let msg = Message::Binary(vec![0u8; 65537].into()); // 1 byte over 64 KiB
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some());
    assert!(matches!(result.unwrap(), Message::Close(Some(_))));
}
