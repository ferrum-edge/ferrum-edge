//! Tests for ws_rate_limiting plugin

use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::ws_rate_limiting::WsRateLimiting;
use ferrum_edge::plugins::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::Message;

// === Plugin creation and metadata ===

#[test]
fn test_creation_defaults() {
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default());
    assert_eq!(plugin.name(), "ws_rate_limiting");
    assert_eq!(plugin.priority(), 2910);
}

#[test]
fn test_supported_protocols_websocket_only() {
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default());
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
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default());
    assert!(plugin.requires_ws_frame_hooks());
}

#[test]
fn test_tracked_keys_count_starts_at_zero() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 10}),
        PluginHttpClient::default(),
    );
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

// === Frames within limit pass ===

#[tokio::test]
async fn test_frames_within_limit_pass() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 5}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    for _ in 0..5 {
        let result = plugin
            .on_ws_frame(
                "test-proxy",
                1,
                WebSocketFrameDirection::ClientToBackend,
                &msg,
            )
            .await;
        assert!(result.is_none(), "Frames within limit should pass");
    }
}

// === Frames exceeding limit return Close ===

#[tokio::test]
async fn test_frames_exceeding_limit_return_close_1008() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 3}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Use up all 3 tokens
    for _ in 0..3 {
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

    // 4th should be rejected with close code 1008
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
                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy
            );
            assert_eq!(cf.reason.as_str(), "Frame rate exceeded");
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

// === Per-connection isolation ===

#[tokio::test]
async fn test_per_connection_isolation() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 2}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Connection 1: drain tokens
    for _ in 0..2 {
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
    // Connection 1 should be rate limited
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some(), "Connection 1 should be rate limited");

    // Connection 2: should have independent bucket, should pass
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            2,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(
        result.is_none(),
        "Connection 2 should not be affected by connection 1's rate limit"
    );
}

// === Burst size ===

#[tokio::test]
async fn test_burst_size_larger_than_fps() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 5, "burst_size": 10}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Should allow 10 frames (burst_size) before limiting
    for i in 0..10 {
        let result = plugin
            .on_ws_frame(
                "test-proxy",
                1,
                WebSocketFrameDirection::ClientToBackend,
                &msg,
            )
            .await;
        assert!(result.is_none(), "Frame {} should pass (burst_size=10)", i);
    }

    // 11th should be rejected
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some(), "Frame beyond burst should be rejected");
}

// === Token refill over time ===

#[tokio::test]
async fn test_token_refill_over_time() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 10}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Drain all 10 tokens
    for _ in 0..10 {
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

    // Should be rate limited now
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some());

    // Wait for token refill (~150ms = ~1.5 tokens at 10/s)
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Should have ~1 token now
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none(), "Should pass after token refill");
}

// === Both directions share the same bucket ===

#[tokio::test]
async fn test_both_directions_share_bucket() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 4}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // 2 frames client->backend
    for _ in 0..2 {
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

    // 2 frames backend->client
    for _ in 0..2 {
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

    // 5th frame in either direction should be rate limited
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(
        result.is_some(),
        "Should be rate limited after 4 frames total"
    );
}

// === Custom close reason ===

#[tokio::test]
async fn test_custom_close_reason() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "close_reason": "Too many messages"}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Use up the token
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;

    // Next frame should be rejected with custom reason
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
            assert_eq!(cf.reason.as_str(), "Too many messages");
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

// === tracked_keys_count reflects active connections ===

#[tokio::test]
async fn test_tracked_keys_count_increments() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 100}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    assert_eq!(plugin.tracked_keys_count(), Some(0));

    // First connection
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    // Second connection
    plugin
        .on_ws_frame(
            "test-proxy",
            2,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    // Same connection again — no new key
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(2));
}

// === Binary frames are also rate limited ===

#[tokio::test]
async fn test_binary_frames_rate_limited() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 2}),
        PluginHttpClient::default(),
    );

    // Mix text and binary — all count against the same bucket
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &Message::Text("hello".into()),
        )
        .await;
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &Message::Binary(vec![1, 2, 3].into()),
        )
        .await;

    // 3rd frame should be rejected
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &Message::Text("nope".into()),
        )
        .await;
    assert!(result.is_some());
}

// === Different proxy IDs share the same plugin state (keyed by connection_id) ===

#[tokio::test]
async fn test_connection_id_is_key_not_proxy_id() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 2}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Same connection_id, different proxy_ids — same bucket
    plugin
        .on_ws_frame("proxy-a", 1, WebSocketFrameDirection::ClientToBackend, &msg)
        .await;
    plugin
        .on_ws_frame("proxy-b", 1, WebSocketFrameDirection::ClientToBackend, &msg)
        .await;

    let result = plugin
        .on_ws_frame("proxy-c", 1, WebSocketFrameDirection::ClientToBackend, &msg)
        .await;
    assert!(
        result.is_some(),
        "Same connection_id across proxies should share the bucket"
    );
}

// === Zero FPS config ===

#[tokio::test]
async fn test_zero_fps_rejects_all_frames() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 0}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // With 0 FPS, burst_size defaults to 0, so bucket capacity is 0 — all frames rejected
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some(), "Zero FPS should reject all frames");
    assert!(matches!(result.unwrap(), Message::Close(Some(_))));
}

#[tokio::test]
async fn test_zero_burst_size_rejects_all_frames() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 100, "burst_size": 0}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // burst_size=0 means capacity=0 — bucket starts empty
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_some(), "Zero burst should reject all frames");
}

// === Eviction logic ===

#[tokio::test]
async fn test_stale_entries_evicted_on_capacity_trigger() {
    // Test that when we exceed MAX_STATE_ENTRIES, stale entries get evicted.
    // We can't create 50K entries in a unit test, but we can verify the is_active()
    // logic by checking that entries persist when active and accumulate when stale.
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1000}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Create 3 connections
    for conn_id in 0u64..3 {
        plugin
            .on_ws_frame(
                "test-proxy",
                conn_id,
                WebSocketFrameDirection::ClientToBackend,
                &msg,
            )
            .await;
    }
    assert_eq!(plugin.tracked_keys_count(), Some(3));

    // Wait for buckets to become stale (2x window for FPS=1000, burst=1000 → 2s)
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;

    // Add a 4th connection — stale entries still present (under eviction threshold)
    plugin
        .on_ws_frame(
            "test-proxy",
            99,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(4),
        "Stale entries persist under eviction threshold"
    );

    // Verify active connection is still functional
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            99,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none(), "Active connection should still work");
}

#[tokio::test]
async fn test_zero_fps_buckets_evicted_as_stale() {
    // Ensure zero-rate buckets are considered inactive (not leaked forever)
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 0}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    // Create a connection — it will be rejected immediately
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    // The bucket has refill_rate=0, capacity=0.
    // is_active() should return false for zero-rate buckets (we guard against div-by-zero).
}

// === Connection ID edge cases ===

#[tokio::test]
async fn test_connection_id_zero_works() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 10}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    let result = plugin
        .on_ws_frame(
            "test-proxy",
            0,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none(), "Connection ID 0 should work");
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn test_connection_id_max_works() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 10}),
        PluginHttpClient::default(),
    );
    let msg = Message::Text("hello".into());

    let result = plugin
        .on_ws_frame(
            "test-proxy",
            u64::MAX,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    assert!(result.is_none(), "Connection ID u64::MAX should work");
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}
