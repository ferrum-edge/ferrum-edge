//! Tests for ws_rate_limiting plugin

use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::ws_rate_limiting::WsRateLimiting;
use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection, priority,
};
use serde_json::json;
use std::sync::atomic::Ordering;
use tokio_tungstenite::tungstenite::protocol::Message;

// === Plugin creation and metadata ===

#[test]
fn test_creation_defaults() {
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "ws_rate_limiting");
    assert_eq!(plugin.priority(), priority::WS_RATE_LIMITING);
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[test]
fn test_supported_protocols_websocket_only() {
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default()).unwrap();
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
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default()).unwrap();
    assert!(plugin.requires_ws_frame_hooks());
    assert!(!plugin.observes_ws_frame_decisions());
}

#[test]
fn test_tracked_keys_count_starts_at_zero() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 10}),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

// === Frames within limit pass ===

#[tokio::test]
async fn test_frames_within_limit_pass() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 5}),
        PluginHttpClient::default(),
    )
    .unwrap();
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
    )
    .unwrap();
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

    // 4th should be rejected with close code 1008 and exported by the
    // aggregate limiter metric.
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.rate_limit_exceeded.load(Ordering::Relaxed);
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
    assert!(registry.rate_limit_exceeded.load(Ordering::Relaxed) > before);
}

// === Per-connection isolation ===

#[tokio::test]
async fn test_per_connection_isolation() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 2}),
        PluginHttpClient::default(),
    )
    .unwrap();
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
    )
    .unwrap();
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
    )
    .unwrap();
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
    )
    .unwrap();
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
    )
    .unwrap();
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
    )
    .unwrap();
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
    )
    .unwrap();

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
    )
    .unwrap();
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
async fn test_zero_fps_returns_error() {
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 0}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("frames_per_second"));
}

#[test]
fn test_zero_burst_size_returns_error() {
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 100, "burst_size": 0}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("burst_size"));
}

#[test]
fn test_burst_size_smaller_than_fps_returns_error() {
    // The Redis sliding-window approximation assumes burst >= fps so the
    // derived window stays >= 1s and sustained rate matches fps. Reject
    // burst < fps at construction to keep local and Redis paths aligned.
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 100, "burst_size": 50}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        err.contains("burst_size"),
        "expected burst_size error, got: {err}"
    );
    assert!(
        err.contains("frames_per_second"),
        "expected fps mention, got: {err}"
    );
}

#[test]
fn test_nonintegral_burst_fps_ratio_returns_error() {
    // GHSA-cjcm-546w-696v: ceil(burst/fps) windows under-admit non-integral
    // ratios on Redis (e.g. 75/50 → 37.5 fps). Reject them so accepted
    // configs keep local/Redis sustained-rate parity.
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 50, "burst_size": 75}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        err.contains("integer multiple"),
        "expected integer-multiple rejection, got: {err}"
    );
}

#[test]
fn test_overlong_refill_window_returns_error() {
    // GHSA-cjcm-546w-696v: clamping window to 3600s while retaining burst as
    // the limit over-admits (e.g. 3601 / 3600 ≈ 1.0003 fps vs configured 1,
    // or historically 10_000_000 / 3600 ≈ 2778 fps). Keep burst within the
    // operational ceiling so this asserts the window-parity gate specifically.
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "burst_size": 3601}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        err.contains("Redis-representable maximum"),
        "expected overlong-window rejection, got: {err}"
    );
}

#[test]
fn test_pathological_advisory_burst_is_rejected() {
    // Advisory reproduction values exceed both the operational burst ceiling
    // and the Redis-representable refill window; either gate is fail-closed.
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "burst_size": 10_000_000}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        err.contains("burst_size") || err.contains("Redis-representable"),
        "expected fail-closed rejection of advisory reproduction, got: {err}"
    );
}

#[test]
fn test_integral_ratio_at_max_window_is_accepted() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "burst_size": 3600}),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok(), "{:?}", plugin.err());
}

#[test]
fn test_fps_and_burst_upper_bounds_are_enforced() {
    let over = 1_000_001u64;
    let err = WsRateLimiting::new(
        &json!({"frames_per_second": over}),
        PluginHttpClient::default(),
    )
    .err()
    .expect("fps above operational ceiling must be rejected");
    assert!(err.contains("frames_per_second"), "{err}");

    let err = WsRateLimiting::new(
        &json!({"frames_per_second": 100, "burst_size": over}),
        PluginHttpClient::default(),
    )
    .err()
    .expect("burst above operational ceiling must be rejected");
    assert!(err.contains("burst_size"), "{err}");
}

#[test]
fn test_non_object_config_returns_error() {
    let result = WsRateLimiting::new(&json!("bad"), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_invalid_numeric_config_returns_error() {
    for config in [
        json!({"frames_per_second": "100"}),
        json!({"burst_size": "10"}),
        json!({"frames_per_second": -1}),
        json!({"frames_per_second": 100, "sync_mode": "database"}),
    ] {
        let result = WsRateLimiting::new(&config, PluginHttpClient::default());
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_invalid_close_reason_type_returns_error() {
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 100, "close_reason": true}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("close_reason"));
}

#[test]
fn test_rejects_unknown_root_keys() {
    let error = WsRateLimiting::new(&json!({"frames_per_secod": 1}), PluginHttpClient::default())
        .err()
        .expect("misspelled frames_per_second must fail admission");
    assert!(error.contains("unknown configuration key(s)"), "{error}");
    assert!(error.contains("frames_per_secod"), "{error}");
    assert!(error.contains("frames_per_second"), "{error}");

    let error = WsRateLimiting::new(
        &json!({
            "frames_per_second": 10,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_tsl": true,
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("misspelled redis_tls must fail admission");
    assert!(error.contains("redis_tsl"), "{error}");
    assert!(error.contains("redis_tls"), "{error}");
}

#[test]
fn test_accepts_every_documented_root_key() {
    WsRateLimiting::new(
        &json!({
            "frames_per_second": 10,
            "burst_size": 20,
            "close_reason": "slow down",
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_tls": false,
            "redis_key_prefix": "explicit:prefix",
            "redis_pool_size": 4,
            "redis_connect_timeout_seconds": 5,
            "redis_health_check_interval_seconds": 5,
            "redis_username": "user",
            "redis_password": "pass",
            "redis_failure_policy": "local_fallback",
        }),
        PluginHttpClient::default(),
    )
    .expect("the documented root key set must remain accepted");
}

#[test]
fn test_redis_tls_posture_is_parsed_without_echoing_credentials() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::RedisConfig;

    let cfg = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://user:secret@cache.internal:6379/0",
            "redis_tls": true,
        }),
        "test",
    )
    .expect("redis config must parse")
    .expect("redis mode must produce a config");
    assert!(cfg.tls);
    assert_eq!(cfg.redacted_url(), "redis://redacted@cache.internal:6379/0");
    assert_eq!(cfg.hostname(), Some("cache.internal".to_string()));
}

// === Eviction logic ===

#[tokio::test]
async fn test_stale_entries_persist_until_sampled_sweep() {
    // Below-cap stale pruning runs on the sampled periodic interval (every
    // 100_000 frames), not on every frame. A handful of frames therefore keeps
    // idle keys until that sampled sweep; controllable-time coverage for the
    // prune itself lives in rate_limit_cleanup_tests.
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1000}),
        PluginHttpClient::default(),
    )
    .unwrap();
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

    // Add a 4th connection — still far below the sampled sweep interval.
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
        "Stale entries persist until the sampled periodic sweep"
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
async fn test_zero_fps_buckets_returns_error() {
    // Zero FPS is now rejected at construction time
    let result = WsRateLimiting::new(
        &json!({"frames_per_second": 0}),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

// === Connection ID edge cases ===

#[tokio::test]
async fn test_connection_id_zero_works() {
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 10}),
        PluginHttpClient::default(),
    )
    .unwrap();
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
    )
    .unwrap();
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

#[test]
fn test_redis_connection_scope_key_is_namespaced_per_instance() {
    let key_a = ferrum_edge::_test_support::ws_rate_limiter_scope_key("proxy-a", 7);
    let key_b = ferrum_edge::_test_support::ws_rate_limiter_scope_key("proxy-a", 7);
    assert_ne!(key_a, key_b);
    assert!(key_a.ends_with(":proxy-a:7"));
    assert!(key_b.ends_with(":proxy-a:7"));
}

/// Public surfaces must retain the instance-scoped Redis limitation from the
/// detailed plugin reference (`docs/plugins.md` / `docs/plugin_execution_order.md`)
/// and must not claim portable cross-instance frame-budget coordination.
#[test]
fn test_public_docs_retain_instance_scoped_redis_semantics() {
    let readme = include_str!("../../../README.md");
    let features = include_str!("../../../FEATURES.md");
    let plugins = include_str!("../../../docs/plugins.md");
    let order = include_str!("../../../docs/plugin_execution_order.md");

    assert!(
        !readme.contains(
            "All three rate limiting plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`) support centralized mode via `sync_mode: \"redis\"` for coordinated limits across multiple gateway instances"
        ),
        "README must not unqualifiedly group ws_rate_limiting with portable-identity distributed limiters"
    );
    assert!(
        readme.contains("externalize per-connection frame counters")
            && readme.contains("per-plugin/gateway-instance Redis namespace"),
        "README must describe instance-scoped Redis externalization for ws_rate_limiting"
    );

    assert!(
        !features.contains("cross-instance frame rate coordination"),
        "FEATURES must not promise cross-instance frame rate coordination for ws_rate_limiting"
    );
    assert!(
        features.contains("externalizes per-connection counters")
            && features.contains("per-plugin/gateway-instance key namespacing")
            && features.contains("not portable across reconnects or rebuilds"),
        "FEATURES must retain the instance-scoped Redis limitation"
    );

    // Parse OpenAPI so folded YAML descriptions are checked as rendered text,
    // not raw source lines that may wrap mid-phrase.
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let ws_schema = &spec["components"]["schemas"]["WsRateLimitingConfig"];
    assert_eq!(ws_schema["additionalProperties"], json!(false));
    let schema_description = ws_schema["description"]
        .as_str()
        .expect("WsRateLimitingConfig description");
    let sync_mode_description = ws_schema["properties"]["sync_mode"]["description"]
        .as_str()
        .expect("WsRateLimitingConfig.sync_mode description");
    let prefix_description = ws_schema["properties"]["redis_key_prefix"]["description"]
        .as_str()
        .expect("WsRateLimitingConfig.redis_key_prefix description");
    let openapi_descriptions =
        format!("{schema_description}\n{sync_mode_description}\n{prefix_description}");
    let normalized_openapi = openapi_descriptions
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(
        !normalized_openapi.contains("cross-instance coordination of frame counters"),
        "OpenAPI must not claim cross-instance coordination for ws_rate_limiting"
    );
    assert!(
        normalized_openapi.contains("externalizes those")
            && normalized_openapi.contains("per-plugin/gateway-instance key")
            && normalized_openapi.contains("not a portable cross-instance budget"),
        "OpenAPI WsRateLimitingConfig/sync_mode must describe instance-scoped Redis semantics"
    );
    assert!(
        normalized_openapi.contains("per-instance UUID"),
        "OpenAPI redis_key_prefix must describe the instance UUID that partitions keys"
    );
    assert!(
        !normalized_openapi.contains("every instance configured with the same prefix increments"),
        "OpenAPI redis_key_prefix must not promise shared per-connection budgets"
    );

    assert!(
        plugins.contains("does not make per-connection limits portable across reconnects")
            && plugins.contains("Unknown top-level keys are rejected")
            && plugins.contains("per-instance UUID")
            && order.contains("rather than sharing a portable connection budget across reconnects"),
        "detailed plugin docs must keep the non-portable Redis semantics that public surfaces mirror"
    );
}

#[test]
fn test_warmup_hostnames_for_redis() {
    let plugin = WsRateLimiting::new(
        &json!({
            "frames_per_second": 100,
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["cache.internal".to_string()]
    );
}

// === Close-reason length cap (RFC 6455 §5.5 control-frame limit) ===

#[tokio::test]
async fn test_transformed_close_does_not_consume_budget_or_create_state() {
    // A Close synthesized by an earlier admission plugin must neither charge a
    // token nor create local rate-limit state. Both directions share this path.
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "burst_size": 1}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let close = Message::Close(Some(
        tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
            reason: "message too large".into(),
        },
    ));

    for direction in [
        WebSocketFrameDirection::ClientToBackend,
        WebSocketFrameDirection::BackendToClient,
    ] {
        let result = plugin.on_ws_frame("test-proxy", 7, direction, &close).await;
        assert!(
            result.is_none(),
            "Close must pass through without replacement ({direction:?})"
        );
        assert_eq!(
            plugin.tracked_keys_count(),
            Some(0),
            "Close must not create local rate-limit state ({direction:?})"
        );
    }

    // The sole burst token must still be available for a subsequent data frame.
    let text = Message::Text("hello".into());
    let allowed = plugin
        .on_ws_frame(
            "test-proxy",
            7,
            WebSocketFrameDirection::ClientToBackend,
            &text,
        )
        .await;
    assert!(
        allowed.is_none(),
        "first data frame after ignored Close must still be admitted"
    );
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn test_transformed_close_skips_redis_accounting_path() {
    // Even with Redis sync enabled, an inbound Close must return before any
    // Redis/local check. An unreachable Redis URL would otherwise fall back and
    // charge local state; that must not happen for an already-final Close.
    let plugin = WsRateLimiting::new(
        &json!({
            "frames_per_second": 1,
            "burst_size": 1,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let close = Message::Close(Some(
        tokio_tungstenite::tungstenite::protocol::frame::CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
            reason: "message too large".into(),
        },
    ));

    let result = plugin
        .on_ws_frame(
            "test-proxy",
            9,
            WebSocketFrameDirection::ClientToBackend,
            &close,
        )
        .await;
    assert!(result.is_none());
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_close_reason_is_truncated_to_websocket_limit() {
    // Construct a reason longer than 123 bytes (the RFC 6455 control-frame cap
    // after the 2-byte status code). The plugin must truncate it on a UTF-8
    // boundary before storing.
    let long_reason = "rate-".repeat(40); // 200 bytes, all ASCII
    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "close_reason": long_reason}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let msg = Message::Text("hello".into());

    // Drain the single token so the next frame returns Close
    plugin
        .on_ws_frame(
            "test-proxy",
            1,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
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
            assert!(
                cf.reason.as_str().len() <= 123,
                "close reason must be ≤ 123 bytes, got {}",
                cf.reason.as_str().len()
            );
            assert!(cf.reason.as_str().starts_with("rate-"));
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

#[tokio::test]
async fn test_close_reason_truncates_on_utf8_boundary() {
    // 124 bytes total: 122 ASCII + 1 two-byte char (é = 0xC3 0xA9). The cap of
    // 123 bytes lands inside that final char, so truncation must back up to 122.
    let mut s = "a".repeat(122);
    s.push('é');
    assert_eq!(s.len(), 124);

    let plugin = WsRateLimiting::new(
        &json!({"frames_per_second": 1, "close_reason": s}),
        PluginHttpClient::default(),
    )
    .unwrap();
    let msg = Message::Text("x".into());
    plugin
        .on_ws_frame(
            "test-proxy",
            42,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    let result = plugin
        .on_ws_frame(
            "test-proxy",
            42,
            WebSocketFrameDirection::ClientToBackend,
            &msg,
        )
        .await;
    match result.unwrap() {
        Message::Close(Some(cf)) => {
            // Should truncate to 122 bytes (the 'é' would push us to 124, > 123).
            assert_eq!(cf.reason.as_str().len(), 122);
            assert!(cf.reason.as_str().chars().all(|c| c == 'a'));
        }
        other => panic!("Expected Close frame, got {:?}", other),
    }
}

// === Redis failure policy (GHSA-87rq-v4hx-8rcq) ===

fn is_policy_close(result: &Option<Message>) -> bool {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    matches!(result, Some(Message::Close(Some(cf))) if cf.code == CloseCode::Policy)
}

fn unavailable_redis_ws_config(extra: serde_json::Value) -> serde_json::Value {
    let mut config = json!({
        "frames_per_second": 1000,
        "burst_size": 1000,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1",
        "redis_health_check_interval_seconds": 3600
    });
    let (Some(object), Some(extra)) = (config.as_object_mut(), extra.as_object()) else {
        return config;
    };
    for (key, value) in extra {
        object.insert(key.clone(), value.clone());
    }
    config
}

/// Both frame-charging entry points must fail closed while the centralized
/// store cannot be consulted.
///
/// `on_ws_reassembly_frames` charges the physical fragments of a reassembled
/// message in one batched op (GHSA-qq94-2gv2-phh6) and shares `on_ws_frame`'s
/// admission path, so a fragmented message must not slip past a budget this
/// process cannot prove. The configured budget is far larger than anything
/// charged here, so a Close can only come from the fail-closed policy.
#[tokio::test]
async fn fail_closed_policy_closes_both_frame_charging_paths_while_redis_is_unavailable() {
    let plugin = WsRateLimiting::new(
        &unavailable_redis_ws_config(json!({})),
        PluginHttpClient::default(),
    )
    .unwrap();
    let msg = Message::Text("hello".into());
    let direction = WebSocketFrameDirection::ClientToBackend;

    let message = plugin.on_ws_frame("proxy", 1, direction, &msg).await;
    let fragment = plugin
        .on_ws_reassembly_frames("proxy", 2, direction, 3)
        .await;

    assert!(
        is_policy_close(&message),
        "a reassembled message must fail closed while centralized enforcement is \
         unavailable, got {message:?}"
    );
    assert!(
        is_policy_close(&fragment),
        "a batched fragment charge must fail closed while centralized enforcement is \
         unavailable, got {fragment:?}"
    );
}

/// The availability escape hatch covers the batched fragment path too — but
/// only when the operator asks for it.
#[tokio::test]
async fn local_fallback_policy_admits_both_frame_charging_paths_while_redis_is_unavailable() {
    let plugin = WsRateLimiting::new(
        &unavailable_redis_ws_config(json!({ "redis_failure_policy": "local_fallback" })),
        PluginHttpClient::default(),
    )
    .unwrap();
    let msg = Message::Text("hello".into());
    let direction = WebSocketFrameDirection::ClientToBackend;

    let message = plugin.on_ws_frame("proxy", 1, direction, &msg).await;
    let fragment = plugin
        .on_ws_reassembly_frames("proxy", 2, direction, 3)
        .await;

    assert!(
        message.is_none(),
        "local_fallback must admit a reassembled message on per-process state"
    );
    assert!(
        fragment.is_none(),
        "local_fallback must admit a batched fragment charge on per-process state"
    );
}

/// An empty fragment batch charges nothing, so there is nothing to refuse even
/// under the fail-closed default. Zero fragments is not a free admission of
/// work — there is no work.
#[tokio::test]
async fn empty_fragment_batch_is_not_charged_under_the_fail_closed_default() {
    let plugin = WsRateLimiting::new(
        &unavailable_redis_ws_config(json!({})),
        PluginHttpClient::default(),
    )
    .unwrap();
    let direction = WebSocketFrameDirection::ClientToBackend;

    let result = plugin
        .on_ws_reassembly_frames("proxy", 3, direction, 0)
        .await;

    assert!(
        result.is_none(),
        "a zero-fragment batch must not synthesize a policy Close"
    );
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "a zero-fragment batch must not create local rate-limit state"
    );
}
