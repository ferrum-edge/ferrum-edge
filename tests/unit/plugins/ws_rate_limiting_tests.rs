//! Tests for ws_rate_limiting plugin

use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::ws_rate_limiting::WsRateLimiting;
use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection, priority,
};
use ferrum_edge::plugins::{RequestContext, WsDisconnectContext};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
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
    // burst < fps at construction when Redis sync keeps local and Redis paths
    // aligned.
    let result = WsRateLimiting::new(
        &unavailable_redis_ws_config(json!({"frames_per_second": 100, "burst_size": 50})),
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
    // Redis-synced configs keep local/Redis sustained-rate parity.
    let result = WsRateLimiting::new(
        &unavailable_redis_ws_config(json!({"frames_per_second": 50, "burst_size": 75})),
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
        &unavailable_redis_ws_config(json!({"frames_per_second": 1, "burst_size": 3601})),
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
            "limit_by": "connection",
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

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [
        (
            json!({"frames_per_second": "'UNREGISTERED_TRAFFIC_TOKEN"}),
            "`frames_per_second`",
            "must be an integer",
        ),
        (
            json!({"frames_per_second": true}),
            "`frames_per_second`",
            "must be an integer",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("ws_rate_limiting", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

#[test]
fn shared_frame_rate_relations_keep_fields_and_withhold_numeric_operands() {
    for (frames, burst, reason) in [
        (731, 730, "must be >="),
        (731, 1463, "must be an integer multiple of"),
        (1, 3731, "exceeds the Redis-representable maximum"),
    ] {
        let config =
            unavailable_redis_ws_config(json!({"frames_per_second": frames, "burst_size": burst}));
        let error = WsRateLimiting::new(&config, PluginHttpClient::default())
            .err()
            .expect("unrepresentable frame rate must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for retained in [
            "ws_rate_limiting:",
            "`frames_per_second`",
            "`burst_size`",
            reason,
        ] {
            assert!(rendered.contains(retained), "{retained}: {rendered}");
        }
        for withheld in ["731", "730", "1463", "3731"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// === Hard-cap reclamation (ws_rate_limiting-SOL-1) ===

/// Atomic admission never lets the map grow past the cap, so capacity pressure
/// must start AT the cap. A map filled exactly to the cap with idle entries is
/// reclaimed by the pre-admission eviction gate, and the next unseen session is
/// admitted, without waiting for a traffic-count-sampled sweep.
#[test]
fn idle_entries_at_the_hard_cap_are_reclaimed_before_admission() {
    use ferrum_edge::_test_support::{
        ws_rate_limiting_admits_at_production_cap_for_test as admits,
        ws_rate_limiting_max_state_entries_for_test as max_state_entries,
        ws_rate_limiting_maybe_evict_at_for_test as maybe_evict,
        ws_rate_limiting_seed_connection_for_test as seed,
    };

    // Defaults: 100 fps / burst 100 → 1 s refill window, idle after 2 s.
    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default()).unwrap();
    let cap = max_state_entries();
    let seeded_at = Instant::now();
    for connection_id in 0..cap as u64 {
        seed(&plugin, connection_id, seeded_at);
    }
    assert_eq!(plugin.tracked_keys_count(), Some(cap));
    let fresh = cap as u64;
    assert!(
        !admits(&plugin, fresh, seeded_at),
        "precondition: an unseen session is refused while the map is exactly full"
    );

    // The periodic sample is not armed: only capacity pressure can sweep.
    // Buckets record their creation instant, so stay well past the 2 s idle
    // threshold even if seeding the full map was slow.
    let idle_at = seeded_at + Duration::from_secs(30);
    let _ = maybe_evict(&plugin, idle_at);
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "idle entries at exactly the cap must be reclaimed by the capacity gate"
    );
    assert!(
        admits(&plugin, fresh, idle_at),
        "a new session must be admitted once idle state is reclaimed"
    );
}

/// The reclamation is stale-only: a map full of active budgets keeps them and
/// keeps refusing unseen sessions, while existing sessions continue.
#[test]
fn active_budgets_at_the_hard_cap_are_never_evicted() {
    use ferrum_edge::_test_support::{
        ws_rate_limiting_admits_at_production_cap_for_test as admits,
        ws_rate_limiting_max_state_entries_for_test as max_state_entries,
        ws_rate_limiting_maybe_evict_at_for_test as maybe_evict,
        ws_rate_limiting_seed_connection_for_test as seed,
    };

    let plugin = WsRateLimiting::new(&json!({}), PluginHttpClient::default()).unwrap();
    let cap = max_state_entries();
    let seeded_at = Instant::now();
    for connection_id in 0..cap as u64 {
        seed(&plugin, connection_id, seeded_at);
    }

    // Still inside the 2 s activity window of every bucket (each records its
    // creation instant, which is no earlier than `seeded_at`).
    let active_at = seeded_at + Duration::from_millis(1500);
    let _ = maybe_evict(&plugin, active_at);
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(cap),
        "active budgets must never be force-evicted"
    );
    assert!(
        !admits(&plugin, cap as u64, active_at),
        "an unseen session must still fail closed at an active cap"
    );
    assert!(
        admits(&plugin, 0, active_at),
        "an existing session continues on its own budget at the cap"
    );
}

// === Disconnect releases connection state (ws_rate_limiting-CLAUDE-1) ===

fn ws_disconnect_ctx(connection_id: u64) -> WsDisconnectContext {
    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: None,
        client_ip: "10.0.0.1".to_string(),
        backend_target: "ws://backend.local:9000/ws".to_string(),
        http_method: "GET".to_string(),
        request_path: "/ws".to_string(),
        handshake_status_code: 101,
        listen_port: 8080,
        duration_ms: 1.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 0,
        bytes_client_to_backend: 5,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01Z".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id,
        metadata: ferrum_edge::plugins::MetadataMap::default(),
    }
}

/// A long refill window keeps a bucket "active" for two hours after its last
/// frame, so only the disconnect hook can release a finished session's slot.
fn long_window_config() -> serde_json::Value {
    json!({"frames_per_second": 1, "burst_size": 3600})
}

#[tokio::test]
async fn disconnect_releases_the_finished_connection_budget() {
    let plugin = WsRateLimiting::new(&long_window_config(), PluginHttpClient::default()).unwrap();
    assert!(
        plugin.requires_ws_disconnect_hooks(),
        "connection mode must opt into disconnect hooks to release its state"
    );
    let msg = Message::Text("hello".into());
    let direction = WebSocketFrameDirection::ClientToBackend;

    assert!(
        plugin
            .on_ws_frame("test-proxy", 7, direction, &msg)
            .await
            .is_none()
    );
    assert!(
        plugin
            .on_ws_frame("test-proxy", 8, direction, &msg)
            .await
            .is_none()
    );
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    plugin.on_ws_disconnect(&ws_disconnect_ctx(7)).await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    assert!(!ferrum_edge::_test_support::ws_rate_limiting_contains_connection_for_test(&plugin, 7));
    assert!(
        ferrum_edge::_test_support::ws_rate_limiting_contains_connection_for_test(&plugin, 8),
        "a live session keeps its consumed budget"
    );

    // A repeated or unknown disconnect is a no-op, never an underflow.
    plugin.on_ws_disconnect(&ws_disconnect_ctx(7)).await;
    plugin.on_ws_disconnect(&ws_disconnect_ctx(99)).await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

/// More finished sessions than the hard cap, each of whose bucket stays
/// "active" for the whole test: without disconnect release the map fills and
/// every later session is policy-closed on its first frame.
#[tokio::test]
async fn connection_churn_beyond_the_cap_never_locks_out_new_sessions() {
    let plugin = WsRateLimiting::new(&long_window_config(), PluginHttpClient::default()).unwrap();
    let cap = ferrum_edge::_test_support::ws_rate_limiting_max_state_entries_for_test() as u64;
    let msg = Message::Text("hello".into());
    let direction = WebSocketFrameDirection::ClientToBackend;
    let mut disconnect = ws_disconnect_ctx(0);

    for connection_id in 0..=cap {
        let result = plugin
            .on_ws_frame("test-proxy", connection_id, direction, &msg)
            .await;
        assert!(
            result.is_none(),
            "session {connection_id} must be admitted after earlier sessions ended"
        );
        disconnect.connection_id = connection_id;
        plugin.on_ws_disconnect(&disconnect).await;
    }
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

// === Aggregate budgets via `limit_by` (ws_rate_limiting-SOL-2) ===

fn upgrade_context(client_ip: &str, consumer: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(client_ip.to_string(), "GET".to_string(), "/ws".to_string());
    if let Some(username) = consumer {
        let mut identified = super::plugin_utils::create_test_consumer();
        identified.id = username.to_string();
        identified.username = username.to_string();
        ctx.identified_consumer = Some(Arc::new(identified));
    }
    ctx
}

fn proxy_context(proxy_id: &str) -> RequestContext {
    let mut ctx = upgrade_context("10.0.0.1", None);
    let mut proxy = super::plugin_utils::create_test_proxy();
    proxy.id = proxy_id.to_string();
    ctx.matched_proxy = Some(Arc::new(proxy));
    ctx
}

/// Burst 2 refilled at one frame per second: the shared-budget tests spend the
/// burst within a few awaits, so a scheduling stall under a second cannot refill
/// a token and flip a refusal.
fn aggregate_plugin(limit_by: &str) -> Arc<WsRateLimiting> {
    Arc::new(
        WsRateLimiting::new(
            &json!({"frames_per_second": 1, "burst_size": 2, "limit_by": limit_by}),
            PluginHttpClient::default(),
        )
        .unwrap(),
    )
}

fn bind(plugin: &Arc<WsRateLimiting>, ctx: &RequestContext) -> Arc<dyn Plugin> {
    Arc::clone(plugin)
        .bind_ws_session(ctx)
        .expect("an aggregate limit_by must bind a session-scoped instance")
}

async fn frame(session: &Arc<dyn Plugin>, connection_id: u64) -> Option<Message> {
    session
        .on_ws_frame(
            "test-proxy",
            connection_id,
            WebSocketFrameDirection::ClientToBackend,
            &Message::Text("hello".into()),
        )
        .await
}

#[tokio::test]
async fn consumer_budget_is_shared_across_sessions_and_isolated_between_consumers() {
    let plugin = aggregate_plugin("consumer");
    let alice = upgrade_context("10.0.0.1", Some("alice"));
    let first = bind(&plugin, &alice);
    let second = bind(&plugin, &alice);
    assert_eq!(first.name(), "ws_rate_limiting");
    assert_eq!(first.priority(), priority::WS_RATE_LIMITING);
    assert!(first.requires_ws_frame_hooks());

    assert!(frame(&first, 1).await.is_none());
    assert!(frame(&second, 2).await.is_none());
    assert!(
        is_policy_close(&frame(&second, 2).await),
        "a second session of the same consumer must draw on the shared budget"
    );

    // Same client IP, different consumer: an independent budget.
    let bob = bind(&plugin, &upgrade_context("10.0.0.1", Some("bob")));
    assert!(frame(&bob, 3).await.is_none());
}

#[tokio::test]
async fn consumer_mode_falls_back_to_the_client_ip_for_anonymous_sessions() {
    let plugin = aggregate_plugin("consumer");
    let first = bind(&plugin, &upgrade_context("10.0.0.9", None));
    let second = bind(&plugin, &upgrade_context("10.0.0.9", None));
    assert!(frame(&first, 1).await.is_none());
    assert!(frame(&first, 1).await.is_none());
    assert!(is_policy_close(&frame(&second, 2).await));

    let other_ip = bind(&plugin, &upgrade_context("10.0.0.10", None));
    assert!(frame(&other_ip, 3).await.is_none());
}

#[tokio::test]
async fn ip_budget_is_shared_across_sessions_and_consumers_of_one_address() {
    let plugin = aggregate_plugin("ip");
    let alice = bind(&plugin, &upgrade_context("192.0.2.1", Some("alice")));
    let bob = bind(&plugin, &upgrade_context("192.0.2.1", Some("bob")));
    assert!(frame(&alice, 1).await.is_none());
    assert!(frame(&bob, 2).await.is_none());
    assert!(is_policy_close(&frame(&alice, 1).await));

    let other_ip = bind(&plugin, &upgrade_context("192.0.2.2", Some("alice")));
    assert!(frame(&other_ip, 3).await.is_none());
}

#[tokio::test]
async fn service_budget_is_shared_across_sessions_of_one_proxy() {
    let plugin = aggregate_plugin("service");
    let first = bind(&plugin, &proxy_context("proxy-a"));
    let second = bind(&plugin, &proxy_context("proxy-a"));
    assert!(frame(&first, 1).await.is_none());
    assert!(frame(&second, 2).await.is_none());
    assert!(is_policy_close(&frame(&first, 1).await));

    let other_proxy = bind(&plugin, &proxy_context("proxy-b"));
    assert!(frame(&other_proxy, 3).await.is_none());
}

#[tokio::test]
async fn aggregate_fragment_batches_charge_the_shared_budget() {
    let plugin = aggregate_plugin("ip");
    let first = bind(&plugin, &upgrade_context("198.51.100.7", None));
    let second = bind(&plugin, &upgrade_context("198.51.100.7", None));
    let direction = WebSocketFrameDirection::ClientToBackend;

    assert!(
        first
            .on_ws_reassembly_frames("test-proxy", 1, direction, 2)
            .await
            .is_none()
    );
    assert!(
        is_policy_close(
            &second
                .on_ws_reassembly_frames("test-proxy", 2, direction, 1)
                .await
        ),
        "fragments on one session must drain the budget every bound session shares"
    );
    assert!(
        second
            .on_ws_reassembly_frames("test-proxy", 2, direction, 0)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn connection_mode_keeps_the_shared_instance_and_aggregate_modes_skip_disconnect() {
    let connection =
        Arc::new(WsRateLimiting::new(&json!({}), PluginHttpClient::default()).unwrap());
    let explicit = Arc::new(
        WsRateLimiting::new(
            &json!({"limit_by": "connection"}),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );
    let ctx = upgrade_context("10.0.0.1", Some("alice"));
    assert!(Arc::clone(&connection).bind_ws_session(&ctx).is_none());
    assert!(Arc::clone(&explicit).bind_ws_session(&ctx).is_none());
    assert!(explicit.requires_ws_disconnect_hooks());

    for limit_by in ["consumer", "ip", "service"] {
        assert!(
            !aggregate_plugin(limit_by).requires_ws_disconnect_hooks(),
            "{limit_by}: an aggregate budget outlives one session"
        );
    }
}

/// An aggregate budget resolves its identity only at session binding. A relay
/// path that skipped binding has no identity to charge, so the shared instance
/// fails closed instead of silently enforcing a weaker per-connection budget.
#[tokio::test]
async fn unbound_aggregate_frames_fail_closed() {
    let plugin = aggregate_plugin("consumer");
    let direction = WebSocketFrameDirection::ClientToBackend;
    let message = plugin
        .on_ws_frame("test-proxy", 1, direction, &Message::Text("hello".into()))
        .await;
    assert!(is_policy_close(&message));
    let fragment = plugin
        .on_ws_reassembly_frames("test-proxy", 1, direction, 2)
        .await;
    assert!(is_policy_close(&fragment));
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[test]
fn limit_by_rejects_unknown_and_non_string_values_without_echo() {
    for config in [
        json!({"limit_by": "UNREGISTERED_DIMENSION"}),
        json!({"limit_by": "Consumer"}),
        json!({"limit_by": 7}),
        json!({"limit_by": null}),
    ] {
        let error = WsRateLimiting::new(&config, PluginHttpClient::default())
            .err()
            .unwrap_or_else(|| panic!("limit_by must be rejected: {config}"));
        assert!(error.contains("`limit_by`"), "{error}");
        assert!(!error.contains("UNREGISTERED_DIMENSION"), "{error}");
    }
}

#[test]
fn limit_by_is_part_of_the_local_state_semantics() {
    use ferrum_edge::_test_support::{
        ws_rate_limiting_shares_local_state_for_test as shares,
        ws_rate_limiting_with_policy_identity_for_test as with_identity,
    };
    let omitted = with_identity(&json!({}), "ferrum", "ws-limit-by-semantics").unwrap();
    let explicit = with_identity(
        &json!({"limit_by": "connection"}),
        "ferrum",
        "ws-limit-by-semantics",
    )
    .unwrap();
    let consumer = with_identity(
        &json!({"limit_by": "consumer"}),
        "ferrum",
        "ws-limit-by-semantics",
    )
    .unwrap();
    assert!(
        shares(&omitted, &explicit),
        "the explicit default must keep the live budget"
    );
    assert!(
        !shares(&omitted, &consumer),
        "a dimension change must isolate onto fresh state"
    );
}

// === Local mode accepts any token-bucket shape (ws_rate_limiting-CLAUDE-3) ===

#[test]
fn local_mode_accepts_any_token_bucket_shape_and_enforces_its_burst() {
    use ferrum_edge::_test_support::ws_rate_limiting_charge_frame_for_test as charge;
    for (frames_per_second, burst_size) in [(60u64, 90u64), (1000, 100), (1, 7200)] {
        let plugin = WsRateLimiting::new(
            &json!({
                "frames_per_second": frames_per_second,
                "burst_size": burst_size,
                "sync_mode": "local"
            }),
            PluginHttpClient::default(),
        )
        .unwrap_or_else(|error| panic!("{frames_per_second}/{burst_size}: {error}"));
        let now = Instant::now();
        for index in 0..burst_size {
            assert!(
                charge(&plugin, 1, now),
                "{frames_per_second}/{burst_size}: frame {index} is inside the burst"
            );
        }
        assert!(
            !charge(&plugin, 1, now),
            "{frames_per_second}/{burst_size}: the burst is the instantaneous ceiling"
        );
    }
}

#[test]
fn redis_mode_keeps_rejecting_unrepresentable_token_bucket_shapes() {
    for (frames_per_second, burst_size, reason) in [
        (60u64, 90u64, "integer multiple"),
        (1000, 100, "must be >="),
        (1, 7200, "Redis-representable maximum"),
    ] {
        let error = WsRateLimiting::new(
            &unavailable_redis_ws_config(
                json!({"frames_per_second": frames_per_second, "burst_size": burst_size}),
            ),
            PluginHttpClient::default(),
        )
        .err()
        .unwrap_or_else(|| panic!("{frames_per_second}/{burst_size} must be rejected"));
        assert!(error.contains(reason), "{error}");
    }
}

// === Close accounting by reason (ws_rate_limiting-CLAUDE-4) ===

/// A fail-closed close while Redis is unavailable is not a budget overrun: it
/// is counted in `ferrum_rate_limit_enforcement_unavailable_total` so an outage
/// that mass-closes sessions is visible in metrics.
#[tokio::test]
async fn fail_closed_close_is_counted_as_enforcement_unavailable() {
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry
        .rate_limit_unavailable_denials
        .load(Ordering::Relaxed);
    let plugin = WsRateLimiting::new(
        &unavailable_redis_ws_config(json!({})),
        PluginHttpClient::default(),
    )
    .unwrap();
    let direction = WebSocketFrameDirection::ClientToBackend;

    let message = plugin
        .on_ws_frame("proxy", 1, direction, &Message::Text("hello".into()))
        .await;
    let fragment = plugin
        .on_ws_reassembly_frames("proxy", 2, direction, 3)
        .await;
    assert!(is_policy_close(&message));
    assert!(is_policy_close(&fragment));
    assert!(
        registry
            .rate_limit_unavailable_denials
            .load(Ordering::Relaxed)
            >= before + 2,
        "each fail-closed close must count as enforcement unavailable"
    );
}
