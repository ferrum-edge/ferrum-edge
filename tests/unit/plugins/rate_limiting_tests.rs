//! Tests for rate_limiting plugin

use ferrum_gateway::plugins::{Plugin, PluginResult, rate_limiting::RateLimiting};
use serde_json::json;

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_consumer, create_test_context,
};

#[tokio::test]
async fn test_rate_limiting_plugin_creation() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "consumer"
    });
    let plugin = RateLimiting::new(&config);
    assert_eq!(plugin.name(), "rate_limiting");
}

#[tokio::test]
async fn test_rate_limiting_plugin_consumer_limiting() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 3,
        "limit_by": "consumer"
    });
    let plugin = RateLimiting::new(&config);

    let consumer = create_test_consumer();

    // In consumer mode, on_request_received should pass through (no-op)
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(consumer.clone());
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Consumer-based limiting happens in authorize phase (after auth identifies consumer)
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(consumer.clone());
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // Multiple requests for same consumer should be rate limited via authorize
    let mut rejected_count = 0;
    for _i in 0..6 {
        let mut ctx_test = create_test_context();
        ctx_test.identified_consumer = Some(consumer.clone());
        let result = plugin.authorize(&mut ctx_test).await;
        if matches!(result, PluginResult::Reject { .. }) {
            rejected_count += 1;
        }
    }

    // Should have some rejections after hitting the limit
    assert!(
        rejected_count > 0,
        "Expected some requests to be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limiting_plugin_ip_limiting() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    // First request should pass
    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Multiple requests should eventually be rate limited
    let mut rejected_count = 0;
    for _i in 0..10 {
        let mut ctx_test = create_test_context();
        let result = plugin.on_request_received(&mut ctx_test).await;
        if matches!(result, PluginResult::Reject { .. }) {
            rejected_count += 1;
        }
    }

    // Should have some rejections after hitting the limit
    assert!(
        rejected_count > 0,
        "Expected some requests to be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limiting_plugin_short_window() {
    let config = json!({
        "window_seconds": 1,
        "max_requests": 2,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // First request should pass
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Second request should pass
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Third request should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_plugin_zero_limit() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 0,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // With zero limit, all requests should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_plugin_invalid_config() {
    let config = json!({
        "window_seconds": "invalid",
        "max_requests": -1,
        "limit_by": "invalid_type"
    });
    let plugin = RateLimiting::new(&config);
    assert_eq!(plugin.name(), "rate_limiting");

    // Should still work despite invalid config
    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    // Should handle gracefully
    assert!(
        matches!(result, PluginResult::Continue) || matches!(result, PluginResult::Reject { .. })
    );
}

#[tokio::test]
async fn test_rate_limiting_ip_mode_authorize_is_noop() {
    // In IP mode, authorize() should NOT apply rate limiting (only on_request_received does)
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // on_request_received uses the limit
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // authorize should always return Continue in IP mode (not count against the limit)
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // The next on_request_received should be rejected (limit=1, already used)
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_consumer_mode_on_request_received_is_noop() {
    // In consumer mode, on_request_received() should be a no-op (authorize handles limiting)
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "consumer"
    });
    let plugin = RateLimiting::new(&config);

    let consumer = create_test_consumer();

    // on_request_received should pass through in consumer mode
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(consumer.clone());
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // authorize uses the limit for consumer mode
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // Second authorize should be rejected (limit=1, already used)
    let mut ctx2 = create_test_context();
    ctx2.identified_consumer = Some(consumer.clone());
    let result = plugin.authorize(&mut ctx2).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_consumer_fallback_to_ip() {
    // In consumer mode, unauthenticated requests fall back to IP-based keying
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "consumer"
    });
    let plugin = RateLimiting::new(&config);

    // No consumer set — should fall back to IP-based key
    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // Second request from same IP (no consumer) should be rejected
    let mut ctx2 = create_test_context();
    let result = plugin.authorize(&mut ctx2).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_different_ips_independent() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    // IP 1: first request passes
    let mut ctx1 = create_test_context();
    ctx1.client_ip = "10.0.0.1".to_string();
    let result = plugin.on_request_received(&mut ctx1).await;
    assert_continue(result);

    // IP 1: second request rejected
    let result = plugin.on_request_received(&mut ctx1).await;
    assert_reject(result, Some(429));

    // IP 2: first request passes (independent counter)
    let mut ctx2 = create_test_context();
    ctx2.client_ip = "10.0.0.2".to_string();
    let result = plugin.on_request_received(&mut ctx2).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_rate_limiting_explicit_rate_config() {
    let config = json!({
        "requests_per_second": 2,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // First two should pass
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Third should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_non_standard_window_exact() {
    // Non-standard window: 45 seconds, 10 requests.
    // Previously this was converted via integer division to per-minute rate:
    //   (10 * 60) / 45 = 13 req/min (precision loss: should be 13.33)
    // Now it should use the exact 45-second window with 10 requests.
    let config = json!({
        "window_seconds": 45,
        "max_requests": 10,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // All 10 requests within the 45s window should pass
    for _i in 0..10 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // The 11th request should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_non_standard_window_7s() {
    // 7-second window with 3 requests
    // Old behavior: (3 * 60) / 7 = 25 req/min (a completely different rate)
    // New behavior: exactly 3 requests per 7 seconds
    let config = json!({
        "window_seconds": 7,
        "max_requests": 3,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // First 3 should pass
    for _ in 0..3 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 4th should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_non_standard_window_90s() {
    // 90-second window (between 60s and 3600s)
    let config = json!({
        "window_seconds": 90,
        "max_requests": 5,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // All 5 should pass
    for _ in 0..5 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 6th should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

// ─── Token Bucket (per-second TPS) Tests ───────────────────────────────

#[tokio::test]
async fn test_rate_limiting_tps_uses_token_bucket() {
    // requests_per_second creates a 1s window → token bucket (≤5s threshold)
    let config = json!({
        "requests_per_second": 5,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // All 5 should pass (bucket starts full)
    for _ in 0..5 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 6th should be rejected (bucket empty)
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_tps_refills_over_time() {
    let config = json!({
        "requests_per_second": 10,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // Drain all 10 tokens
    for _ in 0..10 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // Should be rejected now
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));

    // Wait for tokens to refill (100ms = ~1 token at 10/s rate)
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Should have ~1 token available now
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_rate_limiting_high_tps_limit() {
    // Ensure high TPS limits work without memory issues.
    // With a token bucket at 10,000 req/s, micro-refill during the loop
    // means we may slightly exceed the nominal bucket capacity. The key
    // assertion: we can fire ~10,000 requests without OOM, and eventually
    // the bucket runs dry.
    let config = json!({
        "requests_per_second": 10000,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // Fire 10500 requests — most should pass, some at the tail should be rejected
    let mut passed = 0;
    let mut rejected = 0;
    for _ in 0..10500 {
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Continue => passed += 1,
            PluginResult::Reject { .. } => rejected += 1,
        }
    }

    // Should have passed ~10,000 (token bucket allows capacity + micro-refill)
    assert!(
        passed >= 10000,
        "Expected at least 10000 passed, got {}",
        passed
    );
    // Should have rejected some at the end
    assert!(
        rejected > 0,
        "Expected some rejections after draining bucket"
    );
}

#[tokio::test]
async fn test_rate_limiting_tps_zero_limit() {
    // Zero TPS should reject everything
    let config = json!({
        "requests_per_second": 0,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_combined_tps_and_per_minute() {
    // Both per-second AND per-minute limits — both must pass
    let config = json!({
        "requests_per_second": 5,
        "requests_per_minute": 10,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    // First 5 pass (within per-second burst)
    for _ in 0..5 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 6th rejected by per-second limit
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_window_1s_uses_token_bucket() {
    // window_seconds: 1 → ≤5s threshold → should use token bucket
    let config = json!({
        "window_seconds": 1,
        "max_requests": 3,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    for _ in 0..3 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_window_5s_uses_token_bucket() {
    // window_seconds: 5 → boundary, ≤5s → token bucket
    let config = json!({
        "window_seconds": 5,
        "max_requests": 10,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    for _ in 0..10 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_window_6s_uses_sliding_window() {
    // window_seconds: 6 → >5s → sliding window (exact counting)
    let config = json!({
        "window_seconds": 6,
        "max_requests": 3,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);

    let mut ctx = create_test_context();

    for _ in 0..3 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}
