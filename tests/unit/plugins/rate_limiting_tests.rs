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

    // First request should pass
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(consumer.clone());
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Multiple requests for same consumer should be rate limited
    let mut rejected_count = 0;
    for _i in 0..6 {
        let mut ctx_test = create_test_context();
        ctx_test.identified_consumer = Some(consumer.clone());
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
async fn test_rate_limiting_authorize_does_not_double_count() {
    // After our fix, authorize() should NOT apply rate limiting (defaults to Continue)
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

    // authorize should always return Continue (not count against the limit)
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // The next on_request_received should be rejected (limit=1, already used)
    let result = plugin.on_request_received(&mut ctx).await;
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
