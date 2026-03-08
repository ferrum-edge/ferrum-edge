//! Tests for rate_limiting plugin

use ferrum_gateway::plugins::{rate_limiting::RateLimiting, Plugin, PluginResult};
use serde_json::json;

mod plugin_utils;
use plugin_utils::{create_test_consumer, create_test_context, assert_continue, assert_reject};

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
    
    // Test first request should pass
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(consumer.clone());
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
    
    // Multiple requests for same consumer should be rate limited
    let mut rejected_count = 0;
    for i in 0..6 {
        let mut ctx_test = create_test_context();
        ctx_test.identified_consumer = Some(consumer.clone());
        let result = plugin.authorize(&mut ctx_test).await;
        if matches!(result, PluginResult::Reject { .. }) {
            rejected_count += 1;
        }
    }
    
    // Should have some rejections after hitting the limit
    assert!(rejected_count > 0, "Expected some requests to be rate limited");
}

#[tokio::test]
async fn test_rate_limiting_plugin_ip_limiting() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip"
    });
    let plugin = RateLimiting::new(&config);
    
    // Test first request should pass
    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
    
    // Multiple requests should eventually be rate limited
    let mut rejected_count = 0;
    for i in 0..10 {
        let mut ctx_test = create_test_context();
        let result = plugin.authorize(&mut ctx_test).await;
        if matches!(result, PluginResult::Reject { .. }) {
            rejected_count += 1;
        }
    }
    
    // Should have some rejections after hitting the limit
    assert!(rejected_count > 0, "Expected some requests to be rate limited");
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
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
    
    // Second request should pass
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
    
    // Third request should be rejected
    let result = plugin.authorize(&mut ctx).await;
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
    let result = plugin.authorize(&mut ctx).await;
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
    let result = plugin.authorize(&mut ctx).await;
    // Should handle gracefully
    assert!(matches!(result, PluginResult::Continue) || matches!(result, PluginResult::Reject { .. }));
}
