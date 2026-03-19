//! Tests for http_logging plugin

use ferrum_gateway::plugins::{Plugin, http_logging::HttpLogging};
use serde_json::json;

use super::plugin_utils::create_test_transaction_summary;

#[tokio::test]
async fn test_http_logging_plugin_creation() {
    let plugin = HttpLogging::new(&json!({
        "endpoint_url": "http://localhost:9200/logs",
        "authorization_header": "Bearer log-token"
    }));
    assert_eq!(plugin.name(), "http_logging");
}

#[tokio::test]
async fn test_http_logging_plugin_creation_empty_config() {
    let plugin = HttpLogging::new(&json!({}));
    assert_eq!(plugin.name(), "http_logging");
}

#[tokio::test]
async fn test_http_logging_empty_url_does_not_send() {
    // When endpoint_url is empty, log() should return without sending
    let plugin = HttpLogging::new(&json!({}));
    let summary = create_test_transaction_summary();

    // This should not panic or error - just silently return
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_http_logging_invalid_url_does_not_panic() {
    // When endpoint_url is unreachable, log() should handle the error gracefully
    let plugin = HttpLogging::new(&json!({
        "endpoint_url": "http://127.0.0.1:1/unreachable"
    }));
    let summary = create_test_transaction_summary();

    // Should not panic - just log a warning
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_http_logging_with_authorization_header() {
    let plugin = HttpLogging::new(&json!({
        "endpoint_url": "http://127.0.0.1:1/unreachable",
        "authorization_header": "Bearer my-secret-token"
    }));
    assert_eq!(plugin.name(), "http_logging");

    // Should not panic even with auth header set and unreachable endpoint
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_http_logging_default_lifecycle_phases() {
    // http_logging only implements log(), all other phases should return Continue
    let plugin = HttpLogging::new(&json!({}));

    let mut ctx = ferrum_gateway::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    let consumer_index = ferrum_gateway::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}
