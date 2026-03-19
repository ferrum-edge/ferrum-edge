//! Tests for stdout_logging plugin

use ferrum_gateway::plugins::{Plugin, PluginResult, stdout_logging::StdoutLogging};
use serde_json::json;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

#[tokio::test]
async fn test_stdout_logging_plugin_creation() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config);
    assert_eq!(plugin.name(), "stdout_logging");
}

#[tokio::test]
async fn test_stdout_logging_plugin_lifecycle() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config);
    let mut ctx = create_test_context();

    // Test all lifecycle phases
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let consumer_index = ferrum_gateway::ConsumerIndex::new(&[]);
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_stdout_logging_plugin_logging() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config);

    let summary = create_test_transaction_summary();

    // Should not panic when logging
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_stdout_logging_plugin_with_config() {
    let config = json!({
        "log_level": "info",
        "include_metadata": true
    });
    let plugin = StdoutLogging::new(&config);
    assert_eq!(plugin.name(), "stdout_logging");

    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}
