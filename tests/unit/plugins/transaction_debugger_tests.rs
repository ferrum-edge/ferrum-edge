//! Tests for transaction_debugger plugin

use ferrum_gateway::plugins::{Plugin, RequestContext, transaction_debugger::TransactionDebugger};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::create_test_transaction_summary;

fn make_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "POST".to_string(),
        "/api/data".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers
        .insert("x-request-id".to_string(), "abc-123".to_string());
    ctx
}

#[tokio::test]
async fn test_transaction_debugger_creation() {
    let plugin = TransactionDebugger::new(&json!({}));
    assert_eq!(plugin.name(), "transaction_debugger");
}

#[tokio::test]
async fn test_transaction_debugger_creation_with_config() {
    let plugin = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "log_response_body": true
    }));
    assert_eq!(plugin.name(), "transaction_debugger");
}

#[tokio::test]
async fn test_transaction_debugger_on_request_received() {
    let plugin = TransactionDebugger::new(&json!({}));
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_on_request_received_with_body_logging() {
    let plugin = TransactionDebugger::new(&json!({"log_request_body": true}));
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_after_proxy() {
    let plugin = TransactionDebugger::new(&json!({}));
    let mut ctx = make_ctx();
    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_after_proxy_with_body_logging() {
    let plugin = TransactionDebugger::new(&json!({"log_response_body": true}));
    let mut ctx = make_ctx();
    let mut response_headers: HashMap<String, String> = HashMap::new();

    let result = plugin
        .after_proxy(&mut ctx, 500, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_log() {
    let plugin = TransactionDebugger::new(&json!({}));
    let summary = create_test_transaction_summary();

    // Should not panic
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_transaction_debugger_full_lifecycle() {
    let plugin = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "log_response_body": true
    }));

    let mut ctx = make_ctx();
    let consumer_index = ferrum_gateway::ConsumerIndex::new(&[]);
    let mut headers: HashMap<String, String> = HashMap::new();

    // on_request_received
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    // authenticate (default - Continue)
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    // authorize (default - Continue)
    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    // before_proxy (default - Continue)
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    // after_proxy
    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    // log
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_transaction_debugger_default_body_logging_disabled() {
    let plugin = TransactionDebugger::new(&json!({}));
    let mut ctx = make_ctx();

    // Should work fine with body logging disabled
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}
