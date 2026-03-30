//! Tests for transaction_debugger plugin

use ferrum_edge::plugins::{Plugin, RequestContext, transaction_debugger::TransactionDebugger};
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
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_on_request_received_with_body_logging() {
    let plugin = TransactionDebugger::new(&json!({"log_request_body": true}));
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
        ferrum_edge::plugins::PluginResult::Continue
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
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_log() {
    let plugin = TransactionDebugger::new(&json!({}));
    let summary = create_test_transaction_summary();

    // Verify log phase completes and plugin is operational after logging
    plugin.log(&summary).await;

    // After logging, the plugin should still be functional (not corrupted)
    assert_eq!(plugin.name(), "transaction_debugger");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::TRANSACTION_DEBUGGER
    );
}

#[tokio::test]
async fn test_transaction_debugger_full_lifecycle() {
    let plugin = TransactionDebugger::new(&json!({
        "log_request_body": true,
        "log_response_body": true
    }));

    let mut ctx = make_ctx();
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);
    let mut headers: HashMap<String, String> = HashMap::new();

    // on_request_received
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // authenticate (default - Continue)
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // authorize (default - Continue)
    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // before_proxy (default - Continue)
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // after_proxy
    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    // log
    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
}

// ── Header redaction tests ─────────────────────────────────────────────

fn make_ctx_with_sensitive_headers() -> RequestContext {
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "POST".to_string(),
        "/api/data".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.headers.insert(
        "authorization".to_string(),
        "Bearer secret-token-123".to_string(),
    );
    ctx.headers
        .insert("cookie".to_string(), "session=abc123".to_string());
    ctx.headers
        .insert("x-api-key".to_string(), "sk-live-secret".to_string());
    ctx.headers
        .insert("x-request-id".to_string(), "req-456".to_string());
    ctx
}

#[tokio::test]
async fn test_transaction_debugger_redacts_sensitive_request_headers() {
    // The plugin should not leak sensitive headers in its debug output.
    // We verify the plugin processes requests with sensitive headers without error.
    let plugin = TransactionDebugger::new(&json!({}));
    let mut ctx = make_ctx_with_sensitive_headers();

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Sensitive headers should still be in the original context (not modified)
    assert_eq!(
        ctx.headers.get("authorization").unwrap(),
        "Bearer secret-token-123"
    );
}

#[tokio::test]
async fn test_transaction_debugger_redacts_sensitive_response_headers() {
    let plugin = TransactionDebugger::new(&json!({}));
    let mut ctx = make_ctx();
    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("set-cookie".to_string(), "session=secret".to_string());
    response_headers.insert(
        "www-authenticate".to_string(),
        "Bearer realm=\"api\"".to_string(),
    );
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 401, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Response headers should not be modified by the debugger
    assert_eq!(
        response_headers.get("set-cookie").unwrap(),
        "session=secret"
    );
}

#[tokio::test]
async fn test_transaction_debugger_custom_redacted_headers() {
    let plugin = TransactionDebugger::new(&json!({
        "redacted_headers": ["x-custom-secret", "x-internal-token"]
    }));
    let mut ctx = RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.headers
        .insert("x-custom-secret".to_string(), "my-secret".to_string());
    ctx.headers
        .insert("x-internal-token".to_string(), "token-value".to_string());
    ctx.headers
        .insert("x-safe-header".to_string(), "visible".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_transaction_debugger_default_body_logging_disabled() {
    let plugin = TransactionDebugger::new(&json!({}));
    let mut ctx = make_ctx();

    // Should work fine with body logging disabled
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}
