//! Tests for request_transformer plugin

use ferrum_gateway::plugins::{request_transformer::RequestTransformer, Plugin, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx() -> RequestContext {
    RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/test".to_string())
}

#[tokio::test]
async fn test_request_transformer_creation() {
    let plugin = RequestTransformer::new(&json!({}));
    assert_eq!(plugin.name(), "request_transformer");
}

#[tokio::test]
async fn test_request_transformer_add_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "custom-value"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert_eq!(headers.get("x-custom").unwrap(), "custom-value");
}

#[tokio::test]
async fn test_request_transformer_remove_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-Remove-Me"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-remove-me".to_string(), "should-be-removed".to_string());
    headers.insert("x-keep-me".to_string(), "should-remain".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert!(!headers.contains_key("x-remove-me"));
    assert!(headers.contains_key("x-keep-me"));
}

#[tokio::test]
async fn test_request_transformer_update_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Existing", "value": "new-value"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-existing".to_string(), "old-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert_eq!(headers.get("x-existing").unwrap(), "new-value");
}

#[tokio::test]
async fn test_request_transformer_add_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "version", "value": "v2"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert_eq!(ctx.query_params.get("version").unwrap(), "v2");
}

#[tokio::test]
async fn test_request_transformer_remove_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "secret"}
        ]
    }));

    let mut ctx = make_ctx();
    ctx.query_params.insert("secret".to_string(), "should-be-removed".to_string());
    ctx.query_params.insert("keep".to_string(), "should-remain".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert!(!ctx.query_params.contains_key("secret"));
    assert!(ctx.query_params.contains_key("keep"));
}

#[tokio::test]
async fn test_request_transformer_update_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "query", "key": "page", "value": "2"}
        ]
    }));

    let mut ctx = make_ctx();
    ctx.query_params.insert("page".to_string(), "1".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert_eq!(ctx.query_params.get("page").unwrap(), "2");
}

#[tokio::test]
async fn test_request_transformer_multiple_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Added", "value": "yes"},
            {"operation": "remove", "target": "header", "key": "X-Removed"},
            {"operation": "add", "target": "query", "key": "added_param", "value": "true"},
            {"operation": "remove", "target": "query", "key": "removed_param"}
        ]
    }));

    let mut ctx = make_ctx();
    ctx.query_params.insert("removed_param".to_string(), "gone".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-removed".to_string(), "gone".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert_eq!(headers.get("x-added").unwrap(), "yes");
    assert!(!headers.contains_key("x-removed"));
    assert_eq!(ctx.query_params.get("added_param").unwrap(), "true");
    assert!(!ctx.query_params.contains_key("removed_param"));
}

#[tokio::test]
async fn test_request_transformer_empty_rules() {
    let plugin = RequestTransformer::new(&json!({"rules": []}));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-existing".to_string(), "untouched".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    assert_eq!(headers.get("x-existing").unwrap(), "untouched");
}

#[tokio::test]
async fn test_request_transformer_no_config() {
    let plugin = RequestTransformer::new(&json!({}));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
}

#[tokio::test]
async fn test_request_transformer_add_without_value_ignored() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-NoValue"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
    // Should not add header without a value
    assert!(!headers.contains_key("x-novalue"));
}

#[tokio::test]
async fn test_request_transformer_unknown_operation_ignored() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "delete", "target": "header", "key": "X-Test", "value": "val"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
}

#[tokio::test]
async fn test_request_transformer_unknown_target_ignored() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, ferrum_gateway::plugins::PluginResult::Continue));
}
