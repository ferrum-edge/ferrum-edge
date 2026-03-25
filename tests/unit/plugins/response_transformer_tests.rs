//! Tests for response_transformer plugin

use ferrum_gateway::plugins::{Plugin, RequestContext, response_transformer::ResponseTransformer};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

#[tokio::test]
async fn test_response_transformer_creation() {
    let plugin = ResponseTransformer::new(&json!({}));
    assert_eq!(plugin.name(), "response_transformer");
}

#[tokio::test]
async fn test_response_transformer_add_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-Response-Id", "value": "abc-123"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-response-id").unwrap(), "abc-123");
}

#[tokio::test]
async fn test_response_transformer_remove_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "key": "X-Internal"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-internal".to_string(), "sensitive-data".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-internal"));
    assert!(headers.contains_key("content-type"));
}

#[tokio::test]
async fn test_response_transformer_update_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "key": "Server", "value": "Ferrum Gateway"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("server".to_string(), "nginx".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("server").unwrap(), "Ferrum Gateway");
}

#[tokio::test]
async fn test_response_transformer_multiple_rules() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-Gateway", "value": "ferrum"},
            {"operation": "remove", "key": "X-Powered-By"},
            {"operation": "update", "key": "Server", "value": "Ferrum"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-powered-by".to_string(), "Express".to_string());
    headers.insert("server".to_string(), "nginx".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-gateway").unwrap(), "ferrum");
    assert!(!headers.contains_key("x-powered-by"));
    assert_eq!(headers.get("server").unwrap(), "Ferrum");
}

#[tokio::test]
async fn test_response_transformer_empty_rules() {
    let plugin = ResponseTransformer::new(&json!({"rules": []}));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-existing".to_string(), "unchanged".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-existing").unwrap(), "unchanged");
}

#[tokio::test]
async fn test_response_transformer_no_config() {
    let plugin = ResponseTransformer::new(&json!({}));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 500, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_response_transformer_add_without_value_ignored() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-NoValue"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-novalue"));
}

#[tokio::test]
async fn test_response_transformer_unknown_operation_ignored() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "prepend", "key": "X-Test", "value": "val"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_response_transformer_handles_various_status_codes() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-Processed", "value": "true"}
        ]
    }));

    for status in [200, 201, 301, 400, 404, 500, 503] {
        let mut ctx = make_ctx();
        let mut headers: HashMap<String, String> = HashMap::new();

        let result = plugin.after_proxy(&mut ctx, status, &mut headers).await;
        assert!(matches!(
            result,
            ferrum_gateway::plugins::PluginResult::Continue
        ));
        assert_eq!(headers.get("x-processed").unwrap(), "true");
    }
}

#[tokio::test]
async fn test_response_transformer_rename_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "key": "x-old", "new_key": "x-new"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old".to_string(), "the-value".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-old"));
    assert_eq!(headers.get("x-new").unwrap(), "the-value");
}

#[tokio::test]
async fn test_response_transformer_rename_header_nonexistent() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "key": "x-missing", "new_key": "x-new"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-new"));
    assert!(!headers.contains_key("x-missing"));
}

#[tokio::test]
async fn test_response_transformer_rename_without_new_key_ignored() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "key": "x-old"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old".to_string(), "the-value".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    // Without new_key, the rename is a no-op — old key should remain
    assert_eq!(headers.get("x-old").unwrap(), "the-value");
}

#[tokio::test]
async fn test_response_transformer_header_key_pre_lowercased() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-UPPER", "value": "lowered"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    // Key should be stored as lowercase due to pre-lowercasing at config time
    assert_eq!(headers.get("x-upper").unwrap(), "lowered");
    assert!(!headers.contains_key("X-UPPER"));
}
