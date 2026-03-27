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

// ── Body transformation tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_response_transformer_body_rename_field() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old_name", "new_key": "new_name"}
        ]
    }));

    assert!(plugin.requires_response_body_buffering());

    let body = br#"{"old_name":"Alice","age":30}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["new_name"], "Alice");
    assert!(transformed.get("old_name").is_none());
    assert_eq!(transformed["age"], 30);
}

#[tokio::test]
async fn test_response_transformer_body_rename_nested_field() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "data.old_field", "new_key": "data.new_field"}
        ]
    }));

    let body = br#"{"data":{"old_field":"value","other":"keep"}}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["data"]["new_field"], "value");
    assert!(transformed["data"].get("old_field").is_none());
    assert_eq!(transformed["data"]["other"], "keep");
}

#[tokio::test]
async fn test_response_transformer_body_remove_field() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "internal.debug_info"}
        ]
    }));

    let body = br#"{"data":"public","internal":{"debug_info":"secret","id":"keep"}}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["data"], "public");
    assert!(transformed["internal"].get("debug_info").is_none());
    assert_eq!(transformed["internal"]["id"], "keep");
}

#[tokio::test]
async fn test_response_transformer_body_add_field() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "gateway_version", "value": "1.0"}
        ]
    }));

    let body = br#"{"data":"response"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["data"], "response");
    assert_eq!(transformed["gateway_version"], 1.0);
}

#[tokio::test]
async fn test_response_transformer_body_update_field() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "status", "value": "processed"}
        ]
    }));

    let body = br#"{"status":"pending","data":"result"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["status"], "processed");
    assert_eq!(transformed["data"], "result");
}

#[tokio::test]
async fn test_response_transformer_body_multiple_rules() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "resp_data", "new_key": "data"},
            {"operation": "remove", "target": "body", "key": "internal_trace_id"},
            {"operation": "add", "target": "body", "key": "api_version", "value": "v2"}
        ]
    }));

    let body = br#"{"resp_data":"payload","internal_trace_id":"abc123"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["data"], "payload");
    assert!(transformed.get("resp_data").is_none());
    assert!(transformed.get("internal_trace_id").is_none());
    assert_eq!(transformed["api_version"], "v2");
}

#[tokio::test]
async fn test_response_transformer_body_mixed_header_and_body_rules() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-Processed", "value": "true"},
            {"operation": "rename", "target": "body", "key": "old_field", "new_key": "new_field"}
        ]
    }));

    assert!(plugin.requires_response_body_buffering());

    // Test header rules via after_proxy
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-processed").unwrap(), "true");

    // Test body rules via transform_response_body
    let body = br#"{"old_field":"data"}"#;
    let body_result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&body_result.unwrap()).unwrap();
    assert_eq!(transformed["new_field"], "data");
}

#[tokio::test]
async fn test_response_transformer_body_non_json_skipped() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }));

    let body = b"<xml>not json</xml>";
    let result = plugin
        .transform_response_body(body, Some("text/html"))
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_response_transformer_no_body_rules_no_buffering() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X-Header", "value": "yes"}
        ]
    }));

    // No body rules → no buffering required
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_response_transformer_body_deeply_nested() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "a.b.c.old", "new_key": "a.b.c.new"}
        ]
    }));

    let body = br#"{"a":{"b":{"c":{"old":"deep_value","keep":"yes"}}}}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["a"]["b"]["c"]["new"], "deep_value");
    assert!(transformed["a"]["b"]["c"].get("old").is_none());
    assert_eq!(transformed["a"]["b"]["c"]["keep"], "yes");
}

#[tokio::test]
async fn test_response_transformer_body_vnd_json_content_type() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "processed", "value": "true"}
        ]
    }));

    let body = br#"{"data":"value"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/vnd.api+json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["processed"], true);
}
