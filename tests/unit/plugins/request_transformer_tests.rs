//! Tests for request_transformer plugin

use ferrum_gateway::plugins::{Plugin, RequestContext, request_transformer::RequestTransformer};
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    ctx.query_params
        .insert("secret".to_string(), "should-be-removed".to_string());
    ctx.query_params
        .insert("keep".to_string(), "should-remain".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    ctx.query_params
        .insert("removed_param".to_string(), "gone".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-removed".to_string(), "gone".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-existing").unwrap(), "untouched");
}

#[tokio::test]
async fn test_request_transformer_no_config() {
    let plugin = RequestTransformer::new(&json!({}));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
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
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_request_transformer_body_rules_not_applied_in_before_proxy() {
    // Body rules are applied via transform_request_body, not before_proxy
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    // Body rules are handled separately, headers should be untouched
    assert!(headers.is_empty());
}

#[tokio::test]
async fn test_request_transformer_unknown_target_ignored() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "cookie", "key": "field", "value": "val"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_request_transformer_rename_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old-Name", "new_key": "X-New-Name"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old-name".to_string(), "the-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-old-name"));
    assert_eq!(headers.get("x-new-name").unwrap(), "the-value");
}

#[tokio::test]
async fn test_request_transformer_rename_header_nonexistent() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Does-Not-Exist", "new_key": "X-New-Name"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-new-name"));
    assert!(!headers.contains_key("x-does-not-exist"));
}

#[tokio::test]
async fn test_request_transformer_rename_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "query", "key": "old_key", "new_key": "new_key"}
        ]
    }));

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("old_key".to_string(), "the-value".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!ctx.query_params.contains_key("old_key"));
    assert_eq!(ctx.query_params.get("new_key").unwrap(), "the-value");
}

#[tokio::test]
async fn test_request_transformer_rename_query_param_nonexistent() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "query", "key": "missing_key", "new_key": "new_key"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert!(!ctx.query_params.contains_key("missing_key"));
    assert!(!ctx.query_params.contains_key("new_key"));
}

#[tokio::test]
async fn test_request_transformer_rename_without_new_key_ignored() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old-Name"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old-name".to_string(), "the-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    // Without new_key, the rename is a no-op — old key should remain
    assert_eq!(headers.get("x-old-name").unwrap(), "the-value");
}

#[tokio::test]
async fn test_request_transformer_header_key_pre_lowercased() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-UPPER-CASE", "value": "lowered"}
        ]
    }));

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    // Key should be stored as lowercase due to pre-lowercasing at config time
    assert_eq!(headers.get("x-upper-case").unwrap(), "lowered");
    assert!(!headers.contains_key("X-UPPER-CASE"));
}

// ── Body transformation tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_request_transformer_body_add_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "version", "value": "v2"}
        ]
    }));

    assert!(plugin.modifies_request_body());

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["name"], "Alice");
    assert_eq!(transformed["version"], "v2");
}

#[tokio::test]
async fn test_request_transformer_body_add_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "user.role", "value": "admin"}
        ]
    }));

    let body = br#"{"user":{"name":"Alice"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["name"], "Alice");
    assert_eq!(transformed["user"]["role"], "admin");
}

#[tokio::test]
async fn test_request_transformer_body_add_does_not_overwrite() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "name", "value": "Bob"}
        ]
    }));

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    // "add" should not overwrite existing field
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_update_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "status", "value": "active"}
        ]
    }));

    let body = br#"{"status":"pending"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["status"], "active");
}

#[tokio::test]
async fn test_request_transformer_body_update_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "user.address.city", "value": "NYC"}
        ]
    }));

    let body = br#"{"user":{"address":{"city":"LA","zip":"90001"}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["address"]["city"], "NYC");
    assert_eq!(transformed["user"]["address"]["zip"], "90001");
}

#[tokio::test]
async fn test_request_transformer_body_remove_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "internal_id"}
        ]
    }));

    let body = br#"{"name":"Alice","internal_id":"secret123"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["name"], "Alice");
    assert!(transformed.get("internal_id").is_none());
}

#[tokio::test]
async fn test_request_transformer_body_remove_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "user.password"}
        ]
    }));

    let body = br#"{"user":{"name":"Alice","password":"secret"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["name"], "Alice");
    assert!(transformed["user"].get("password").is_none());
}

#[tokio::test]
async fn test_request_transformer_body_rename_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "first_name", "new_key": "given_name"}
        ]
    }));

    let body = br#"{"first_name":"Alice","age":30}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["given_name"], "Alice");
    assert!(transformed.get("first_name").is_none());
    assert_eq!(transformed["age"], 30);
}

#[tokio::test]
async fn test_request_transformer_body_rename_nested_field() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "user.old_field", "new_key": "user.new_field"}
        ]
    }));

    let body = br#"{"user":{"old_field":"data","other":"keep"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["user"]["new_field"], "data");
    assert!(transformed["user"].get("old_field").is_none());
    assert_eq!(transformed["user"]["other"], "keep");
}

#[tokio::test]
async fn test_request_transformer_body_rename_across_nesting_levels() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "nested.deep.value", "new_key": "flat_value"}
        ]
    }));

    let body = br#"{"nested":{"deep":{"value":"found"}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["flat_value"], "found");
    assert!(transformed["nested"]["deep"].get("value").is_none());
}

#[tokio::test]
async fn test_request_transformer_body_multiple_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old_name", "new_key": "new_name"},
            {"operation": "remove", "target": "body", "key": "secret"},
            {"operation": "add", "target": "body", "key": "version", "value": "2"},
            {"operation": "update", "target": "body", "key": "status", "value": "processed"}
        ]
    }));

    let body = br#"{"old_name":"Alice","secret":"hidden","status":"pending"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["new_name"], "Alice");
    assert!(transformed.get("old_name").is_none());
    assert!(transformed.get("secret").is_none());
    assert_eq!(transformed["version"], 2);
    assert_eq!(transformed["status"], "processed");
}

#[tokio::test]
async fn test_request_transformer_body_mixed_header_and_body_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "yes"},
            {"operation": "rename", "target": "body", "key": "old_field", "new_key": "new_field"},
            {"operation": "remove", "target": "query", "key": "debug"}
        ]
    }));

    assert!(plugin.modifies_request_body());

    // Test header/query rules via before_proxy
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("debug".to_string(), "true".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_gateway::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-custom").unwrap(), "yes");
    assert!(!ctx.query_params.contains_key("debug"));

    // Test body rules via transform_request_body
    let body = br#"{"old_field":"data"}"#;
    let body_result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&body_result.unwrap()).unwrap();
    assert_eq!(transformed["new_field"], "data");
}

#[tokio::test]
async fn test_request_transformer_body_non_json_content_type_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }));

    let body = b"<xml>not json</xml>";
    let result = plugin
        .transform_request_body(body, Some("application/xml"))
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_invalid_json_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }));

    let body = b"this is not json";
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_empty_body_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }));

    let result = plugin
        .transform_request_body(b"", Some("application/json"))
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_no_body_rules_returns_false() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "val"}
        ]
    }));

    assert!(!plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_body_deeply_nested_three_levels() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "a.b.c.d", "value": "deep_value"}
        ]
    }));

    let body = br#"{"a":{"b":{"c":{"d":"old"}}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["a"]["b"]["c"]["d"], "deep_value");
}

#[tokio::test]
async fn test_request_transformer_body_add_creates_intermediate_objects() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "new.nested.field", "value": "created"}
        ]
    }));

    let body = br#"{"existing":"keep"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["existing"], "keep");
    assert_eq!(transformed["new"]["nested"]["field"], "created");
}

#[tokio::test]
async fn test_request_transformer_body_numeric_value() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "count", "value": "42"}
        ]
    }));

    let body = br#"{}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    // "42" string is parsed as number 42
    assert_eq!(transformed["count"], 42);
}

#[tokio::test]
async fn test_request_transformer_body_boolean_value() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "active", "value": "true"}
        ]
    }));

    let body = br#"{}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["active"], true);
}

#[tokio::test]
async fn test_request_transformer_body_rename_nonexistent_is_noop() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "missing", "new_key": "present"}
        ]
    }));

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"))
        .await;
    // No field was renamed, so no modification — returns None
    assert!(result.is_none());
}
