//! Tests for request_transformer plugin

use ferrum_edge::plugins::{
    HTTP_GRPC_PROTOCOLS, Plugin, RequestContext, priority, request_transformer::RequestTransformer,
};
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
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "test"}
        ]
    }))
    .unwrap();
    assert_eq!(plugin.name(), "request_transformer");
    assert_eq!(plugin.priority(), priority::REQUEST_TRANSFORMER);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.is_auth_plugin());
}

#[tokio::test]
async fn test_request_transformer_add_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "custom-value"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-custom").unwrap(), "custom-value");
}

#[tokio::test]
async fn test_request_transformer_remove_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-Remove-Me"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-remove-me".to_string(), "should-be-removed".to_string());
    headers.insert("x-keep-me".to_string(), "should-remain".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-existing".to_string(), "old-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-existing").unwrap(), "new-value");
}

#[tokio::test]
async fn test_request_transformer_add_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "version", "value": "v2"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(ctx.query_params.get("version").unwrap(), "v2");
}

#[tokio::test]
async fn test_request_transformer_remove_query_param() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "secret"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("secret".to_string(), "should-be-removed".to_string());
    ctx.query_params
        .insert("keep".to_string(), "should-remain".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params.insert("page".to_string(), "1".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("removed_param".to_string(), "gone".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-removed".to_string(), "gone".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-added").unwrap(), "yes");
    assert!(!headers.contains_key("x-removed"));
    assert_eq!(ctx.query_params.get("added_param").unwrap(), "true");
    assert!(!ctx.query_params.contains_key("removed_param"));
}

#[tokio::test]
async fn test_request_transformer_empty_rules() {
    let result = RequestTransformer::new(&json!({"rules": []}));
    let err = result.err().expect("expected error for empty rules");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_no_config() {
    let result = RequestTransformer::new(&json!({}));
    let err = result.err().expect("expected error for no config");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_invalid_rules_container_shapes() {
    for config in [
        json!("bad"),
        json!({"rules": "not-array"}),
        json!({"rules": [42]}),
    ] {
        let err = RequestTransformer::new(&config)
            .err()
            .expect("expected invalid config to be rejected");
        assert!(
            err.contains("config must be an object")
                || err.contains("'rules' must be an array")
                || err.contains("rule must be an object"),
            "unexpected error for {config:?}: {err}"
        );
    }
}

#[tokio::test]
async fn test_request_transformer_add_without_value_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-NoValue"}
        ]
    }))
    .err()
    .expect("expected error for add without value");
    assert!(err.contains("requires a 'value'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_unknown_operation_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "delete", "target": "header", "key": "X-Test", "value": "val"}
        ]
    }))
    .err()
    .expect("expected error for unknown operation");
    assert!(err.contains("unknown operation"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_body_rules_not_applied_in_before_proxy() {
    // Body rules are applied via transform_request_body, not before_proxy
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    // Body rules are handled separately, headers should be untouched
    assert!(headers.is_empty());
}

#[tokio::test]
async fn test_request_transformer_unknown_target_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "cookie", "key": "field", "value": "val"}
        ]
    }))
    .err()
    .expect("expected error for unknown target");
    assert!(err.contains("unknown target"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rename_header() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old-Name", "new_key": "X-New-Name"}
        ]
    })).unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old-name".to_string(), "the-value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    })).unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("old_key".to_string(), "the-value".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!ctx.query_params.contains_key("missing_key"));
    assert!(!ctx.query_params.contains_key("new_key"));
}

#[tokio::test]
async fn test_request_transformer_rename_without_new_key_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old-Name"}
        ]
    }))
    .err()
    .expect("expected error for rename without new_key");
    assert!(err.contains("requires a 'new_key'"), "got: {err}");
}

#[tokio::test]
async fn test_rename_array_index_rejected_at_construction() {
    // Rename rules targeting array indices are ambiguous (move? swap?
    // overwrite?) and previously caused silent data loss when both sides
    // pointed at the same array. They must be rejected at plugin construction
    // so the misconfiguration surfaces as an HTTP 400 (admin API) or startup
    // failure (file mode) instead of corrupting user data at runtime.
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "items.0", "new_key": "items.1"}
        ]
    }))
    .err()
    .expect("expected error for rename with array indices");
    assert!(err.contains("does not support array indices"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_header_key_pre_lowercased() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-UPPER-CASE", "value": "lowered"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    assert!(plugin.modifies_request_body());

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"user":{"name":"Alice"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"status":"pending"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"user":{"address":{"city":"LA","zip":"90001"}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"name":"Alice","internal_id":"secret123"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"user":{"name":"Alice","password":"secret"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"first_name":"Alice","age":30}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    })).unwrap();

    let body = br#"{"user":{"old_field":"data","other":"keep"}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    })).unwrap();

    let body = br#"{"nested":{"deep":{"value":"found"}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"old_name":"Alice","secret":"hidden","status":"pending"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    assert!(plugin.modifies_request_body());

    // Test header/query rules via before_proxy
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("debug".to_string(), "true".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-custom").unwrap(), "yes");
    assert!(!ctx.query_params.contains_key("debug"));

    // Test body rules via transform_request_body
    let body = br#"{"old_field":"data"}"#;
    let body_result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = b"<xml>not json</xml>";
    let result = plugin
        .transform_request_body(body, Some("application/xml"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_invalid_json_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let body = b"this is not json";
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_empty_body_skipped() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field", "value": "val"}
        ]
    }))
    .unwrap();

    let result = plugin
        .transform_request_body(b"", Some("application/json"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_transformer_body_no_body_rules_returns_false() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Custom", "value": "val"}
        ]
    }))
    .unwrap();

    assert!(!plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_body_deeply_nested_three_levels() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "a.b.c.d", "value": "deep_value"}
        ]
    }))
    .unwrap();

    let body = br#"{"a":{"b":{"c":{"d":"old"}}}}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"existing":"keep"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"name":"Alice"}"#;
    let result = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await;
    // No field was renamed, so no modification — returns None
    assert!(result.is_none());
}

// ── New behaviour: config validation & hot-path fast-path ─────────────────

#[tokio::test]
async fn test_request_transformer_modifies_request_headers_false_for_query_only() {
    // With only query rules, modifies_request_headers() must be false so the
    // handler can skip cloning ctx.headers.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "v", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_modifies_request_headers_false_for_body_only() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "v", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(!plugin.modifies_request_headers());
    assert!(plugin.modifies_request_body());
}

#[tokio::test]
async fn test_request_transformer_modifies_request_headers_true_for_header_rule() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-A", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(plugin.modifies_request_headers());
}

#[tokio::test]
async fn test_request_transformer_rejects_crlf_in_header_value() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Bad", "value": "ok\r\nX-Inject: evil"}
        ]
    }))
    .err()
    .expect("expected error for CRLF in header value");
    assert!(err.contains("CR or LF"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_body_rule_without_value() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "field"}
        ]
    }))
    .err()
    .expect("expected error for body add without value");
    assert!(err.contains("requires a 'value'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_body_rule_without_new_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old"}
        ]
    }))
    .err()
    .expect("expected error for body rename without new_key");
    assert!(err.contains("requires a 'new_key'"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_body_array_index() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "items.0.name", "value": "updated"}
        ]
    }))
    .unwrap();
    let body = br#"{"items":[{"name":"a"},{"name":"b"}]}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["items"][0]["name"], "updated");
    assert_eq!(parsed["items"][1]["name"], "b");
}

#[tokio::test]
async fn test_request_transformer_body_dot_escape_in_key() {
    // Key contains a literal dot — escaped as `\.` in the rule key.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "weird\\.key", "value": "v"}
        ]
    }))
    .unwrap();
    let body = br#"{"weird.key":"old"}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["weird.key"], "v");
}

// ── Strict type validation for config fields ──────────────────────────────

#[tokio::test]
async fn test_request_transformer_rejects_non_string_target() {
    // A numeric/boolean/object target must fail config load, not silently
    // coerce to "header".
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": 0, "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_operation() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": 42, "target": "header", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string operation");
    assert!(err.contains("'operation' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": 123, "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string key");
    assert!(err.contains("'key' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_invalid_header_key() {
    for key in ["bad header", "x:bad", "x/bad", "x\nbad"] {
        let err = RequestTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "header", "key": key, "value": "v"}
            ]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected invalid header key to be rejected: {key:?}"));
        assert!(err.contains("valid HTTP header name"), "got: {err}");
    }
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_value() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Count", "value": 42}
        ]
    }))
    .err()
    .expect("expected error for non-string header value");
    assert!(err.contains("'value' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_new_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old", "new_key": 7}
        ]
    }))
    .err()
    .expect("expected error for non-string new_key");
    assert!(err.contains("'new_key' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_invalid_header_new_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old", "new_key": "bad header"}
        ]
    }))
    .err()
    .expect("expected invalid header new_key to be rejected");
    assert!(err.contains("valid HTTP header name"), "got: {err}");
}

// ── JSON null value preservation on body rules ───────────────────────────

#[tokio::test]
async fn test_request_transformer_body_add_null_value() {
    // Explicit JSON null is a legitimate value — `value: null` on an `add`
    // rule must insert a JSON null into the body (not be treated as "missing
    // value" and reject the config at load time).
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "optional_field", "value": null}
        ]
    }))
    .unwrap();

    let body = br#"{"name":"Alice"}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("body should be modified");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed["optional_field"].is_null());
    assert_eq!(parsed["name"], "Alice");
}

#[tokio::test]
async fn test_request_transformer_body_update_null_value() {
    // `value: null` on an `update` rule must set the target field to null.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "status", "value": null}
        ]
    }))
    .unwrap();

    let body = br#"{"status":"active"}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("body should be modified");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed["status"].is_null());
}

#[tokio::test]
async fn test_request_transformer_rejects_non_string_body_target() {
    // Non-string target must be rejected even for what would be body rules,
    // via the shared `parse_body_rules` validator.
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": true, "key": "f", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_null_target() {
    // Explicit `"target": null` must fail config load; silently coercing null
    // would mask misconfiguration (typos, broken templating, etc.).
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": null, "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for null target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_missing_target() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for missing target");
    assert!(err.contains("'target' is required"), "got: {err}");
}

// ── Route-level transform overrides (`apply_route_overrides`) ──────────────
//
// `mesh_route_dispatch` publishes per-rule Arcs onto
// `ctx.route_override_request_transform`. The transformer plugin always
// consumes them at the end of `before_proxy`. When the proxy has no
// operator-configured `request_transformer`, the K8s VirtualService
// translator auto-emits an instance with `apply_route_overrides: true` and
// no static rules; that instance must still be valid and must declare
// `modifies_request_headers() == true` so the dispatcher clones headers.

use ferrum_edge::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, parse_route_header_transforms,
};
use std::sync::Arc;

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_accepts_empty_rules() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .expect("apply_route_overrides=true allows zero static rules");
    assert!(
        plugin.modifies_request_headers(),
        "apply_route_overrides=true must declare modifies_request_headers so the dispatcher clones headers"
    );
}

#[tokio::test]
async fn test_request_transformer_empty_rules_without_opt_in_still_errors() {
    let err = RequestTransformer::new(&json!({
        "rules": [],
    }))
    .err()
    .expect("zero rules without apply_route_overrides must error");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_route_override_applies_after_static_rules() {
    // Static rule sets X-Trace=static; route-level override sets
    // X-Trace=route. Per the documented precedence (static first, then
    // per-rule), the route override must win.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Trace", "value": "static"}
        ]
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Trace", "value": "route"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_rules);
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(headers.get("x-trace").map(String::as_str), Some("route"));
    // Plugin must consume the Arc so a subsequent transformer instance in
    // the chain does not re-apply the same list.
    assert!(ctx.route_override_request_transform.is_none());
}

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_no_static_rules_applies_overrides() {
    // The translator's auto-emitted instance: no static rules, only
    // consumes per-context overrides.
    let plugin = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"},
        {"operation": "remove", "target": "header", "key": "X-Debug"},
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_rules);
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-debug".to_string(), "yes".to_string());

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-api-version").map(String::as_str), Some("v1"));
    assert!(!headers.contains_key("x-debug"));
}

#[tokio::test]
async fn test_request_transformer_route_override_absent_is_no_op() {
    // Static rules continue to apply when no per-context override is
    // published — this is the steady-state path on every other request.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Static", "value": "1"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-static").map(String::as_str), Some("1"));
}

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_invalid_type_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": "yes",
    }))
    .err()
    .expect("non-boolean apply_route_overrides must error");
    assert!(err.contains("must be a boolean"), "got: {err}");
}

// === GAP-3E: RTDS overlay gate ===

#[tokio::test]
async fn test_request_transformer_runtime_overlay_scope_accepted() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "internal",
        "default_enabled": true
    }))
    .unwrap();
    assert_eq!(plugin.name(), "request_transformer");
}

#[tokio::test]
async fn test_request_transformer_rejects_empty_runtime_overlay_scope() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "   "
    }))
    .err()
    .unwrap();
    assert!(err.contains("runtime_overlay_scope"));
}

#[tokio::test]
async fn test_request_transformer_rejects_non_bool_default_enabled() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "internal",
        "default_enabled": "true"
    }))
    .err()
    .unwrap();
    assert!(err.contains("default_enabled"));
}

#[tokio::test]
async fn test_request_transformer_overlay_gate_observable_end_to_end() {
    // Single test that walks every overlay-gate behaviour serially to
    // avoid racing the process-global `request_transformer::runtime_overlay`
    // ArcSwap from parallel test cases.
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::request_transformer::runtime_overlay;
    use tokio::sync::Mutex;
    static GUARD: Mutex<()> = Mutex::const_new(());
    let _guard = GUARD.lock().await;

    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}
        ],
        "runtime_overlay_scope": "gated",
        "default_enabled": true
    }))
    .unwrap();

    // ── Case 1: overlay missing → fallback default_enabled=true applies the rule.
    runtime_overlay::reset_for_test();
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 2: overlay says enabled=false → rule short-circuited.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut make_ctx(), &mut headers).await;
    assert!(
        !headers.contains_key("x-gated"),
        "overlay=false must suppress the rule"
    );

    // ── Case 3: overlay says enabled=true → rule applies.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut make_ctx(), &mut headers).await;
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 4: plugin without a scope ignores the overlay entirely.
    runtime_overlay::reset_for_test();
    let no_scope_plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Plain", "value": "v"}
        ]
    }))
    .unwrap();
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    no_scope_plugin
        .before_proxy(&mut make_ctx(), &mut headers)
        .await;
    assert_eq!(
        headers.get("x-plain").map(String::as_str),
        Some("v"),
        "plugins without runtime_overlay_scope must always apply rules"
    );

    // ── Case 5: default_enabled=false combined with missing overlay
    //           suppresses rules until the overlay flips them on.
    runtime_overlay::reset_for_test();
    let pessimistic_plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Pess", "value": "v"}
        ],
        "runtime_overlay_scope": "pessimistic",
        "default_enabled": false
    }))
    .unwrap();
    let mut headers: HashMap<String, String> = HashMap::new();
    pessimistic_plugin
        .before_proxy(&mut make_ctx(), &mut headers)
        .await;
    assert!(
        !headers.contains_key("x-pess"),
        "default_enabled=false must suppress when overlay missing"
    );

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.pessimistic.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    pessimistic_plugin
        .before_proxy(&mut make_ctx(), &mut headers)
        .await;
    assert_eq!(headers.get("x-pess").map(String::as_str), Some("v"));

    runtime_overlay::reset_for_test();
}
