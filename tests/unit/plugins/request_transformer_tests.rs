//! Tests for request_transformer plugin

use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, RequestContext, priority,
    request_transformer::RequestTransformer,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{
    capture_debug_logs_during, normalize_compressed_request_for_plugin_test,
};

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
    // Header/query rules also run on WebSocket handshakes (request_transformer-SOL-3).
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
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
    assert_eq!(ctx.outbound_query_string(), Some("version=v2"));
}

#[tokio::test]
async fn test_query_transform_marks_metadata_for_raw_query_consumers() {
    // Mirror of `QUERY_PARAMS_TRANSFORMED_METADATA_KEY` (pub(crate) in proxy).
    const QUERY_PARAMS_TRANSFORMED_METADATA_KEY: &str = "ferrum:query_params_transformed";

    // A query rule that actually mutates the ordered query sets the marker.
    let mutating = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "token"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("token=secret&keep=1".to_string());
    ctx.materialize_query_params();
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = mutating.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        ctx.metadata
            .contains_key(QUERY_PARAMS_TRANSFORMED_METADATA_KEY),
        "an applied query transform must mark metadata for raw-query consumers"
    );
    assert_eq!(ctx.outbound_query_string(), Some("keep=1"));
    assert!(!ctx.query_params.contains_key("token"));

    // A query rule that no-ops (nothing to remove) must NOT set the marker, so a
    // safe raw-query composition is not needlessly rewritten.
    let noop = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "absent"}
        ]
    }))
    .unwrap();
    let mut noop_ctx = make_ctx();
    noop_ctx.set_raw_query_string("keep=value".to_string());
    noop_ctx.materialize_query_params();
    let mut noop_headers: HashMap<String, String> = HashMap::new();
    let _ = noop.before_proxy(&mut noop_ctx, &mut noop_headers).await;
    assert!(
        !noop_ctx
            .metadata
            .contains_key(QUERY_PARAMS_TRANSFORMED_METADATA_KEY),
        "a no-op query rule must not mark a query transform"
    );
    assert_eq!(noop_ctx.outbound_query_string(), None);

    // A header-only transform must not set the query-transform marker.
    let header_only = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "1"}
        ]
    }))
    .unwrap();
    let mut header_ctx = make_ctx();
    let mut header_headers: HashMap<String, String> = HashMap::new();
    let _ = header_only
        .before_proxy(&mut header_ctx, &mut header_headers)
        .await;
    assert!(
        !header_ctx
            .metadata
            .contains_key(QUERY_PARAMS_TRANSFORMED_METADATA_KEY),
        "a header-only transform must not mark a query transform"
    );
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
    assert!(err.contains("no `rules` configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_no_config() {
    let result = RequestTransformer::new(&json!({}));
    let err = result.err().expect("expected error for no config");
    assert!(err.contains("no `rules` configured"), "got: {err}");
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
                || err.contains("`rules` must be an array")
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
    assert!(err.contains("requires a `value`"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_unknown_operation_rejected() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "delete", "target": "header", "key": "X-Test", "value": "val"}
        ]
    }))
    .err()
    .expect("expected error for unknown `operation`");
    assert!(err.contains("unknown `operation`"), "got: {err}");
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
    .expect("expected error for unknown `target`");
    assert!(err.contains("unknown `target`"), "got: {err}");
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
    assert!(err.contains("requires a `new_key`"), "got: {err}");
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
async fn configured_decompression_exposes_plaintext_before_request_transforms() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "remove",
                "target": "body",
                "key": "credentials.api_key"
            }
        ]
    }))
    .unwrap();
    let plaintext = br#"{"credentials":{"api_key":"secret","region":"us"}}"#;

    for encoding in ["gzip", "br"] {
        let (mut ctx, headers, body) = normalize_compressed_request_for_plugin_test(
            "application/json",
            "/transform",
            encoding,
            plaintext,
        )
        .await;
        let transformed = plugin
            .transform_request_body_with_context(
                &mut ctx,
                &body,
                Some("application/json"),
                &headers,
            )
            .await
            .expect("decoded JSON rule must transform the request body");
        let transformed: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
        assert!(transformed["credentials"].get("api_key").is_none());
        assert_eq!(transformed["credentials"]["region"], "us");
    }
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
    // Stale integrity fields are retired by proxy core over the final
    // outbound headers, clone-on-write, so body rules no longer force a
    // per-request header-map copy (PR #6858 review SOL-6).
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "v", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(!plugin.modifies_request_headers());
    assert!(plugin.modifies_request_body());
    assert!(!plugin.modifies_request_query());
    // The context-aware body hook publishes the skip reason, so the H1/H2
    // dispatcher must select it (PR #6858 review SOL-2).
    assert!(plugin.needs_final_request_body_context());

    let header_only = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "x-a", "value": "1"}]
    }))
    .unwrap();
    assert!(!header_only.needs_final_request_body_context());
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
    assert!(err.contains("requires a `value`"), "got: {err}");
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
    assert!(err.contains("requires a `new_key`"), "got: {err}");
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
    assert!(err.contains("`target` must be a string"), "got: {err}");
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
    assert!(err.contains("`operation` must be a string"), "got: {err}");
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
    assert!(err.contains("`key` must be a string"), "got: {err}");
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
    assert!(err.contains("`value` must be a string"), "got: {err}");
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
    assert!(err.contains("`new_key` must be a string"), "got: {err}");
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
    assert!(err.contains("`target` must be a string"), "got: {err}");
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
    assert!(err.contains("`target` must be a string"), "got: {err}");
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
    assert!(err.contains("`target` is required"), "got: {err}");
}

// ── Route-level transform overrides (`apply_route_overrides`) ──────────────
//
// `mesh_route_dispatch` publishes per-rule Arcs onto
// `ctx.route_override_request_transform`. Enabled transformer instances apply
// only their static rules; proxy core applies the matched route list exactly
// once after the last eligible instance. When the proxy has no
// operator-configured `request_transformer`, the K8s VirtualService
// translator auto-emits an instance with `apply_route_overrides: true` and
// no static rules; that instance must still be valid and must declare
// `modifies_request_headers() == true` so the dispatcher clones headers.

use ferrum_edge::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, finalize_route_override_request_headers,
    parse_route_header_transforms,
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
    assert!(err.contains("no `rules` configured"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_route_override_applies_after_static_rules() {
    // Static rule sets X-Trace=static; route-level override sets
    // X-Trace=route. Per the documented precedence (static first, then
    // chain-level route finalization), the route override must win.
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
    finalize_route_override_request_headers(&mut ctx, &mut headers);

    assert_eq!(headers.get("x-trace").map(String::as_str), Some("route"));
    // Chain-level finalization consumes the Arc exactly once.
    assert!(ctx.route_override_request_transform.is_none());
}

#[tokio::test]
async fn test_request_transformer_apply_route_overrides_no_static_rules_applies_overrides() {
    // The translator's auto-emitted instance: no static rules, only
    // participates in chain-level route finalization.
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
    finalize_route_override_request_headers(&mut ctx, &mut headers);
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

#[test]
fn test_request_transformer_overlay_gate_parsing() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::request_transformer::runtime_overlay;

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.public.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    fields.insert(
        "ferrum.request_transformer.internal.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    fields.insert(
        "ferrum.request_transformer.bad.enabled".to_string(),
        RuntimeValue::Number(1.0),
    );
    fields.insert(
        "ferrum.request_transformer..enabled".to_string(),
        RuntimeValue::Bool(true),
    );

    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let snap = runtime_overlay::current_gates();
    assert_eq!(snap.gate("public"), Some(false));
    assert_eq!(snap.gate("internal"), Some(true));
    assert_eq!(snap.gate("bad"), None);
    assert_eq!(snap.gate(""), None);
    assert_eq!(snap.gate("missing"), None);

    runtime_overlay::apply_overlay(&MeshRuntimeOverlay::default());
    assert_eq!(runtime_overlay::current_gates().gate("public"), None);
}

/// The gate is resolved from CONFIGURATION, not from live process-global state
/// (GHSA-83rc-23c9-3g9x). Every case below therefore builds the instance from the
/// effective config a mesh generation would have produced, and no case touches
/// the process-global store — which is exactly the property being asserted: a
/// store mutation cannot reach a constructed instance.
///
/// Cross-generation and mid-request barriers live in
/// `tests/integration/transformer_runtime_overlay_generation_tests.rs`.
#[tokio::test]
async fn test_request_transformer_overlay_gate_resolves_from_effective_config() {
    let apply = |config: serde_json::Value| async move {
        let plugin = RequestTransformer::new(&config).unwrap();
        let mut headers: HashMap<String, String> = HashMap::new();
        let result = plugin.before_proxy(&mut make_ctx(), &mut headers).await;
        assert!(matches!(
            result,
            ferrum_edge::plugins::PluginResult::Continue
        ));
        headers
    };

    // ── Case 1: scope set, generation named no gate → default_enabled=true.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "default_enabled": true
    }))
    .await;
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 2: the generation resolved the gate to false → rules suppressed.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "default_enabled": true,
        "runtime_overlay_resolved_enabled": false
    }))
    .await;
    assert!(
        !headers.contains_key("x-gated"),
        "a resolved gate of false must suppress the rules"
    );

    // ── Case 3: the generation resolved the gate to true → rules apply, and it
    //           OVERRIDES a pessimistic default.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "default_enabled": false,
        "runtime_overlay_resolved_enabled": true
    }))
    .await;
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 4: no scope → always enabled, and a stray resolved value cannot
    //           gate an instance that never opted in.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Plain", "value": "v"}],
        "runtime_overlay_resolved_enabled": false
    }))
    .await;
    assert_eq!(
        headers.get("x-plain").map(String::as_str),
        Some("v"),
        "plugins without runtime_overlay_scope must always apply rules"
    );

    // ── Case 5: scope set, no resolved gate, default_enabled=false → suppressed.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Pess", "value": "v"}],
        "runtime_overlay_scope": "pessimistic",
        "default_enabled": false
    }))
    .await;
    assert!(
        !headers.contains_key("x-pess"),
        "default_enabled=false must suppress when the generation named no gate"
    );
}

/// A mutation of the process-global gate store must NOT change what an
/// already-constructed instance does. This is the direct regression guard for the
/// request-time lookup the advisory describes.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_request_transformer_ignores_live_process_global_gate_mutations() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::request_transformer::runtime_overlay;
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    // Built from a generation that resolved the gate to TRUE.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": true
    }))
    .unwrap();

    // Publish a CONTRADICTING gate into the live store, as a later accepted
    // slice would. The instance must not observe it.
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay {
        fields: HashMap::from([(
            "ferrum.request_transformer.gated.enabled".to_string(),
            RuntimeValue::Bool(false),
        )]),
    });

    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut make_ctx(), &mut headers).await;
    assert_eq!(
        headers.get("x-gated").map(String::as_str),
        Some("yes"),
        "a live store mutation must not reach an already-published instance"
    );

    // And the same in the other direction.
    let disabled = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": false
    }))
    .unwrap();
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay {
        fields: HashMap::from([(
            "ferrum.request_transformer.gated.enabled".to_string(),
            RuntimeValue::Bool(true),
        )]),
    });
    let mut headers: HashMap<String, String> = HashMap::new();
    disabled.before_proxy(&mut make_ctx(), &mut headers).await;
    assert!(
        !headers.contains_key("x-gated"),
        "a live store mutation must not enable an instance published as disabled"
    );

    runtime_overlay::reset_for_test();
}

#[test]
fn test_request_transformer_disabled_generation_drops_mutation_and_buffering_capabilities() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Sanitized", "value": "yes"},
            {"operation": "remove", "target": "query", "key": "debug"},
            {"operation": "remove", "target": "body", "key": "secret"}
        ],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": false
    }))
    .unwrap();

    assert!(
        !plugin.modifies_request_headers(),
        "a disabled generation must not force request-header cloning"
    );
    // request_transformer-claude-3: the query capability honors the same gate,
    // so a disabled generation cannot trip later-than-dedup/cache composition
    // refusals or early-route-total query accounting.
    assert!(
        !plugin.modifies_request_query(),
        "a disabled generation must not advertise query mutation"
    );
    assert!(
        !plugin.modifies_request_body(),
        "a disabled generation has no request-body transform"
    );
    assert!(
        !plugin.requires_request_body_buffering(),
        "a disabled generation must not advertise request buffering"
    );
    assert!(
        !plugin.should_buffer_request_body(&make_ctx()),
        "request-time buffering must agree with the immutable disabled gate"
    );
}

#[tokio::test]
async fn test_request_transformer_rejects_non_boolean_resolved_gate() {
    let err = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": "true"
    }))
    .err()
    .expect("a non-boolean resolved gate must be rejected");
    assert!(
        err.contains("runtime_overlay_resolved_enabled"),
        "got: {err}"
    );
}

// ── Issue #2374: unknown keys, operation-exact fields, HeaderValue admission ──

#[tokio::test]
async fn test_request_transformer_rejects_unknown_top_level_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Color", "value": "blue"}
        ],
        "runtime_overlay_scpoe": "internal"
    }))
    .err()
    .expect("expected error for unknown top-level key");
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("runtime_overlay_scpoe"), "got: {err}");
    assert!(err.contains("under `config`"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_unknown_header_rule_key() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "vaule": "green"
            }
        ]
    }))
    .err()
    .expect("expected error for unknown header rule key");
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("vaule"), "got: {err}");
    assert!(err.contains("config.rules[0]"), "got: {err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_unknown_query_and_body_rule_keys() {
    let query_err = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue",
                "typo_key": 1
            }
        ]
    }))
    .err()
    .expect("expected error for unknown query rule key");
    assert!(query_err.contains("typo_key"), "got: {query_err}");
    assert!(query_err.contains("config.rules[0]"), "got: {query_err}");

    let body_err = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "add",
                "target": "body",
                "key": "enabled",
                "value": true,
                "extra_field": 1
            }
        ]
    }))
    .err()
    .expect("expected error for unknown body rule key");
    assert!(body_err.contains("extra_field"), "got: {body_err}");
    assert!(body_err.contains("config.rules[0]"), "got: {body_err}");
}

#[tokio::test]
async fn test_request_transformer_rejects_incompatible_header_and_query_fields() {
    for (rule, needle) in [
        (
            json!({
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": "X-Ignored"
            }),
            "`new_key` must not be set for \"header\" \"add\"",
        ),
        (
            json!({
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": "X-Ignored"
            }),
            "`new_key` must not be set for \"header\" \"update\"",
        ),
        (
            json!({
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": "ignored"
            }),
            "`value` must not be set for \"header\" `rename`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "value": "ignored"
            }),
            "`value` must not be set for \"header\" `remove`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "new_key": "X-Ignored"
            }),
            "`new_key` must not be set for \"header\" `remove`",
        ),
        (
            json!({
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue",
                "new_key": "ignored"
            }),
            "`new_key` must not be set for \"query\" \"add\"",
        ),
        (
            json!({
                "operation": "update",
                "target": "query",
                "key": "color",
                "value": "blue",
                "new_key": "ignored"
            }),
            "`new_key` must not be set for \"query\" \"update\"",
        ),
        (
            json!({
                "operation": "rename",
                "target": "query",
                "key": "old",
                "new_key": "new",
                "value": "ignored"
            }),
            "`value` must not be set for \"query\" `rename`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "value": "ignored"
            }),
            "`value` must not be set for \"query\" `remove`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "new_key": "ignored"
            }),
            "`new_key` must not be set for \"query\" `remove`",
        ),
        (
            json!({
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": null
            }),
            "`new_key` must not be set for \"header\" \"add\"",
        ),
        (
            json!({
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": null
            }),
            "`value` must not be set for \"header\" `rename`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "value": null
            }),
            "`value` must not be set for \"header\" `remove`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "new_key": null
            }),
            "`new_key` must not be set for \"header\" `remove`",
        ),
        (
            json!({
                "operation": "add",
                "target": "query",
                "key": "color",
                "value": "blue",
                "new_key": null
            }),
            "`new_key` must not be set for \"query\" \"add\"",
        ),
        (
            json!({
                "operation": "rename",
                "target": "query",
                "key": "old",
                "new_key": "new",
                "value": null
            }),
            "`value` must not be set for \"query\" `rename`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "value": null
            }),
            "`value` must not be set for \"query\" `remove`",
        ),
        (
            json!({
                "operation": "remove",
                "target": "query",
                "key": "color",
                "new_key": null
            }),
            "`new_key` must not be set for \"query\" `remove`",
        ),
    ] {
        let err = RequestTransformer::new(&json!({ "rules": [rule] }))
            .err()
            .expect("expected incompatible field rejection");
        assert!(
            err.contains(needle),
            "expected needle {needle:?}, got: {err}"
        );
    }
}

#[tokio::test]
async fn test_request_transformer_rejects_forbidden_header_control_bytes() {
    for (label, value) in [
        ("NUL", "ok\u{0000}bad"),
        ("SOH", "ok\u{0001}bad"),
        ("BEL", "ok\u{0007}bad"),
        ("DEL", "ok\u{007f}bad"),
    ] {
        let err = RequestTransformer::new(&json!({
            "rules": [
                {"operation": "update", "target": "header", "key": "X-Color", "value": value}
            ]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected HeaderValue rejection for {label}"));
        assert!(err.contains("valid HTTP HeaderValue"), "{label}: got {err}");
    }
}

#[tokio::test]
async fn test_request_transformer_accepts_valid_header_value_edge_cases() {
    for value in [
        "",
        " ",
        "\t",
        "plain",
        "a b",
        "tab\there",
        "café",
        "!#$%&'*+-.^_`|~",
    ] {
        let plugin = RequestTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "header", "key": "X-Edge", "value": value}
            ]
        }));
        if let Err(error) = plugin {
            panic!("valid HeaderValue edge case rejected: {value:?} -> {error}");
        }
    }
}

#[tokio::test]
async fn test_request_transformer_accepted_values_pass_backend_adapter_gates() {
    // Outbound Hyper / native H3 / reqwest adapters all parse outbound header
    // values through `HeaderValue::from_str` (or the same http type). Values
    // admitted by construction must therefore succeed on every adapter gate.
    let values = [
        "plain",
        "a b",
        "tab\there",
        "café",
        "!#$%&'*+-.^_`|~",
        "",
        " ",
    ];
    for value in values {
        RequestTransformer::new(&json!({
            "rules": [
                {"operation": "update", "target": "header", "key": "X-Parity", "value": value}
            ]
        }))
        .unwrap_or_else(|e| panic!("construction rejected {value:?}: {e}"));

        assert!(
            http::HeaderValue::from_str(value).is_ok(),
            "http HeaderValue rejected admitted value {value:?}"
        );
        assert!(
            hyper::header::HeaderValue::from_str(value).is_ok(),
            "hyper HeaderValue rejected admitted value {value:?}"
        );
        assert!(
            reqwest::header::HeaderValue::from_str(value).is_ok(),
            "reqwest HeaderValue rejected admitted value {value:?}"
        );
    }
}

#[tokio::test]
async fn test_request_transformer_route_level_rejects_invalid_control_values() {
    // Route-level transforms share the same HeaderValue + CR/LF admission gate.
    let crlf: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Bad", "value": "a\r\nInjected: 1"}
    ]))
    .unwrap();
    let crlf_err = parse_route_header_transforms(&crlf, "route_override").unwrap_err();
    assert!(crlf_err.contains("CR or LF"), "got: {crlf_err}");

    let nul: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "add", "target": "header", "key": "X-Bad", "value": "ok\u{0000}bad"}
    ]))
    .unwrap();
    let nul_err = parse_route_header_transforms(&nul, "route_override").unwrap_err();
    assert!(nul_err.contains("valid HTTP HeaderValue"), "got: {nul_err}");
}

#[tokio::test]
async fn test_request_transformer_route_level_accepted_value_applies() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Route", "value": "tab\there"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_rules);
    let mut headers: HashMap<String, String> = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    finalize_route_override_request_headers(&mut ctx, &mut headers);
    assert_eq!(
        headers.get("x-route").map(String::as_str),
        Some("tab\there")
    );
}

// ── Header mutation tracing must never emit configured values ─────────────

fn assert_secret_absent_from_logs(logs: &str, secret: &str) {
    assert!(
        !logs.contains(secret),
        "configured header value must not appear in tracing output: {secret:?}\nlogs:\n{logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_request_transformer_header_mutations_never_log_configured_values() {
    let cases = [
        (
            "add",
            json!({"operation": "add", "target": "header", "key": "Authorization", "value": "Bearer backend-token-never-log"}),
            HashMap::new(),
            "authorization",
            "Bearer backend-token-never-log",
        ),
        (
            "update",
            json!({"operation": "update", "target": "header", "key": "Set-Cookie", "value": "session=opaque-cookie-never-log"}),
            HashMap::from([("set-cookie".to_string(), "old=discard".to_string())]),
            "set-cookie",
            "session=opaque-cookie-never-log",
        ),
        (
            "api-key add",
            json!({"operation": "add", "target": "header", "key": "X-Api-Key", "value": "api-key-secret-never-log"}),
            HashMap::new(),
            "x-api-key",
            "api-key-secret-never-log",
        ),
        (
            "signature update",
            json!({"operation": "update", "target": "header", "key": "X-Signature", "value": "sha256=sig-never-log"}),
            HashMap::new(),
            "x-signature",
            "sha256=sig-never-log",
        ),
        (
            "custom add",
            json!({"operation": "add", "target": "header", "key": "X-Tenant-Credential", "value": "arbitrary-custom-never-log"}),
            HashMap::new(),
            "x-tenant-credential",
            "arbitrary-custom-never-log",
        ),
    ];

    for (label, rule, mut seed_headers, expected_key, secret) in cases {
        let plugin = RequestTransformer::new(&json!({ "rules": [rule] })).unwrap();
        let logs = capture_debug_logs_during(|| async {
            let mut ctx = make_ctx();
            let mut headers = std::mem::take(&mut seed_headers);
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                headers.get(expected_key).map(String::as_str),
                Some(secret),
                "{label}: header mutation must still apply"
            );
        })
        .await;
        assert_secret_absent_from_logs(&logs, secret);
        assert!(
            logs.contains("request_transformer:"),
            "{label}: expected transformer debug event, got:\n{logs}"
        );
    }

    // Remove only logs the header name; still exercise it with a sensitive key.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "Authorization"}
        ]
    }))
    .unwrap();
    let logs = capture_debug_logs_during(|| async {
        let mut ctx = make_ctx();
        let mut headers = HashMap::from([(
            "authorization".to_string(),
            "Bearer existing-token-never-log".to_string(),
        )]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(!headers.contains_key("authorization"));
    })
    .await;
    assert_secret_absent_from_logs(&logs, "Bearer existing-token-never-log");
    assert!(
        logs.contains("request_transformer: removed header authorization"),
        "remove should still emit a name-only diagnostic"
    );
}

#[tokio::test]
async fn test_ordered_query_duplicate_and_encoding_semantics() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "access_token"},
            {"operation": "update", "target": "query", "key": "tag", "value": "green"},
            {"operation": "add", "target": "query", "key": "version", "value": "v2"},
            {"operation": "rename", "target": "query", "key": "old", "new_key": "new"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    // Duplicates, key-without-equals, empty value, plus, percent-encoded name/value,
    // and an invalid percent triplet retained on an unmodified keep pair.
    ctx.set_raw_query_string(
        "access_token=secret&tag=red&tag=blue&flag&empty=&q=a+b&old=1&keep=%ZZ&name=%E2%9C%93"
            .to_string(),
    );
    ctx.materialize_query_params();
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(
        ctx.outbound_query_string(),
        Some("tag=green&tag=green&flag&empty=&q=a+b&new=1&keep=%ZZ&name=%E2%9C%93&version=v2")
    );
    assert!(!ctx.query_params.contains_key("access_token"));
    assert_eq!(
        ctx.query_params.get("tag").map(String::as_str),
        Some("green")
    );
    assert_eq!(
        ctx.query_params.get("version").map(String::as_str),
        Some("v2")
    );
    assert_eq!(ctx.query_params.get("new").map(String::as_str), Some("1"));
    assert!(!ctx.query_params.contains_key("old"));
}

#[tokio::test]
async fn test_query_add_does_not_overwrite_existing_duplicate_name() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "tag", "value": "green"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("tag=red&tag=blue".to_string());
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.outbound_query_string(), None);
    assert!(!ctx.metadata.contains_key("ferrum:query_params_transformed"));
}

#[tokio::test]
async fn test_query_update_creates_when_absent_and_encodes_spaces() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "query", "key": "q", "value": "a b"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("keep=1".to_string());
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.outbound_query_string(), Some("keep=1&q=a%20b"));
}

#[tokio::test]
async fn test_query_rename_preserves_flag_without_equals() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "query", "key": "flag", "new_key": "enabled"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("flag&keep=".to_string());
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.outbound_query_string(), Some("enabled&keep="));
}

#[tokio::test]
async fn test_query_repeated_rules_apply_in_order() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "step", "value": "1"},
            {"operation": "update", "target": "query", "key": "step", "value": "2"},
            {"operation": "rename", "target": "query", "key": "step", "new_key": "phase"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.outbound_query_string(), Some("phase=2"));
}

#[tokio::test]
async fn test_query_crlf_rejected_at_construction() {
    let err = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "x", "value": "a\nb"}
        ]
    }))
    .err()
    .expect("CRLF query value must be rejected");
    assert!(err.contains("must not contain CR or LF"), "got: {err}");
}

#[tokio::test]
async fn test_query_transform_composes_with_auth_strip_helper() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "query", "key": "page", "value": "2"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("api_key=secret&page=1&keep=1".to_string());
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    // Auth-marked credentials are stripped from the transform input before
    // query rules run, so the published outbound query never retains them.
    assert_eq!(ctx.outbound_query_string(), Some("page=2&keep=1"));
    assert!(!ctx.query_params.contains_key("api_key"));
    let effective = ferrum_edge::_test_support::effective_backend_query_string_for_test(&ctx);
    assert_eq!(effective, "page=2&keep=1");
}

#[tokio::test]
async fn test_auth_marked_credential_cannot_survive_rename() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "query", "key": "access_token", "new_key": "moved"},
            {"operation": "add", "target": "query", "key": "page", "value": "2"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("access_token=never-forward-this&keep=1".to_string());
    ctx.materialize_query_params();
    assert_eq!(
        ctx.query_params.get("access_token").map(String::as_str),
        Some("never-forward-this")
    );
    ctx.metadata.insert(
        "auth.strip_query_param.access_token".to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Renaming an auth-marked credential must not move the secret to a new
    // outbound name, nor leave it in the plugin-visible map.
    assert_eq!(ctx.outbound_query_string(), Some("keep=1&page=2"));
    assert!(!ctx.query_params.contains_key("access_token"));
    assert!(!ctx.query_params.contains_key("moved"));
    assert!(
        !ctx.query_params
            .values()
            .any(|value| value == "never-forward-this")
    );

    let effective = ferrum_edge::_test_support::effective_backend_query_string_for_test(&ctx);
    assert_eq!(effective, "keep=1&page=2");
    assert!(!effective.contains("never-forward-this"));
    assert!(!effective.contains("moved="));
    assert!(!effective.contains("access_token"));
}

#[tokio::test]
async fn test_query_transform_does_not_log_secret_values() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "access_token"},
            {"operation": "update", "target": "query", "key": "page", "value": "super-secret-page"}
        ]
    }))
    .unwrap();
    let logs = capture_debug_logs_during(|| async {
        let mut ctx = make_ctx();
        ctx.set_raw_query_string("access_token=never-log-this-token&page=1".to_string());
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.outbound_query_string(), Some("page=super-secret-page"));
    })
    .await;
    assert_secret_absent_from_logs(&logs, "never-log-this-token");
    assert_secret_absent_from_logs(&logs, "super-secret-page");
}

#[tokio::test]
async fn test_query_rules_do_not_declare_query_predicates() {
    // Query matching parses the retained raw/outbound query itself; the
    // transformer mutates the query rather than deciding on it.
    let with_query = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "query", "key": "token"}
        ]
    }))
    .unwrap();
    assert!(
        !with_query.requires_decoded_query_params(),
        "request_transformer query rules are mutations, not query predicates"
    );

    let header_only = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "1"}
        ]
    }))
    .unwrap();
    assert!(!header_only.requires_decoded_query_params());
}

#[test]
fn gateway_owned_request_destinations_fail_admission() {
    for destination in [
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Host",
        "X-Forwarded-For",
        "X-Forwarded-Proto",
        "X-Forwarded-Host",
        "Keep-Alive",
        "Proxy-Authorization",
        "Proxy-Connection",
        "TE",
        "Trailer",
        "Upgrade",
        "Expect",
        "X-Ferrum-Original-Content-Encoding",
        "X-Grpc-Web-Mode",
    ] {
        for operation in ["add", "update", "rename"] {
            let rule = if operation == "rename" {
                json!({"target": "header", "operation": operation,
                    "key": "x-source", "new_key": destination})
            } else {
                json!({"target": "header", "operation": operation,
                    "key": destination, "value": "configured"})
            };
            let error = RequestTransformer::new(&json!({"rules": [rule]}))
                .err()
                .expect("gateway-owned destination must fail admission");
            assert!(error.contains(&destination.to_ascii_lowercase()));
            assert!(error.contains("gateway-owned"));
        }
        for rule in [
            json!({"target": "header", "operation": "remove", "key": destination}),
            json!({"target": "header", "operation": "rename",
                "key": destination, "new_key": "x-captured"}),
            json!({"target": "query", "operation": "update",
                "key": destination, "value": "ordinary-query-value"}),
        ] {
            assert!(RequestTransformer::new(&json!({"rules": [rule]})).is_ok());
        }
    }
}

// ---------------------------------------------------------------------------
// The `x-consumer-*` namespace is gateway-owned consumer assertion metadata
// ---------------------------------------------------------------------------

#[test]
fn admission_refuses_every_consumer_assertion_namespace_destination() {
    for destination in [
        "x-consumer-foo",
        "X-Consumer-Role",
        "X-CONSUMER-GROUPS",
        "x-consumer-username",
        "x-consumer-custom-id",
        // `_` is equivalent to `-` in the namespace prefix.
        "X_Consumer_Role",
        "x_consumer-groups",
    ] {
        for operation in ["add", "update", "rename"] {
            let rule = if operation == "rename" {
                json!({"target": "header", "operation": operation,
                    "key": "x-source", "new_key": destination})
            } else {
                json!({"target": "header", "operation": operation,
                    "key": destination, "value": "admin"})
            };
            let error = RequestTransformer::new(&json!({"rules": [rule]}))
                .err()
                .expect("an x-consumer-* destination must fail admission");
            assert!(
                error.contains("`rule[0]`"),
                "{operation} {destination}: {error}"
            );
            assert!(
                error.contains(&destination.to_ascii_lowercase()),
                "{operation} {destination}: {error}"
            );
            assert!(
                error.contains("`x-consumer-*`"),
                "{operation} {destination}: {error}"
            );
        }
        // Removing, or renaming a value away from the namespace, stays legal.
        for rule in [
            json!({"target": "header", "operation": "remove", "key": destination}),
            json!({"target": "header", "operation": "rename",
                "key": destination, "new_key": "x-captured"}),
        ] {
            assert!(RequestTransformer::new(&json!({"rules": [rule]})).is_ok());
        }
    }
    // Names that only resemble the prefix are ordinary headers.
    for destination in [
        "x-consumer",
        "x-consumers-role",
        "x-consumerrole",
        "x_consumer",
    ] {
        let config = json!({"rules": [
            {"target": "header", "operation": "add", "key": destination, "value": "v"}
        ]});
        assert!(
            RequestTransformer::new(&config).is_ok(),
            "{destination} is outside the gateway-owned namespace"
        );
    }
}

// ---------------------------------------------------------------------------
// Issue #5106 — a JSON-only body rule must not pin an ordinary non-JSON upload
// to the buffered path. The config-time capability stays the upper bound; the
// per-request predicate is the exact negation of what `transform_request_body`
// declines on media type.
// ---------------------------------------------------------------------------

fn body_rule_plugin() -> RequestTransformer {
    RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "state", "value": "changed"}
        ]
    }))
    .unwrap()
}

fn upload_ctx(content_type: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/upload".to_string(),
    );
    if let Some(content_type) = content_type {
        ctx.headers
            .insert("content-type".to_string(), content_type.to_string());
    }
    ctx
}

#[test]
fn declared_non_json_uploads_release_request_buffering() {
    let plugin = body_rule_plugin();
    assert!(
        plugin.requires_request_body_buffering(),
        "the config-time capability remains the upper bound"
    );

    for content_type in [
        "application/octet-stream",
        "multipart/form-data; boundary=----x",
        "application/x-www-form-urlencoded",
        "image/png",
        "video/mp4",
        "text/plain; charset=utf-8",
        "application/grpc",
        "application/grpc-web+proto",
    ] {
        let ctx = upload_ctx(Some(content_type));
        assert!(
            !plugin.should_buffer_request_body(&ctx),
            "the transform declines `{content_type}`, so it must stream"
        );
    }
}

#[test]
fn json_and_untyped_uploads_keep_request_buffering() {
    let plugin = body_rule_plugin();

    for content_type in [
        "application/json",
        "application/json; charset=utf-8",
        "application/merge-patch+json",
        // Framed gRPC `+json` satisfies `is_json_content_type`, so it stays
        // buffered exactly as the transform treats it: declined only after the
        // document parse fails.
        "application/grpc+json",
    ] {
        let ctx = upload_ctx(Some(content_type));
        assert!(
            plugin.should_buffer_request_body(&ctx),
            "the transform inspects `{content_type}`, so it must buffer"
        );
    }

    let untyped = upload_ctx(None);
    assert!(
        plugin.should_buffer_request_body(&untyped),
        "an absent Content-Type is parsed as JSON by the transform"
    );
}

#[test]
fn header_and_query_only_instances_never_pin_a_request_body() {
    let header_only = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-A", "value": "1"}]
    }))
    .unwrap();
    let query_only = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "query", "key": "a", "value": "1"}]
    }))
    .unwrap();

    let ctx = upload_ctx(Some("application/json"));
    for plugin in [header_only, query_only] {
        assert!(!plugin.requires_request_body_buffering());
        assert!(!plugin.should_buffer_request_body(&ctx));
    }
}

#[test]
fn an_unrelated_header_rule_does_not_rebuffer_a_non_json_upload() {
    // The mixed-rule shape: one ordinary header rule beside the JSON body rule.
    // Header rules run in `before_proxy` and need no body, so the upload still
    // streams.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Audit", "value": "yes"},
            {"operation": "update", "target": "body", "key": "state", "value": "changed"}
        ]
    }))
    .unwrap();

    let binary = upload_ctx(Some("application/octet-stream"));
    assert!(!plugin.should_buffer_request_body(&binary));

    let json_upload = upload_ctx(Some("application/json"));
    assert!(plugin.should_buffer_request_body(&json_upload));
}

#[test]
fn a_disabled_generation_releases_every_upload() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "secret"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": false
    }))
    .unwrap();

    let json_upload = upload_ctx(Some("application/json"));
    assert!(!plugin.should_buffer_request_body(&json_upload));
}

#[tokio::test]
async fn a_released_non_json_upload_would_have_been_declined_anyway() {
    // Proves the predicate is not widening behaviour: the bytes the gateway now
    // streams are exactly the bytes the transform returns `None` for, while a
    // JSON control still gets rewritten.
    let plugin = body_rule_plugin();
    let body = br#"{"state":"original"}"#;
    let hdrs = HashMap::new();

    let ct = "application/octet-stream";
    let declined = plugin.transform_request_body(body, Some(ct), &hdrs).await;
    assert!(declined.is_none(), "a binary upload must be declined");

    let json_ct = "application/json";
    let rewritten = plugin
        .transform_request_body(body, Some(json_ct), &hdrs)
        .await
        .expect("the JSON control is still transformed");
    let rewritten = String::from_utf8(rewritten).expect("UTF-8 output");
    assert_eq!(rewritten, r#"{"state":"changed"}"#);
}

#[test]
fn the_shared_request_dispatch_decision_follows_the_upload_media_type() {
    use ferrum_edge::_test_support::final_request_body_requirements_for_test;

    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(body_rule_plugin())];

    let binary = upload_ctx(Some("application/octet-stream"));
    let (buffers_binary, _, _) =
        final_request_body_requirements_for_test(&plugins, &binary, true, false, false, false);
    assert!(!buffers_binary, "an ordinary binary upload must stream");

    // The post-`before_proxy` re-evaluation is what keeps a header rewrite from
    // bypassing the rules: proxy core re-runs this against the effective
    // outbound headers, so a `text/plain` -> `application/json` rewrite still
    // selects buffering before the body is read.
    let rewritten = upload_ctx(Some("application/json"));
    let (buffers_json, _, _) =
        final_request_body_requirements_for_test(&plugins, &rewritten, true, false, false, false);
    assert!(buffers_json, "a JSON upload is still collected");
}

// ---------------------------------------------------------------------------
// Issue #5108 — body rules reject operation-incompatible `new_key` by PRESENCE,
// so an explicit `new_key: null` fails exactly as a string would.
// ---------------------------------------------------------------------------

#[test]
fn body_rules_reject_explicitly_null_new_key_on_every_incompatible_operation() {
    for operation in ["add", "update", "remove"] {
        let mut rule = json!({
            "operation": operation,
            "target": "body",
            "key": "v",
            "new_key": null
        });
        if operation != "remove" {
            rule["value"] = json!(1);
        }
        let error = RequestTransformer::new(&json!({"rules": [rule]}))
            .err()
            .expect("an explicit null new_key must fail admission");
        let needle = if operation == "remove" {
            "must not be set for body `remove`".to_string()
        } else {
            format!("must not be set for body {operation:?}")
        };
        assert!(error.contains("`new_key`"), "got: {error}");
        assert!(error.contains(&needle), "got: {error}");
    }
}

#[test]
fn body_rules_keep_explicit_null_as_a_value() {
    // `value: null` on add/update is a legitimate operation — it sets the field
    // to JSON null — and must keep passing.
    for operation in ["add", "update"] {
        let config = json!({
            "rules": [
                {"operation": operation, "target": "body", "key": "v", "value": null}
            ]
        });
        assert!(RequestTransformer::new(&config).is_ok(), "{operation}");
    }
}

#[test]
fn a_null_body_rename_target_is_still_a_missing_rename_target() {
    let config = json!({
        "rules": [{"operation": "rename", "target": "body", "key": "a", "new_key": null}]
    });
    let error = RequestTransformer::new(&config)
        .err()
        .expect("rename without a new_key must fail");
    assert!(error.contains("requires a `new_key`"), "got: {error}");

    let valid = json!({
        "rules": [{"operation": "rename", "target": "body", "key": "a", "new_key": "b"}]
    });
    assert!(RequestTransformer::new(&valid).is_ok());
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let token = "'\"`UNREGISTERED_TRAFFIC_TOKEN\\tail";
    for (config, field, reason) in [
        (
            json!({"rules": [{"target": token}]}),
            "`rule[0]`",
            "unknown `target`",
        ),
        (
            json!({"rules": [{"target": "header", "operation": token}]}),
            "`operation`",
            "unknown",
        ),
        (
            json!({"rules": [{"target": "body", "operation": token}]}),
            "`rule[0]`",
            "unknown body `operation`",
        ),
        (
            json!({"rules": [{"target": "body", "operation": "rename", "key": format!("{token}.0"), "new_key": token}]}),
            "`key` or `new_key`",
            "does not support array indices",
        ),
        (
            json!({"rules": [{token: true}]}),
            "`config.rules[0]`",
            "unknown config key",
        ),
        (
            json!({"rules": [{"target": 918273641}]}),
            "`target`",
            "must be a string",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("request_transformer", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// ---------------------------------------------------------------------------
// Production-launch review fixes (request_transformer-SOL-*, -claude-*)
// ---------------------------------------------------------------------------

fn post_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test".to_string(),
    )
}

/// Parse a JSON object into its members' raw lexemes, so assertions compare
/// the exact bytes the backend receives rather than two values already rounded
/// through the same `serde_json::Value` representation.
fn raw_members(body: &[u8]) -> HashMap<String, String> {
    let members: HashMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(body).expect("transformed body is a JSON object");
    members
        .into_iter()
        .map(|(name, raw)| (name, raw.get().to_string()))
        .collect()
}

#[tokio::test]
async fn body_rewrite_preserves_lossy_number_lexemes_exactly() {
    // request_transformer-SOL-1: removing an unrelated field re-serializes the
    // whole document; numbers outside the 64-bit integer range and decimals
    // beyond binary64 precision must reach the backend byte-for-byte.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let body = br#"{"id":18446744073709551617,"neg":-9223372036854775809,"pi":3.14159265358979323846264338327950288,"price":1.50,"tiny":2.5e-3,"zero":-0,"plain":42,"nested":[1.10,{"x":123456789012345678901234567890}],"debug":true}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("the remove rule rewrites the body");
    let members = raw_members(&out);
    assert!(!members.contains_key("debug"));
    assert_eq!(members["id"], "18446744073709551617");
    assert_eq!(members["neg"], "-9223372036854775809");
    assert_eq!(members["pi"], "3.14159265358979323846264338327950288");
    assert_eq!(members["price"], "1.50");
    assert_eq!(members["tiny"], "2.5e-3");
    assert_eq!(members["zero"], "-0");
    assert_eq!(members["plain"], "42");
    assert_eq!(
        members["nested"],
        r#"[1.10,{"x":123456789012345678901234567890}]"#
    );
}

#[tokio::test]
async fn body_rename_and_update_keep_number_lexemes_where_they_land() {
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "amount", "new_key": "total"},
            {"operation": "update", "target": "body", "key": "rate", "value": 5}
        ]
    }))
    .unwrap();
    let body = br#"{"amount":1.000000000000000000001,"rate":0.30000000000000000000001,"keep":98765432109876543210}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("rename + update rewrite the body");
    let members = raw_members(&out);
    assert!(!members.contains_key("amount"));
    assert_eq!(members["total"], "1.000000000000000000001");
    assert_eq!(
        members["rate"], "5",
        "an overwritten number takes the rule value"
    );
    assert_eq!(members["keep"], "98765432109876543210");
}

#[tokio::test]
async fn body_number_preservation_survives_stand_in_shaped_client_strings() {
    // A client string shaped like a private stand-in stays a string AND no
    // longer disables preservation of unrelated lossy numbers (PR #6858
    // review SOL-4): the stand-in generation is chosen to be unused.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let body = br#"{"s":"\u0000ferrum-number-0:0","t":"\u0000ferrum-number-1:0","u":"\u0000ferrum-number:0","id":18446744073709551617,"pi":3.14159265358979323846264338327950288,"debug":true}"#;
    let out = plugin
        .transform_request_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("the remove rule rewrites the body");
    let members = raw_members(&out);
    assert!(!members.contains_key("debug"));
    assert_eq!(members["s"], r#""\u0000ferrum-number-0:0""#);
    assert_eq!(members["t"], r#""\u0000ferrum-number-1:0""#);
    assert_eq!(members["u"], r#""\u0000ferrum-number:0""#);
    assert_eq!(members["id"], "18446744073709551617");
    assert_eq!(members["pi"], "3.14159265358979323846264338327950288");
}

fn integrity_headers(content_type: Option<&str>) -> HashMap<String, String> {
    let mut headers: HashMap<String, String> = HashMap::new();
    if let Some(content_type) = content_type {
        headers.insert("content-type".to_string(), content_type.to_string());
    }
    headers.insert("content-digest".to_string(), "sha-256=:stale:".to_string());
    headers.insert("Repr-Digest".to_string(), "sha-256=:stale:".to_string());
    headers.insert("digest".to_string(), "SHA-256=stale".to_string());
    headers.insert("content-md5".to_string(), "stale".to_string());
    headers.insert("x-keep".to_string(), "1".to_string());
    headers
}

fn retain_client_wire_headers(ctx: &mut RequestContext, headers: &HashMap<String, String>) {
    let mut wire = http::HeaderMap::new();
    for (name, value) in headers {
        wire.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse::<http::HeaderValue>().unwrap(),
        );
    }
    ctx.set_raw_headers(wire);
}

/// Run `before_proxy`, then the final-header boundary, retaining the pristine
/// wire view as both frontends do. An unchanged map takes the no-copy path.
async fn run_chain_then_retire(
    plugins: &[&RequestTransformer],
    ctx: &mut RequestContext,
    inbound: HashMap<String, String>,
) -> Option<HashMap<String, String>> {
    retain_client_wire_headers(ctx, &inbound);
    ctx.headers = inbound.clone();
    let mut outbound = inbound.clone();
    for plugin in plugins {
        plugin.before_proxy(ctx, &mut outbound).await;
    }
    ctx.headers = inbound;
    let mut owned = (outbound != ctx.headers).then_some(outbound);
    ferrum_edge::_test_support::retire_stale_request_integrity_headers(ctx, &mut owned);
    owned
}

/// Exercise both the ordinary H1/H2/H3 boundary and native H3's owned-map
/// deferred boundary with the same behavioral assertions.
fn finalize_body_rule_headers_on_surface(
    ctx: &mut RequestContext,
    outbound: &mut HashMap<String, String>,
    in_map: bool,
) {
    if in_map {
        ferrum_edge::_test_support::retire_stale_request_integrity_headers_in_map(ctx, outbound);
    } else {
        let mut owned = Some(std::mem::take(outbound));
        ferrum_edge::_test_support::retire_stale_request_integrity_headers(ctx, &mut owned);
        *outbound = owned.expect("an owned outbound map stays owned");
    }
}

#[tokio::test]
async fn body_skip_follows_later_header_and_route_content_type_relabels() {
    use ferrum_edge::plugins::request_transformer::BODY_SKIPPED_METADATA_KEY;

    let body = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let relabel_rule = json!({"operation": "update", "target": "header",
        "key": "content-type", "value": "text/plain"});
    let relabel = RequestTransformer::new(&json!({"rules": [relabel_rule.clone()]})).unwrap();
    let raw: Vec<RawRouteHeaderTransformRule> =
        serde_json::from_value(json!([relabel_rule])).unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "test").unwrap());

    for in_map in [false, true] {
        for via_route in [false, true] {
            let mut ctx = post_ctx();
            let mut outbound =
                HashMap::from([("content-type".to_string(), "application/json".to_string())]);
            retain_client_wire_headers(&mut ctx, &outbound);
            body.before_proxy(&mut ctx, &mut outbound).await;
            assert!(!ctx.metadata.contains_key(BODY_SKIPPED_METADATA_KEY));
            if via_route {
                ctx.route_override_request_transform = Some(route_rules.clone());
                finalize_route_override_request_headers(&mut ctx, &mut outbound);
            } else {
                relabel.before_proxy(&mut ctx, &mut outbound).await;
            }
            // No digest and no body-hook call: this request streams after the
            // final header relabel, but must still explain the skipped pass.
            finalize_body_rule_headers_on_surface(&mut ctx, &mut outbound, in_map);
            assert_eq!(
                ctx.metadata
                    .get(BODY_SKIPPED_METADATA_KEY)
                    .map(String::as_str),
                Some("non_json_content_type"),
                "in_map={in_map}, via_route={via_route}"
            );
        }
    }
}

#[tokio::test]
async fn body_skip_is_reconsidered_after_deferred_header_relabels() {
    use ferrum_edge::plugins::request_transformer::BODY_SKIPPED_METADATA_KEY;

    let body = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let relabel = RequestTransformer::new(&json!({"rules": [
        {"operation": "update", "target": "header", "key": "content-type", "value": "application/json"}
    ]}))
    .unwrap();
    for in_map in [false, true] {
        let mut ctx = post_ctx();
        let mut outbound = HashMap::from([("content-type".to_string(), "text/plain".to_string())]);
        body.before_proxy(&mut ctx, &mut outbound).await;
        finalize_body_rule_headers_on_surface(&mut ctx, &mut outbound, in_map);
        assert_eq!(
            ctx.metadata
                .get(BODY_SKIPPED_METADATA_KEY)
                .map(String::as_str),
            Some("non_json_content_type")
        );
        relabel.before_proxy(&mut ctx, &mut outbound).await;
        finalize_body_rule_headers_on_surface(&mut ctx, &mut outbound, in_map);
        assert!(!ctx.metadata.contains_key(BODY_SKIPPED_METADATA_KEY));

        for (bytes, reason) in [
            (b"not json".as_slice(), "parse_error"),
            (b"{}".as_slice(), "no_rule_applied"),
        ] {
            assert!(
                body.transform_request_body_with_context(
                    &mut ctx,
                    bytes,
                    Some("application/json"),
                    &outbound,
                )
                .await
                .is_none()
            );
            finalize_body_rule_headers_on_surface(&mut ctx, &mut outbound, in_map);
            assert_eq!(
                ctx.metadata
                    .get(BODY_SKIPPED_METADATA_KEY)
                    .map(String::as_str),
                Some(reason)
            );
        }
    }
}

#[tokio::test]
async fn body_skip_requires_an_enabled_body_rule_instance() {
    use ferrum_edge::plugins::request_transformer::BODY_SKIPPED_METADATA_KEY;

    for config in [
        json!({"rules": [{"operation": "remove", "target": "header", "key": "x-unused"}]}),
        json!({"rules": [{"operation": "remove", "target": "body", "key": "debug"}],
            "runtime_overlay_scope": "disabled", "default_enabled": false}),
    ] {
        let plugin = RequestTransformer::new(&config).unwrap();
        let mut ctx = post_ctx();
        let outbound =
            run_chain_then_retire(&[&plugin], &mut ctx, integrity_headers(Some("text/plain")))
                .await;
        assert!(outbound.is_none(), "no digest retirement or header copy");
        assert!(!ctx.metadata.contains_key(BODY_SKIPPED_METADATA_KEY));
    }
}

#[tokio::test]
async fn digest_retirement_uses_client_framing_on_each_dispatch_surface() {
    let body = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    for in_map in [false, true] {
        for (client_length, backend_length, retired) in [
            (Some("2"), Some("0"), true),
            (None, Some("0"), true),
            (Some("0"), None, false),
            (Some("0"), Some("2"), false),
        ] {
            let mut ctx = post_ctx();
            let mut outbound = integrity_headers(Some("application/json"));
            if let Some(length) = client_length {
                outbound.insert("content-length".to_string(), length.to_string());
            }
            retain_client_wire_headers(&mut ctx, &outbound);
            body.before_proxy(&mut ctx, &mut outbound).await;
            // Other hooks / finalized-egress overlays can mutate the map;
            // request_transformer itself forbids authoring Content-Length.
            if let Some(length) = backend_length {
                outbound.insert("content-length".to_string(), length.to_string());
            } else {
                outbound.remove("content-length");
            }
            // Even the materialized view can change; only the wire snapshot
            // can prove the original client framing.
            ctx.headers = outbound.clone();
            finalize_body_rule_headers_on_surface(&mut ctx, &mut outbound, in_map);
            for name in ["content-digest", "Repr-Digest", "digest", "content-md5"] {
                assert_eq!(
                    !outbound.contains_key(name),
                    retired,
                    "{name}, in_map={in_map}, client={client_length:?}, backend={backend_length:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn uncertain_client_framing_cannot_exempt_digest_retirement() {
    let body = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    for in_map in [false, true] {
        for uncertain in [
            "missing_snapshot",
            "transfer_encoding",
            "duplicate_length",
            "invalid_length",
        ] {
            let mut ctx = post_ctx();
            let mut outbound = integrity_headers(Some("application/json"));
            outbound.insert("content-length".to_string(), "0".to_string());
            if uncertain != "missing_snapshot" {
                let mut wire = http::HeaderMap::new();
                wire.insert("content-length", http::HeaderValue::from_static("0"));
                match uncertain {
                    "transfer_encoding" => {
                        wire.insert(
                            "transfer-encoding",
                            http::HeaderValue::from_static("chunked"),
                        );
                    }
                    "duplicate_length" => {
                        wire.append("content-length", http::HeaderValue::from_static("0"));
                    }
                    "invalid_length" => {
                        wire.append(
                            "content-length",
                            http::HeaderValue::from_bytes(b"\xff").unwrap(),
                        );
                    }
                    _ => unreachable!(),
                }
                ctx.set_raw_headers(wire);
            }
            body.before_proxy(&mut ctx, &mut outbound).await;
            finalize_body_rule_headers_on_surface(&mut ctx, &mut outbound, in_map);
            assert!(!outbound.contains_key("content-digest"), "{uncertain}");
        }
    }
}

#[tokio::test]
async fn body_rules_retire_stale_request_integrity_headers_over_final_headers() {
    // request_transformer-SOL-2: a digest computed over the client's bytes
    // must not reach the backend beside a body the rules may rewrite.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "body", "key": "gateway_added", "value": true}]
    }))
    .unwrap();
    for content_type in [
        Some("application/json"),
        Some("application/vnd.api+json"),
        None,
    ] {
        let mut ctx = post_ctx();
        let outbound = run_chain_then_retire(&[&plugin], &mut ctx, integrity_headers(content_type))
            .await
            .expect("the retirement materializes an outbound copy");
        for stale in ["content-digest", "Repr-Digest", "digest", "content-md5"] {
            assert!(
                !outbound.contains_key(stale),
                "{stale} must be removed for {content_type:?}"
            );
            // The original inbound view is never mutated.
            assert!(ctx.headers.contains_key(stale));
        }
        assert_eq!(outbound.get("x-keep").map(String::as_str), Some("1"));
    }
}

#[tokio::test]
async fn digest_retirement_follows_a_later_content_type_rewrite() {
    // PR #6858 review SOL-1: a later header-only instance turns a declared
    // `text/plain` upload into JSON the body rules then rewrite. The decision
    // is taken over the FINAL headers, so the digest is still retired.
    let body = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let relabel = RequestTransformer::new(&json!({
        "rules": [{"operation": "update", "target": "header", "key": "content-type", "value": "application/json"}]
    }))
    .unwrap();
    let mut ctx = post_ctx();
    let outbound = run_chain_then_retire(
        &[&body, &relabel],
        &mut ctx,
        integrity_headers(Some("text/plain")),
    )
    .await
    .expect("the relabel produced an outbound copy");
    assert_eq!(
        outbound.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert!(!outbound.contains_key("content-digest"));
    assert!(!outbound.contains_key("content-md5"));

    // Without the relabel the declared non-JSON upload keeps its digest.
    let mut ctx = post_ctx();
    let outbound =
        run_chain_then_retire(&[&body], &mut ctx, integrity_headers(Some("text/plain"))).await;
    assert!(outbound.is_none(), "nothing to retire, nothing copied");
}

#[tokio::test]
async fn integrity_headers_survive_when_body_rules_cannot_rewrite() {
    let body_plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "body", "key": "gateway_added", "value": true}]
    }))
    .unwrap();

    // A body proven empty by `Content-Length: 0` is never rewritten.
    let mut ctx = make_ctx();
    let mut inbound = integrity_headers(None);
    inbound.insert("content-length".to_string(), "0".to_string());
    let outbound = run_chain_then_retire(&[&body_plugin], &mut ctx, inbound).await;
    assert!(outbound.is_none());

    // Framed gRPC JSON can never parse as one document.
    let mut ctx = post_ctx();
    let outbound = run_chain_then_retire(
        &[&body_plugin],
        &mut ctx,
        integrity_headers(Some("application/grpc+json")),
    )
    .await;
    assert!(outbound.is_none());

    // Header-only rules never touch the body.
    let header_plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "x-a", "value": "1"}]
    }))
    .unwrap();
    let mut ctx = post_ctx();
    let outbound = run_chain_then_retire(
        &[&header_plugin],
        &mut ctx,
        integrity_headers(Some("application/json")),
    )
    .await
    .expect("the header rule produced an outbound copy");
    assert!(outbound.contains_key("content-digest"));
}

#[tokio::test]
async fn requests_without_integrity_fields_take_the_no_copy_path() {
    // PR #6858 review SOL-6: a JSON request with no digest allocates no
    // outbound copy and no per-request plugin state for the retirement.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let mut inbound: HashMap<String, String> = HashMap::new();
    inbound.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = post_ctx();
    let outbound = run_chain_then_retire(&[&plugin], &mut ctx, inbound).await;
    assert!(outbound.is_none());
}

#[test]
fn admission_refuses_path_param_assertion_destinations() {
    // request_transformer-claude-1: the router's `x-path-param-*` captures
    // are gateway assertions nothing re-asserts after `before_proxy`.
    for destination in [
        "x-path-param-account",
        "X-Path-Param-Id",
        "X_Path_Param_Account",
        "x_path-param-tenant",
    ] {
        for operation in ["add", "update", "rename"] {
            let rule = if operation == "rename" {
                json!({"target": "header", "operation": operation,
                    "key": "x-legacy-account", "new_key": destination})
            } else {
                json!({"target": "header", "operation": operation,
                    "key": destination, "value": "forged"})
            };
            let error = RequestTransformer::new(&json!({"rules": [rule]}))
                .err()
                .expect("an x-path-param-* destination must fail admission");
            assert!(
                error.contains("`rule[0]`"),
                "{operation} {destination}: {error}"
            );
            assert!(
                error.contains("`x-path-param-*`"),
                "{operation} {destination}: {error}"
            );
        }
        for rule in [
            json!({"target": "header", "operation": "remove", "key": destination}),
            json!({"target": "header", "operation": "rename",
                "key": destination, "new_key": "x-captured"}),
        ] {
            assert!(RequestTransformer::new(&json!({"rules": [rule]})).is_ok());
        }
    }
    for destination in ["x-path-param", "x-path-params-id"] {
        let config = json!({"rules": [
            {"target": "header", "operation": "add", "key": destination, "value": "v"}
        ]});
        assert!(
            RequestTransformer::new(&config).is_ok(),
            "{destination} is outside the route-capture namespace"
        );
    }
}

#[test]
fn admission_refuses_underscore_spellings_of_gateway_owned_destinations() {
    // request_transformer-claude-2: CGI-style backends fold `_` onto `-`, so
    // the underscore spelling lands on the gateway-owned variable.
    for destination in [
        "X_Forwarded_For",
        "x_forwarded_proto",
        "x_forwarded-host",
        "content_length",
        "Transfer_Encoding",
        "proxy_authorization",
        "keep_alive",
        "proxy_connection",
        "x_ferrum_original_content_encoding",
        "x_grpc_web_mode",
    ] {
        for operation in ["add", "update", "rename"] {
            let rule = if operation == "rename" {
                json!({"target": "header", "operation": operation,
                    "key": "x-origin-ip", "new_key": destination})
            } else {
                json!({"target": "header", "operation": operation,
                    "key": destination, "value": "client-chosen"})
            };
            let error = RequestTransformer::new(&json!({"rules": [rule]}))
                .err()
                .expect("a folded gateway-owned destination must fail admission");
            assert!(
                error.contains(&destination.to_ascii_lowercase()),
                "{operation} {destination}: {error}"
            );
            assert!(
                error.contains("gateway-owned"),
                "{operation} {destination}: {error}"
            );
        }
        for rule in [
            json!({"target": "header", "operation": "remove", "key": destination}),
            json!({"target": "header", "operation": "rename",
                "key": destination, "new_key": "x-captured"}),
        ] {
            assert!(RequestTransformer::new(&json!({"rules": [rule]})).is_ok());
        }
    }
}

#[test]
fn body_paths_with_empty_segments_fail_admission() {
    // request_transformer-claude-4.
    for key in ["", "user.", ".user", "a..b", "a.\\\\."] {
        for rule in [
            json!({"operation": "add", "target": "body", "key": key, "value": "x"}),
            json!({"operation": "update", "target": "body", "key": key, "value": "x"}),
            json!({"operation": "remove", "target": "body", "key": key}),
            json!({"operation": "rename", "target": "body", "key": key, "new_key": "moved"}),
            json!({"operation": "rename", "target": "body", "key": "source", "new_key": key}),
        ] {
            let error = RequestTransformer::new(&json!({"rules": [rule]}))
                .err()
                .unwrap_or_else(|| panic!("empty segment in {key:?} must fail admission"));
            assert!(error.contains("empty path segment"), "{key:?}: {error}");
        }
    }
    // Escaped literal dots are single non-empty segments.
    for key in ["meta.weird\\.key", "trailing\\.", "\\.leading"] {
        assert!(
            RequestTransformer::new(&json!({"rules": [
                {"operation": "update", "target": "body", "key": key, "value": "x"}
            ]}))
            .is_ok(),
            "{key:?} has no empty segment"
        );
    }
}

#[tokio::test]
async fn header_and_query_values_resolve_bounded_template_variables() {
    // request_transformer-claude-5.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "x-user-copy", "value": "$(consumer.username)"},
            {"operation": "add", "target": "header", "key": "x-client", "value": "ip=$(client_ip)"},
            {"operation": "update", "target": "header", "key": "x-req", "value": "$(request_id)"},
            {"operation": "update", "target": "header", "key": "x-tenant-copy", "value": "t-$(header.x-tenant)-$(query.region)"},
            {"operation": "add", "target": "header", "key": "x-literal", "value": "cost $$(5) $ ok"},
            {"operation": "add", "target": "query", "key": "tenant", "value": "$(header.x-tenant)"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.identified_consumer = Some(std::sync::Arc::new(
        super::plugin_utils::create_test_consumer(),
    ));
    ctx.metadata
        .insert("request_id".to_string(), "req-123".to_string());
    ctx.set_raw_query_string("region=eu%2Dwest".to_string());
    // Header sources resolve from the ORIGINAL client headers.
    ctx.headers
        .insert("x-tenant".to_string(), "acme".to_string());
    let mut headers = ctx.headers.clone();

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(
        headers.get("x-user-copy").map(String::as_str),
        Some("testuser")
    );
    assert_eq!(
        headers.get("x-client").map(String::as_str),
        Some("ip=127.0.0.1")
    );
    assert_eq!(headers.get("x-req").map(String::as_str), Some("req-123"));
    assert_eq!(
        headers.get("x-tenant-copy").map(String::as_str),
        Some("t-acme-eu-west")
    );
    assert_eq!(
        headers.get("x-literal").map(String::as_str),
        Some("cost $(5) $ ok")
    );
    let outbound = ctx.outbound_query_string().expect("query rule published");
    assert!(outbound.contains("tenant=acme"), "{outbound}");
    assert!(
        !ctx.metadata
            .contains_key(ferrum_edge::plugins::request_transformer::RULE_SKIPPED_METADATA_KEY)
    );
}

#[tokio::test]
async fn unresolvable_or_unsafe_templates_skip_the_rule_and_say_why() {
    use ferrum_edge::plugins::request_transformer::RULE_SKIPPED_METADATA_KEY;

    // Missing variable: no consumer, no partial value.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "update", "target": "header", "key": "x-user", "value": "user=$(consumer.username)"}]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!headers.contains_key("x-user"));
    assert_eq!(
        ctx.metadata
            .get(RULE_SKIPPED_METADATA_KEY)
            .map(String::as_str),
        Some("template_unresolved")
    );

    // A decoded query value carrying CR/LF never becomes a header value.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "update", "target": "header", "key": "x-region", "value": "$(query.region)"}]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("region=eu%0D%0AX-Injected:%201".to_string());
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!headers.contains_key("x-region"));
    assert!(!headers.contains_key("x-injected"));
    assert_eq!(
        ctx.metadata
            .get(RULE_SKIPPED_METADATA_KEY)
            .map(String::as_str),
        Some("template_invalid_header_value")
    );

    // An authentication-owned query credential is never a template source,
    // even under an innocuous name the classifier would not flag.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "update", "target": "header", "key": "x-copied", "value": "$(query.locale)"}]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("locale=s3cr3t".to_string());
    ctx.metadata.insert(
        "auth.strip_query_param.locale".to_string(),
        "true".to_string(),
    );
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!headers.contains_key("x-copied"));
    assert_eq!(
        ctx.metadata
            .get(RULE_SKIPPED_METADATA_KEY)
            .map(String::as_str),
        Some("template_unresolved")
    );
}

#[test]
fn malformed_or_credential_templates_fail_admission() {
    for (value, reason) in [
        ("$(nope)", "unknown template variable"),
        ("$(consumer.username", "unterminated"),
        ("$(header.authorization)", "credential-bearing header"),
        ("$(header.Cookie)", "credential-bearing header"),
        // Any delimiter spelling of a credential header, and any name the
        // shared sensitive-name classifier flags (PR #6858 review SOL-3).
        ("$(header.x_api_key)", "credential-bearing header"),
        ("$(header.X_Auth_Token)", "credential-bearing header"),
        ("$(header.x-session-secret)", "credential-bearing header"),
        ("$(query.api_key)", "credential-bearing query parameter"),
        (
            "$(query.access_token)",
            "credential-bearing query parameter",
        ),
        ("$(query.password)", "credential-bearing query parameter"),
        ("$(header.bad name)", "valid HTTP header"),
        ("$(query.)", "must name a query parameter"),
        (
            "$(client_ip)$(client_ip)$(client_ip)$(client_ip)$(client_ip)$(client_ip)$(client_ip)$(client_ip)$(client_ip)",
            "more than 8 template variables",
        ),
    ] {
        for target in ["header", "query"] {
            let error = RequestTransformer::new(&json!({"rules": [
                {"operation": "update", "target": target, "key": "x-dest", "value": value}
            ]}))
            .err()
            .unwrap_or_else(|| panic!("{target} value {value:?} must fail admission"));
            assert!(error.contains(reason), "{target} {value:?}: {error}");
        }
    }
}

#[tokio::test]
async fn body_non_application_publishes_a_value_free_reason() {
    // request_transformer-claude-6.
    use ferrum_edge::plugins::request_transformer::BODY_SKIPPED_METADATA_KEY;

    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "internal.secret"}]
    }))
    .unwrap();
    let headers: HashMap<String, String> = HashMap::new();

    let mut ctx = post_ctx();
    let out = plugin
        .transform_request_body_with_context(
            &mut ctx,
            b"{not json SENSITIVE",
            Some("application/json"),
            &headers,
        )
        .await;
    assert!(out.is_none());
    assert_eq!(
        ctx.metadata
            .get(BODY_SKIPPED_METADATA_KEY)
            .map(String::as_str),
        Some("parse_error")
    );

    let mut ctx = post_ctx();
    let out = plugin
        .transform_request_body_with_context(
            &mut ctx,
            br#"{"internal":{"other":"SENSITIVE"}}"#,
            Some("application/json"),
            &headers,
        )
        .await;
    assert!(out.is_none());
    assert_eq!(
        ctx.metadata
            .get(BODY_SKIPPED_METADATA_KEY)
            .map(String::as_str),
        Some("no_rule_applied")
    );

    let mut ctx = post_ctx();
    let out = plugin
        .transform_request_body_with_context(
            &mut ctx,
            br#"{"internal":{"secret":"SENSITIVE"}}"#,
            Some("application/json"),
            &headers,
        )
        .await;
    assert!(out.is_some());
    assert!(!ctx.metadata.contains_key(BODY_SKIPPED_METADATA_KEY));

    // A declared non-JSON upload is reported at the final-header boundary,
    // before the streaming path skips the body hook entirely.
    let mut ctx = post_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    finalize_body_rule_headers_on_surface(&mut ctx, &mut headers, false);
    assert_eq!(
        ctx.metadata
            .get(BODY_SKIPPED_METADATA_KEY)
            .map(String::as_str),
        Some("non_json_content_type")
    );
    for value in ctx.metadata.values() {
        assert!(!value.contains("SENSITIVE"));
    }
}

#[tokio::test]
async fn templates_cannot_copy_a_credential_an_earlier_rename_relabelled() {
    // PR #6858 review SOL-3: `rename authorization -> x-context` followed by
    // a template over `x-context` must not publish the credential under an
    // innocuous query name (secondary egress would not recognise it). Header
    // sources resolve from the ORIGINAL client headers, so the renamed name
    // carries nothing.
    let plugin = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "authorization", "new_key": "x-context"},
            {"operation": "add", "target": "query", "key": "trace", "value": "ref=$(header.x-context)"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Bearer SECRET-TOKEN".to_string(),
    );
    let mut headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        headers.get("x-context").map(String::as_str),
        Some("Bearer SECRET-TOKEN"),
        "the rename itself still applies"
    );
    assert!(
        ctx.outbound_query_string()
            .is_none_or(|query| !query.contains("SECRET")),
        "{:?}",
        ctx.outbound_query_string()
    );

    // The same holds across instances for query renames: the second
    // instance reads the original client query, where `k` never existed.
    let rename = RequestTransformer::new(&json!({
        "rules": [{"operation": "rename", "target": "query", "key": "sig", "new_key": "k"}]
    }))
    .unwrap();
    let copy = RequestTransformer::new(&json!({
        "rules": [{"operation": "update", "target": "header", "key": "x-copied", "value": "v=$(query.k)"}]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.set_raw_query_string("sig=SECRET-SIG".to_string());
    let mut headers = ctx.headers.clone();
    rename.before_proxy(&mut ctx, &mut headers).await;
    copy.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        ctx.outbound_query_string()
            .is_some_and(|query| query.contains("k="))
    );
    assert!(!headers.contains_key("x-copied"));
}

#[tokio::test]
async fn digest_retirement_covers_a_lengthless_get_body() {
    // PR #6858 review SOL-7: an HTTP/2 or HTTP/3 GET may carry DATA without
    // `Content-Length`, and the body pass rewrites it all the same, so the
    // method alone never proves the body empty.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let outbound = run_chain_then_retire(
        &[&plugin],
        &mut ctx,
        integrity_headers(Some("application/json")),
    )
    .await
    .expect("the stale digest is retired");
    assert!(!outbound.contains_key("content-digest"));
    assert!(!outbound.contains_key("content-md5"));
}

#[tokio::test]
async fn digest_retirement_covers_a_digest_introduced_by_a_later_rename() {
    // PR #6858 review SOL-8: the body instance saw no integrity field, but a
    // later header-only instance renames one into `Content-Digest`. Core
    // inspects the FINAL headers, so it is still retired.
    let body = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let rename = RequestTransformer::new(&json!({
        "rules": [{"operation": "rename", "target": "header", "key": "x-wire-digest", "new_key": "content-digest"}]
    }))
    .unwrap();
    let mut inbound: HashMap<String, String> = HashMap::new();
    inbound.insert("content-type".to_string(), "application/json".to_string());
    inbound.insert("x-wire-digest".to_string(), "sha-256=:stale:".to_string());
    let mut ctx = post_ctx();
    let outbound = run_chain_then_retire(&[&body, &rename], &mut ctx, inbound)
        .await
        .expect("the rename produced an outbound copy");
    assert!(!outbound.contains_key("x-wire-digest"));
    assert!(
        !outbound.contains_key("content-digest"),
        "a digest introduced after the body instance ran must still be retired"
    );
}

#[test]
fn skip_reasons_survive_default_log_serialization() {
    // PR #6858 review SOL-9: the fixed reason literals are reviewed safe
    // metadata, so default transaction logs show which reason applied.
    use ferrum_edge::plugins::TransactionSummary;
    use ferrum_edge::plugins::request_transformer::{
        BODY_SKIPPED_METADATA_KEY, RULE_SKIPPED_METADATA_KEY,
    };
    use ferrum_edge::plugins::utils::metadata_redaction::metadata_value_is_redacted;

    assert!(!metadata_value_is_redacted(BODY_SKIPPED_METADATA_KEY));
    assert!(!metadata_value_is_redacted(RULE_SKIPPED_METADATA_KEY));
    let summary = TransactionSummary {
        metadata: [
            (
                BODY_SKIPPED_METADATA_KEY.to_string(),
                "parse_error".to_string(),
            ),
            (
                RULE_SKIPPED_METADATA_KEY.to_string(),
                "template_unresolved".to_string(),
            ),
        ]
        .into_iter()
        .collect(),
        ..TransactionSummary::default()
    };
    let rendered = serde_json::to_value(&summary)
        .expect("summary serializes")
        .to_string();
    assert!(rendered.contains("parse_error"), "{rendered}");
    assert!(rendered.contains("template_unresolved"), "{rendered}");
    // Only the two exact keys are reviewed, not the namespace.
    assert!(metadata_value_is_redacted("request_transformer.other"));
}

#[tokio::test]
async fn digest_retirement_folds_underscore_spellings() {
    // Muse round-2 MUSE-3(b): `Content_Digest` folds onto the same CGI
    // variable as `Content-Digest` at Rack/WSGI/PHP backends.
    let plugin = RequestTransformer::new(&json!({
        "rules": [{"operation": "remove", "target": "body", "key": "debug"}]
    }))
    .unwrap();
    let mut inbound: HashMap<String, String> = HashMap::new();
    inbound.insert("content-type".to_string(), "application/json".to_string());
    inbound.insert("content_digest".to_string(), "sha-256=:stale:".to_string());
    inbound.insert("Repr_Digest".to_string(), "sha-256=:stale:".to_string());
    let mut ctx = post_ctx();
    let outbound = run_chain_then_retire(&[&plugin], &mut ctx, inbound)
        .await
        .expect("the stale digests are retired");
    assert!(!outbound.contains_key("content_digest"));
    assert!(!outbound.contains_key("Repr_Digest"));
}
