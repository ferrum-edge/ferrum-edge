//! Tests for response_transformer plugin

use ferrum_edge::plugins::{Plugin, RequestContext, response_transformer::ResponseTransformer};
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
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "test"}
        ]
    }))
    .unwrap();
    assert_eq!(plugin.name(), "response_transformer");
}

#[tokio::test]
async fn test_response_transformer_priority_protocols_and_reject_hook() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "test"}
        ]
    }))
    .unwrap();

    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::RESPONSE_TRANSFORMER
    );
    assert!(plugin.applies_after_proxy_on_reject());
    assert!(
        plugin
            .supported_protocols()
            .contains(&ferrum_edge::plugins::ProxyProtocol::Http)
    );
    assert!(
        plugin
            .supported_protocols()
            .contains(&ferrum_edge::plugins::ProxyProtocol::Grpc)
    );
}

#[tokio::test]
async fn test_response_transformer_add_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Response-Id", "value": "abc-123"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-response-id").unwrap(), "abc-123");
}

#[tokio::test]
async fn test_response_transformer_remove_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-Internal"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-internal".to_string(), "sensitive-data".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-internal"));
    assert!(headers.contains_key("content-type"));
}

#[tokio::test]
async fn test_response_transformer_update_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "Server", "value": "Ferrum Edge"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("server".to_string(), "nginx".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("server").unwrap(), "Ferrum Edge");
}

#[tokio::test]
async fn test_response_transformer_multiple_rules() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Gateway", "value": "ferrum"},
            {"operation": "remove", "target": "header", "key": "X-Powered-By"},
            {"operation": "update", "target": "header", "key": "Server", "value": "Ferrum"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-powered-by".to_string(), "Express".to_string());
    headers.insert("server".to_string(), "nginx".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-gateway").unwrap(), "ferrum");
    assert!(!headers.contains_key("x-powered-by"));
    assert_eq!(headers.get("server").unwrap(), "Ferrum");
}

#[tokio::test]
async fn test_response_transformer_empty_rules() {
    let result = ResponseTransformer::new(&json!({"rules": []}));
    let err = result.err().expect("expected error for empty rules");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_no_config() {
    let result = ResponseTransformer::new(&json!({}));
    let err = result.err().expect("expected error for no config");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_object_config() {
    let err = ResponseTransformer::new(&json!("bad"))
        .err()
        .expect("expected error for non-object config");
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_array_rules() {
    let err = ResponseTransformer::new(&json!({
        "rules": "not-an-array"
    }))
    .err()
    .expect("expected error for non-array rules");
    assert!(err.contains("'rules' must be an array"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_object_rule() {
    let err = ResponseTransformer::new(&json!({
        "rules": ["bad"]
    }))
    .err()
    .expect("expected error for non-object rule");
    assert!(err.contains("rule must be an object"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_add_without_value_rejected() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-NoValue"}
        ]
    }))
    .err()
    .expect("expected error for add without value");
    assert!(err.contains("requires a 'value'"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_unknown_operation_rejected() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "prepend", "target": "header", "key": "X-Test", "value": "val"}
        ]
    }))
    .err()
    .expect("expected error for unknown operation");
    assert!(err.contains("unknown operation"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_handles_various_status_codes() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Processed", "value": "true"}
        ]
    }))
    .unwrap();

    for status in [200, 201, 301, 400, 404, 500, 503] {
        let mut ctx = make_ctx();
        let mut headers: HashMap<String, String> = HashMap::new();

        let result = plugin.after_proxy(&mut ctx, status, &mut headers).await;
        assert!(matches!(
            result,
            ferrum_edge::plugins::PluginResult::Continue
        ));
        assert_eq!(headers.get("x-processed").unwrap(), "true");
    }
}

#[tokio::test]
async fn test_response_transformer_rename_header() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "x-old", "new_key": "x-new"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-old".to_string(), "the-value".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-old"));
    assert_eq!(headers.get("x-new").unwrap(), "the-value");
}

#[tokio::test]
async fn test_response_transformer_rename_header_nonexistent() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "x-missing", "new_key": "x-new"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert!(!headers.contains_key("x-new"));
    assert!(!headers.contains_key("x-missing"));
}

#[tokio::test]
async fn test_response_transformer_rename_without_new_key_rejected() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "x-old"}
        ]
    }))
    .err()
    .expect("expected error for rename without new_key");
    assert!(err.contains("requires a 'new_key'"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_header_key_pre_lowercased() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-UPPER", "value": "lowered"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
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
    }))
    .unwrap();

    assert!(plugin.requires_response_body_buffering());

    let body = br#"{"old_name":"Alice","age":30}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    })).unwrap();

    let body = br#"{"data":{"old_field":"value","other":"keep"}}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"data":"public","internal":{"debug_info":"secret","id":"keep"}}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"data":"response"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"status":"pending","data":"result"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"resp_data":"payload","internal_trace_id":"abc123"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
            {"operation": "add", "target": "header", "key": "X-Processed", "value": "true"},
            {"operation": "rename", "target": "body", "key": "old_field", "new_key": "new_field"}
        ]
    }))
    .unwrap();

    assert!(plugin.requires_response_body_buffering());

    // Test header rules via after_proxy
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(headers.get("x-processed").unwrap(), "true");

    // Test body rules via transform_response_body
    let body = br#"{"old_field":"data"}"#;
    let body_result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = b"<xml>not json</xml>";
    let result = plugin
        .transform_response_body(body, Some("text/html"), &HashMap::new())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_response_transformer_no_body_rules_no_buffering() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Header", "value": "yes"}
        ]
    }))
    .unwrap();

    // No body rules → no buffering required
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_response_transformer_body_deeply_nested() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "a.b.c.old", "new_key": "a.b.c.new"}
        ]
    }))
    .unwrap();

    let body = br#"{"a":{"b":{"c":{"old":"deep_value","keep":"yes"}}}}"#;
    let result = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
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
    }))
    .unwrap();

    let body = br#"{"data":"value"}"#;
    let result = plugin
        .transform_response_body(body, Some("application/vnd.api+json"), &HashMap::new())
        .await;
    let transformed: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(transformed["processed"], true);
}

// ── New behaviour: config validation & new body features ──────────────────

#[tokio::test]
async fn test_response_transformer_unknown_target_rejected() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "cookie", "key": "X-A", "value": "1"}
        ]
    }))
    .err()
    .expect("expected error for unknown target");
    assert!(err.contains("unknown target"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_crlf_in_header_value() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Bad", "value": "x\nSet-Cookie: evil=1"}
        ]
    }))
    .err()
    .expect("expected error for CRLF in header value");
    assert!(err.contains("CR or LF"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_body_array_index() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "items.1.name", "value": "updated"}
        ]
    }))
    .unwrap();
    let body = br#"{"items":[{"name":"a"},{"name":"b"}]}"#;
    let out = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["items"][0]["name"], "a");
    assert_eq!(parsed["items"][1]["name"], "updated");
}

#[tokio::test]
async fn test_response_transformer_body_remove_array_element() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "items.0"}
        ]
    }))
    .unwrap();
    let body = br#"{"items":[{"id":1},{"id":2}]}"#;
    let out = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["items"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["items"][0]["id"], 2);
}

// ── Strict type validation for config fields ──────────────────────────────

#[tokio::test]
async fn test_response_transformer_rejects_non_string_target() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": 0, "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_null_target() {
    // Explicit `"target": null` must fail config load; silently coercing null
    // would mask misconfiguration.
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": null, "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for null target");
    assert!(err.contains("'target' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_missing_target() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for missing target");
    assert!(err.contains("'target' is required"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_query_target() {
    // Unlike request_transformer, response_transformer has no `query` target.
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "query", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for query target");
    assert!(err.contains("unknown target"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_string_operation() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": 42, "target": "header", "key": "X", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string operation");
    assert!(err.contains("'operation' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_string_key() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": 123, "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for non-string key");
    assert!(err.contains("'key' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_invalid_header_key() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "bad header", "value": "v"}
        ]
    }))
    .err()
    .expect("expected error for invalid header key");
    assert!(err.contains("valid HTTP header name"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_string_value() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Count", "value": 42}
        ]
    }))
    .err()
    .expect("expected error for non-string header value");
    assert!(err.contains("'value' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_non_string_new_key() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old", "new_key": 7}
        ]
    }))
    .err()
    .expect("expected error for non-string new_key");
    assert!(err.contains("'new_key' must be a string"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_invalid_header_new_key() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "header", "key": "X-Old", "new_key": "bad header"}
        ]
    }))
    .err()
    .expect("expected error for invalid header new_key");
    assert!(err.contains("valid HTTP header name"), "got: {err}");
}

// ── JSON null value preservation on body rules ───────────────────────────

#[tokio::test]
async fn test_response_transformer_body_update_null_value() {
    // Setting a response field to JSON null is a legitimate operation.
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "error", "value": null}
        ]
    }))
    .unwrap();

    let body = br#"{"error":"timeout"}"#;
    let out = plugin
        .transform_response_body(body, Some("application/json"), &HashMap::new())
        .await
        .expect("body should be modified");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed["error"].is_null());
}

// ── SSE bypass ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_response_transformer_sse_request_skips_buffering() {
    // Body transforms operate on the assembled response. SSE responses must
    // bypass body buffering — otherwise the buffer collects events forever
    // and the gateway 502s once max-response-body is hit.
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old", "new_key": "new"}
        ]
    }))
    .unwrap();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_response_transformer_non_sse_request_still_buffers() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old", "new_key": "new"}
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_response_transformer_header_only_rules_never_buffer() {
    // Header-only rules (no body_rules) must not buffer regardless of SSE.
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Test", "value": "yes"}
        ]
    }))
    .unwrap();
    assert!(!plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    assert!(!plugin.should_buffer_response_body(&ctx));

    let mut ctx_json = make_ctx();
    ctx_json
        .headers
        .insert("accept".to_string(), "application/json".to_string());
    assert!(!plugin.should_buffer_response_body(&ctx_json));
}

#[test]
fn test_response_transformer_no_transform_preflight_reports_conservative_capability() {
    let ctx = make_ctx();
    let headers = HashMap::from([("cache-control".to_string(), "max-age=60".to_string())]);
    let add_only = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": "Cache-Control",
            "value": "no-transform"
        }]
    }))
    .unwrap();
    assert!(add_only.may_add_response_cache_control_no_transform(&ctx, &headers));

    let remove_then_add = ResponseTransformer::new(&json!({
        "rules": [
            {
                "operation": "remove",
                "target": "header",
                "key": "Cache-Control"
            },
            {
                "operation": "add",
                "target": "header",
                "key": "Cache-Control",
                "value": "no-transform"
            }
        ]
    }))
    .unwrap();
    assert!(remove_then_add.may_add_response_cache_control_no_transform(&ctx, &headers));
}

#[test]
fn test_response_transformer_strong_etag_preflight_reports_conservative_capability() {
    let ctx = make_ctx();
    let headers = HashMap::from([("etag".to_string(), "W/\"weak\"".to_string())]);
    let add_strong = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": "ETag",
            "value": "\"strong\""
        }]
    }))
    .unwrap();
    assert!(add_strong.may_add_response_strong_etag(&ctx, &headers));

    let add_weak = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": "ETag",
            "value": "W/\"weak\""
        }]
    }))
    .unwrap();
    assert!(!add_weak.may_add_response_strong_etag(&ctx, &headers));

    let add_malformed_weak = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": "ETag",
            "value": "w/\"weak\""
        }]
    }))
    .unwrap();
    assert!(add_malformed_weak.may_add_response_strong_etag(&ctx, &headers));

    let add_spaced_weak = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": "ETag",
            "value": "W/ \"weak\""
        }]
    }))
    .unwrap();
    assert!(add_spaced_weak.may_add_response_strong_etag(&ctx, &headers));

    let rename_to_etag = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "rename",
            "target": "header",
            "key": "X-Origin-Etag",
            "new_key": "ETag"
        }]
    }))
    .unwrap();
    assert!(rename_to_etag.may_add_response_strong_etag(&ctx, &headers));
}

// ── Route-level transform overrides (`apply_route_overrides`) ──────────────

use ferrum_edge::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, parse_route_header_transforms,
};
use std::sync::Arc;

#[tokio::test]
async fn test_response_transformer_apply_route_overrides_accepts_empty_rules() {
    ResponseTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .expect("apply_route_overrides=true allows zero static rules");
}

#[tokio::test]
async fn test_response_transformer_empty_rules_without_opt_in_still_errors() {
    let err = ResponseTransformer::new(&json!({
        "rules": [],
    }))
    .err()
    .expect("zero rules without apply_route_overrides must error");
    assert!(err.contains("no 'rules' configured"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_route_override_applies_after_static_rules() {
    // Static rule sets X-Backend=static; route-level override sets
    // X-Backend=route. Per documented precedence (static first, then
    // per-rule), the route override must win.
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "X-Backend", "value": "static"}
        ]
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Backend", "value": "route"}
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_response_transform = Some(route_rules);
    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert_eq!(
        response_headers.get("x-backend").map(String::as_str),
        Some("route")
    );
    // Plugin must consume the Arc so a subsequent response_transformer
    // instance in the chain does not re-apply the same list.
    assert!(ctx.route_override_response_transform.is_none());
}

#[tokio::test]
async fn test_response_transformer_apply_route_overrides_no_static_rules_applies_overrides() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": true,
    }))
    .unwrap();

    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(json!([
        {"operation": "update", "target": "header", "key": "X-Cache", "value": "miss"},
        {"operation": "remove", "target": "header", "key": "X-Origin"},
    ]))
    .unwrap();
    let route_rules = Arc::new(parse_route_header_transforms(&raw, "route_override").unwrap());

    let mut ctx = make_ctx();
    ctx.route_override_response_transform = Some(route_rules);
    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("x-origin".to_string(), "alpha".to_string());

    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("x-cache").map(String::as_str),
        Some("miss")
    );
    assert!(!response_headers.contains_key("x-origin"));
}

#[tokio::test]
async fn test_response_transformer_apply_route_overrides_invalid_type_rejected() {
    let err = ResponseTransformer::new(&json!({
        "rules": [],
        "apply_route_overrides": "yes",
    }))
    .err()
    .expect("non-boolean apply_route_overrides must error");
    assert!(err.contains("must be a boolean"), "got: {err}");
}

// === GAP-3E: RTDS overlay gate ===

#[tokio::test]
async fn test_response_transformer_runtime_overlay_scope_accepted() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "internal",
        "default_enabled": true
    }))
    .unwrap();
    assert_eq!(plugin.name(), "response_transformer");
}

#[tokio::test]
async fn test_response_transformer_rejects_empty_runtime_overlay_scope() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Always", "value": "yes"}
        ],
        "runtime_overlay_scope": "   "
    }))
    .err()
    .unwrap();
    assert!(err.contains("runtime_overlay_scope"));
}

#[test]
fn test_response_transformer_overlay_gate_parsing_is_namespaced() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;

    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.response_transformer.public.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    fields.insert(
        "ferrum.response_transformer.internal.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    fields.insert(
        "ferrum.request_transformer.public.enabled".to_string(),
        RuntimeValue::Bool(false),
    );

    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let snap = runtime_overlay::current_gates();
    assert_eq!(snap.gate("public"), Some(true));
    assert_eq!(snap.gate("internal"), Some(false));
    assert_eq!(snap.gate("missing"), None);

    runtime_overlay::reset_for_test();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_response_transformer_overlay_gate_observable_end_to_end() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();

    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}
        ],
        "runtime_overlay_scope": "gated",
        "default_enabled": true
    }))
    .unwrap();

    // ── Case 1: overlay missing → fallback default_enabled=true applies.
    runtime_overlay::reset_for_test();
    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));

    // ── Case 2: overlay says enabled=false → rule short-circuited.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.response_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.after_proxy(&mut make_ctx(), 200, &mut headers).await;
    assert!(
        !headers.contains_key("x-gated"),
        "overlay=false must suppress the rule"
    );

    // ── Case 3: request_transformer overlay must NOT cross into
    //           response_transformer state.
    runtime_overlay::reset_for_test();
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.request_transformer.gated.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    ferrum_edge::plugins::request_transformer::runtime_overlay::apply_overlay(
        &MeshRuntimeOverlay { fields },
    );
    let mut headers: HashMap<String, String> = HashMap::new();
    plugin.after_proxy(&mut make_ctx(), 200, &mut headers).await;
    assert_eq!(
        headers.get("x-gated").map(String::as_str),
        Some("yes"),
        "request_transformer overlay must not gate response_transformer"
    );

    runtime_overlay::reset_for_test();
    ferrum_edge::plugins::request_transformer::runtime_overlay::reset_for_test();
}

// Regression for finding #64: when the RTDS overlay disables the scope, the
// transform is a no-op, so `should_buffer_response_body` must NOT pin the
// response into the buffered path (otherwise a disabled transform still buffers
// a large non-SSE response until the max-response-body limit and 502s). The
// cache-level `requires_response_body_buffering` upper bound stays true since
// it cannot consult request-time overlay state.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_response_transformer_disabled_overlay_skips_response_buffering() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();

    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old", "new_key": "new"}
        ],
        "runtime_overlay_scope": "gated-buffer",
        "default_enabled": true
    }))
    .unwrap();

    // Cache-level upper bound is unconditional on rule shape.
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    // ── Overlay missing → default_enabled=true → still buffers.
    runtime_overlay::reset_for_test();
    assert!(
        plugin.should_buffer_response_body(&ctx),
        "enabled transform with body rules should buffer a non-SSE response"
    );

    // ── Overlay disables the scope → transform is a no-op → must NOT buffer.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.response_transformer.gated-buffer.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "disabled overlay must not pin the response into the buffered path"
    );

    runtime_overlay::reset_for_test();
}

// Companion to #64 using the static fallback (no overlay state needed): a body
// transform whose scope falls back to default_enabled=false must not buffer.
#[tokio::test]
async fn test_response_transformer_default_disabled_skips_response_buffering() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old", "new_key": "new"}
        ],
        "runtime_overlay_scope": "absent-scope",
        "default_enabled": false
    }))
    .unwrap();

    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "default_enabled=false scope must not buffer the response"
    );
}
