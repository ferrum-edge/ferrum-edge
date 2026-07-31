//! Tests for response_transformer plugin

use ferrum_edge::_test_support::{
    apply_synthetic_response_body_hooks_for_test,
    discard_grpc_application_trailers_after_body_rewrite_for_test,
    set_replay_request_body_empty_proven_for_test,
    set_response_presentation_policy_digest_for_test, stamp_original_response_metadata_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::response_caching::ResponseCaching;
use ferrum_edge::plugins::response_transformer::ResponseTransformer;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::create_test_proxy;

/// Origin validators / integrity fields that become stale after a body rewrite.
const STALE_REPRESENTATION_HEADERS: &[&str] = &[
    "etag",
    "last-modified",
    "content-digest",
    "repr-digest",
    "digest",
    "content-md5",
];

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn body_update_plugin() -> ResponseTransformer {
    ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "update", "target": "body", "key": "state", "value": "public"}
        ]
    }))
    .unwrap()
}

fn insert_stale_representation_headers(headers: &mut HashMap<String, String>) {
    // Mixed-case names prove case-insensitive cleanup rather than exact-key deletes.
    headers.insert("ETag".to_string(), "\"origin-v1\"".to_string());
    headers.insert(
        "Last-Modified".to_string(),
        "Wed, 01 Jan 2025 00:00:00 GMT".to_string(),
    );
    headers.insert(
        "Content-Digest".to_string(),
        "sha-256=:stale-content:".to_string(),
    );
    headers.insert(
        "Repr-Digest".to_string(),
        "sha-256=:stale-repr:".to_string(),
    );
    headers.insert("Digest".to_string(), "sha-256=stale-legacy".to_string());
    headers.insert("Content-MD5".to_string(), "stale-md5".to_string());
}

fn assert_stale_representation_headers_absent(headers: &HashMap<String, String>) {
    for name in STALE_REPRESENTATION_HEADERS {
        assert!(
            headers.keys().all(|key| !key.eq_ignore_ascii_case(name)),
            "stale representation field {name} must be removed after a body rewrite"
        );
    }
}

fn assert_stale_representation_headers_present(headers: &HashMap<String, String>) {
    for name in STALE_REPRESENTATION_HEADERS {
        assert!(
            headers.keys().any(|key| key.eq_ignore_ascii_case(name)),
            "representation field {name} must be preserved when the body is unchanged"
        );
    }
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
    assert!(err.contains("valid HTTP HeaderValue"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_unknown_top_level_key() {
    let err = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "header", "key": "X-Color", "value": "blue"}
        ],
        "runtime_overlay_scpoe": "internal"
    }))
    .err()
    .expect("expected error for unknown top-level key");
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("runtime_overlay_scpoe"), "got: {err}");
    assert!(err.contains("under 'config'"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_unknown_header_rule_key() {
    let err = ResponseTransformer::new(&json!({
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
async fn test_response_transformer_rejects_unknown_body_rule_key() {
    let err = ResponseTransformer::new(&json!({
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
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("extra_field"), "got: {err}");
    assert!(err.contains("config.rules[0]"), "got: {err}");
}

#[tokio::test]
async fn test_response_transformer_rejects_incompatible_header_fields() {
    for (rule, needle) in [
        (
            json!({
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": "X-Ignored"
            }),
            "'new_key' must not be set for header 'add'",
        ),
        (
            json!({
                "operation": "update",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": "X-Ignored"
            }),
            "'new_key' must not be set for header 'update'",
        ),
        (
            json!({
                "operation": "add",
                "target": "header",
                "key": "X-Color",
                "value": "blue",
                "new_key": null
            }),
            "'new_key' must not be set for header 'add'",
        ),
        (
            json!({
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": "ignored"
            }),
            "'value' must not be set for header 'rename'",
        ),
        (
            json!({
                "operation": "rename",
                "target": "header",
                "key": "X-Old",
                "new_key": "X-New",
                "value": null
            }),
            "'value' must not be set for header 'rename'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "value": "ignored"
            }),
            "'value' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "new_key": "X-Ignored"
            }),
            "'new_key' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "value": null
            }),
            "'value' must not be set for header 'remove'",
        ),
        (
            json!({
                "operation": "remove",
                "target": "header",
                "key": "X-Color",
                "new_key": null
            }),
            "'new_key' must not be set for header 'remove'",
        ),
    ] {
        let err = ResponseTransformer::new(&json!({ "rules": [rule] }))
            .err()
            .expect("expected incompatible header field rejection");
        assert!(
            err.contains(needle),
            "expected needle {needle:?}, got: {err}"
        );
    }
}

#[tokio::test]
async fn test_response_transformer_accepts_valid_header_value_edge_cases() {
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
        let plugin = ResponseTransformer::new(&json!({
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
async fn test_response_transformer_rejects_forbidden_header_control_bytes() {
    for (label, value) in [
        ("NUL", "ok\u{0000}bad"),
        ("SOH", "ok\u{0001}bad"),
        ("BEL", "ok\u{0007}bad"),
        ("DEL", "ok\u{007f}bad"),
        ("CR", "ok\rbad"),
        ("LF", "ok\nbad"),
    ] {
        let err = ResponseTransformer::new(&json!({
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

#[tokio::test]
async fn test_response_transformer_rejects_protocol_managed_add_update_and_rename_destinations() {
    for (operation, name) in [
        ("add", "Connection"),
        ("update", "CONTENT-LENGTH"),
        ("add", "Transfer-Encoding"),
        ("update", "trailer"),
        ("add", "Upgrade"),
        ("update", "Keep-Alive"),
        ("add", "proxy-connection"),
        ("update", "TE"),
        ("add", "Proxy-Authenticate"),
    ] {
        let err = ResponseTransformer::new(&json!({
            "rules": [{
                "operation": operation,
                "target": "header",
                "key": name,
                "value": "1",
            }]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected rejection for {operation} {name}"));
        assert!(
            err.contains("protocol-managed"),
            "{operation} {name}: {err}"
        );
    }

    let rename_err = ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "rename",
            "target": "header",
            "key": "x-framing",
            "new_key": "Transfer-Encoding"
        }]
    }))
    .err()
    .expect("rename to Transfer-Encoding must be rejected");
    assert!(rename_err.contains("protocol-managed"), "got: {rename_err}");

    // remove of protocol-managed names remains allowed (harmless after origin strip).
    ResponseTransformer::new(&json!({
        "rules": [{
            "operation": "remove",
            "target": "header",
            "key": "Connection"
        }]
    }))
    .expect("remove Connection must remain allowed");
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
async fn test_response_transformer_sse_accept_stays_buffered_until_response_headers() {
    // Client intent cannot prove what representation the backend will return.
    // The pre-header decision therefore remains buffered even for an SSE Accept
    // value, preventing ordinary JSON from streaming past the body policy.
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

    assert!(plugin.should_buffer_response_body(&ctx));

    let json_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &json_headers,
    ));
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &json_headers,));
}

#[tokio::test]
async fn test_response_transformer_backend_event_stream_releases_buffering() {
    // Once backend headers prove that the selected representation is SSE, body
    // transformation is out of scope and the unbounded stream must be released.
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "rename", "target": "body", "key": "old", "new_key": "new"}
        ]
    }))
    .unwrap();
    let ctx = make_ctx();
    let response_headers = HashMap::from([(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    )]);

    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream; charset=utf-8"),
        200,
        &response_headers,
    ));
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &response_headers,));
}

#[tokio::test]
async fn test_response_transformer_ambiguous_event_stream_types_stay_buffered() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "secret"}
        ]
    }))
    .unwrap();
    let ctx = make_ctx();

    for content_type in [
        "application/json; profile=event-stream",
        "application/vnd.acme-event-stream",
        "text/event-stream-like",
        "application/event-stream+json",
    ] {
        let response_headers =
            HashMap::from([("content-type".to_string(), content_type.to_string())]);
        assert!(
            plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some(content_type),
                200,
                &response_headers,
            ),
            "ambiguous media type must stay buffered: {content_type}"
        );
        assert!(plugin.may_release_response_body_under_retries(&ctx));
        assert!(
            !plugin.should_release_response_body_under_retries(&ctx, 200, &response_headers,),
            "ambiguous media type must not release under retries: {content_type}"
        );
    }
}

#[tokio::test]
async fn test_response_transformer_missing_response_type_stays_fail_closed() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "body", "key": "secret"}
        ]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &HashMap::new(),));
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

#[tokio::test]
async fn test_response_transformer_preserves_grpc_web_terminal_policy_buffering() {
    use ferrum_edge::plugins::grpc_web::{GrpcWebPlugin, request_is_grpc_web_translated};

    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-Internal-Trailer"}
        ]
    }))
    .unwrap();
    let grpc_web = GrpcWebPlugin::new(&json!({})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/pkg.Service/Watch".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );

    assert!(matches!(
        grpc_web.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    let mut outgoing = ctx.headers.clone();
    assert!(matches!(
        grpc_web.before_proxy(&mut ctx, &mut outgoing).await,
        PluginResult::Continue
    ));
    assert!(request_is_grpc_web_translated(&ctx));
    assert!(
        plugin.requires_buffered_grpc_web_trailer_policy(&ctx),
        "header policy must keep translated terminal metadata on the compatible buffered path"
    );
    assert!(
        !plugin.requires_response_body_buffering(),
        "ordinary HTTP and native gRPC must remain streaming for header-only rules"
    );
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

/// The gate is resolved from CONFIGURATION, not from live process-global state
/// (GHSA-83rc-23c9-3g9x). Cross-generation and mid-request barriers live in
/// `tests/integration/transformer_runtime_overlay_generation_tests.rs`.
#[tokio::test]
async fn test_response_transformer_overlay_gate_resolves_from_effective_config() {
    let apply = |config: serde_json::Value| async move {
        let plugin = ResponseTransformer::new(&config).unwrap();
        let mut headers: HashMap<String, String> = HashMap::new();
        plugin.after_proxy(&mut make_ctx(), 200, &mut headers).await;
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

    // ── Case 2: the generation resolved the gate to false → rule suppressed.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "default_enabled": true,
        "runtime_overlay_resolved_enabled": false
    }))
    .await;
    assert!(
        !headers.contains_key("x-gated"),
        "a resolved gate of false must suppress the rule"
    );

    // ── Case 3: a resolved true overrides a pessimistic default.
    let headers = apply(json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "default_enabled": false,
        "runtime_overlay_resolved_enabled": true
    }))
    .await;
    assert_eq!(headers.get("x-gated").map(String::as_str), Some("yes"));
}

/// A mutation of the process-global response gate store must NOT change what an
/// already-constructed instance does, in either direction. Direct regression
/// guard for the request-time lookup the advisory describes.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_response_transformer_ignores_live_process_global_gate_mutations() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime_overlay::reset_for_test();

    let enabled = ResponseTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": true
    }))
    .unwrap();
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay {
        fields: HashMap::from([(
            "ferrum.response_transformer.gated.enabled".to_string(),
            RuntimeValue::Bool(false),
        )]),
    });
    let mut headers: HashMap<String, String> = HashMap::new();
    enabled
        .after_proxy(&mut make_ctx(), 200, &mut headers)
        .await;
    assert_eq!(
        headers.get("x-gated").map(String::as_str),
        Some("yes"),
        "a live store mutation must not reach an already-published instance"
    );

    let disabled = ResponseTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": false
    }))
    .unwrap();
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay {
        fields: HashMap::from([(
            "ferrum.response_transformer.gated.enabled".to_string(),
            RuntimeValue::Bool(true),
        )]),
    });
    let mut headers: HashMap<String, String> = HashMap::new();
    disabled
        .after_proxy(&mut make_ctx(), 200, &mut headers)
        .await;
    assert!(
        !headers.contains_key("x-gated"),
        "a live store mutation must not enable an instance published as disabled"
    );

    runtime_overlay::reset_for_test();
}

#[tokio::test]
async fn test_response_transformer_rejects_non_boolean_resolved_gate() {
    let err = ResponseTransformer::new(&json!({
        "rules": [{"operation": "add", "target": "header", "key": "X-Gated", "value": "yes"}],
        "runtime_overlay_scope": "gated",
        "runtime_overlay_resolved_enabled": 1
    }))
    .err()
    .expect("a non-boolean resolved gate must be rejected");
    assert!(
        err.contains("runtime_overlay_resolved_enabled"),
        "got: {err}"
    );
}

/// The two namespaces stay independent: a `request_transformer` gate key must
/// never bind a `response_transformer` instance. Asserted on the cold-path
/// binding, which is now where the separation is enforced.
#[test]
fn test_request_transformer_gate_key_does_not_bind_response_transformer() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::response_transformer::runtime_overlay;

    let cross_namespace = MeshRuntimeOverlay {
        fields: HashMap::from([(
            "ferrum.request_transformer.gated.enabled".to_string(),
            RuntimeValue::Bool(false),
        )]),
    };
    assert!(
        !runtime_overlay::scope_gates(&cross_namespace).contains_key("gated"),
        "a request_transformer key must not appear in the response gate namespace"
    );
}

// Regression for finding #64: when the RTDS overlay disables the scope, the
// transform is a no-op, so `should_buffer_response_body` must NOT pin the
// response into the buffered path (otherwise a disabled transform still buffers
// a large non-SSE response until the max-response-body limit and 502s). The gate
// is immutable for this plugin generation, so the cache-level capability must
// agree too.
#[tokio::test]
async fn test_response_transformer_disabled_overlay_skips_response_buffering() {
    let body_rule_plugin = |resolved: Option<bool>| {
        let mut config = json!({
            "rules": [
                {"operation": "rename", "target": "body", "key": "old", "new_key": "new"}
            ],
            "runtime_overlay_scope": "gated-buffer",
            "default_enabled": true
        });
        if let Some(resolved) = resolved {
            config.as_object_mut().expect("object").insert(
                "runtime_overlay_resolved_enabled".to_string(),
                json!(resolved),
            );
        }
        ResponseTransformer::new(&config).unwrap()
    };

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    // ── Generation named no gate → default_enabled=true → still buffers.
    let enabled = body_rule_plugin(None);
    assert!(enabled.requires_response_body_buffering());
    assert!(
        enabled.should_buffer_response_body(&ctx),
        "enabled transform with body rules should buffer a non-SSE response"
    );

    // ── Generation resolved the gate to false → transform is a no-op → must NOT
    //    buffer, and must not transform either. The two answers come from the
    //    same immutable field, so they cannot disagree (GHSA-83rc-23c9-3g9x).
    let disabled = body_rule_plugin(Some(false));
    assert!(
        !disabled.requires_response_body_buffering(),
        "a disabled generation must not advertise a cache-level buffering capability"
    );
    assert!(
        !disabled.should_buffer_response_body(&ctx),
        "a disabled gate must not pin the response into the buffered path"
    );
    assert!(
        disabled
            .transform_response_body(br#"{"old":"v"}"#, Some("application/json"), &HashMap::new())
            .await
            .is_none(),
        "the phase that would have consumed the buffer must agree it is disabled"
    );
    assert!(
        matches!(
            disabled.response_trailer_policy(),
            ferrum_edge::plugins::ResponseTrailerPolicy::None
        ),
        "a disabled generation must not drop backend trailers"
    );
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

    assert!(
        !plugin.requires_response_body_buffering(),
        "a default-disabled generation must not advertise buffering"
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "default_enabled=false scope must not buffer the response"
    );
}

// ────────────────────── Representation validators after body rewrite (#2382) ──────────────────────

/// Direct hook coverage: an actual rewrite must strip mixed-case validators
/// while preserving unrelated headers such as Cache-Control.
#[tokio::test]
async fn body_rewrite_hook_strips_stale_representation_validators() {
    let plugin = body_update_plugin();
    let original = br#"{"state":"origin"}"#;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("cache-control".to_string(), "private".to_string()),
        ("content-length".to_string(), original.len().to_string()),
    ]);
    insert_stale_representation_headers(&mut headers);

    let rewritten = plugin
        .transform_response_body(original, Some("application/json"), &headers)
        .await
        .expect("body update must rewrite bytes");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rewritten).unwrap()["state"],
        "public"
    );

    let mut rewritten_headers = headers.clone();
    let mut ctx = make_ctx();
    plugin.on_response_body_transformed(&mut ctx, &mut rewritten_headers);
    assert_stale_representation_headers_absent(&rewritten_headers);
    assert_eq!(
        rewritten_headers.get("cache-control").map(String::as_str),
        Some("private")
    );
}

/// Semantic no-ops (add of an already-present field) return `None` and leave
/// origin validators untouched; the hook is only invoked after `Some`.
#[tokio::test]
async fn semantic_noop_preserves_representation_validators() {
    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "add", "target": "body", "key": "state", "value": "public"}
        ]
    }))
    .unwrap();
    let body = br#"{"state":"origin"}"#;
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), body.len().to_string()),
    ]);
    insert_stale_representation_headers(&mut headers);
    let before = headers.clone();

    assert!(
        plugin
            .transform_response_body(body, Some("application/json"), &headers)
            .await
            .is_none(),
        "add of an existing field is a semantic no-op"
    );
    assert_eq!(headers, before);
    assert_stale_representation_headers_present(&headers);

    // Lifecycle path must likewise leave validators when transform returns None.
    let plugin = Arc::new(plugin) as Arc<dyn Plugin>;
    let mut ctx = make_ctx();
    let mut status = 200u16;
    let mut body_buf = bytes::Bytes::from(body.to_vec());
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body_buf,
        None,
        false,
    )
    .await;
    assert!(!rewritten);
    assert_eq!(&body_buf[..], &body[..]);
    assert_stale_representation_headers_present(&headers);
}

/// Parse failures and non-JSON media types return `None` from the transform.
/// Direct callers never invoke the cleanup hook; the buffered lifecycle leaves
/// validators untouched when the plugin does not claim the representation.
#[tokio::test]
async fn parse_failure_and_non_json_preserve_representation_validators() {
    let plugin = body_update_plugin();
    let malformed = b"{not-json";
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), malformed.len().to_string()),
    ]);
    insert_stale_representation_headers(&mut headers);
    let before = headers.clone();

    assert!(
        plugin
            .transform_response_body(malformed, Some("application/json"), &headers)
            .await
            .is_none(),
        "malformed JSON must not rewrite bytes"
    );
    assert_eq!(headers, before);
    assert_stale_representation_headers_present(&headers);

    // Non-JSON responses are unclaimed, so the buffered lifecycle skips finalize.
    let plugin = Arc::new(plugin) as Arc<dyn Plugin>;
    let html = b"<html></html>";
    let mut ctx = make_ctx();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());
    headers.insert("content-length".to_string(), html.len().to_string());
    insert_stale_representation_headers(&mut headers);
    let before = headers.clone();
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let mut body_buf = bytes::Bytes::from(html.to_vec());
    let (replaced, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body_buf,
        None,
        false,
    )
    .await;
    assert!(!replaced);
    assert!(!rewritten);
    assert_eq!(&body_buf[..], &html[..]);
    assert_eq!(headers, before);
    assert_stale_representation_headers_present(&headers);
}

/// Shared buffered transform lifecycle must strip validators after an actual
/// rewrite and repair Content-Length for the new bytes.
#[tokio::test]
async fn buffered_lifecycle_strips_stale_validators_on_rewrite() {
    let plugin = Arc::new(body_update_plugin()) as Arc<dyn Plugin>;
    let mut ctx = make_ctx();
    let original = br#"{"state":"origin"}"#.to_vec();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    headers.insert("x-correlation-id".to_string(), "corr-1".to_string());
    insert_stale_representation_headers(&mut headers);
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let mut body = bytes::Bytes::from(original.clone());
    let (replaced, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(!replaced);
    assert!(rewritten);
    assert_ne!(body, original);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["state"],
        "public"
    );
    let expected_len = body.len().to_string();
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some(expected_len.as_str())
    );
    assert_stale_representation_headers_absent(&headers);
    assert_eq!(
        headers.get("x-correlation-id").map(String::as_str),
        Some("corr-1"),
        "unrelated decorator headers must survive finalize"
    );
}

/// Synthetic short-circuit publication uses the same finalize contract.
#[tokio::test]
async fn synthetic_lifecycle_strips_stale_validators_on_rewrite() {
    let plugin = Arc::new(body_update_plugin()) as Arc<dyn Plugin>;
    let mut ctx = make_ctx();
    let original = br#"{"state":"origin"}"#.to_vec();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_representation_headers(&mut headers);

    let mut body = bytes::Bytes::from(original.clone());
    apply_synthetic_response_body_hooks_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    )
    .await;

    assert_ne!(body, original);
    assert_stale_representation_headers_absent(&headers);
    let expected_len = body.len().to_string();
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some(expected_len.as_str())
    );
}

/// Multiple transformer instances preserve configured order; each rewrite that
/// changes bytes re-runs finalize before the next instance.
#[tokio::test]
async fn multiple_transformer_instances_strip_validators_in_order() {
    let first = Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "update", "target": "body", "key": "state", "value": "mid"}
            ]
        }))
        .unwrap(),
    ) as Arc<dyn Plugin>;
    let second = Arc::new(
        ResponseTransformer::new(&json!({
            "rules": [
                {"operation": "add", "target": "body", "key": "stage", "value": "final"}
            ]
        }))
        .unwrap(),
    ) as Arc<dyn Plugin>;

    let mut ctx = make_ctx();
    let original = br#"{"state":"origin"}"#.to_vec();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_representation_headers(&mut headers);
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[first, second],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(rewritten);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["state"], "mid");
    assert_eq!(json["stage"], "final");
    assert_stale_representation_headers_absent(&headers);
}

/// Digests present in the merged header+trailer view are removed by finalize;
/// buffered gRPC then retires trailer-channel copies while keeping grpc-status.
#[tokio::test]
async fn trailer_integrity_fields_retired_after_body_rewrite() {
    let plugin = Arc::new(body_update_plugin()) as Arc<dyn Plugin>;
    let mut ctx = make_ctx();
    let original = br#"{"state":"origin"}"#.to_vec();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_representation_headers(&mut headers);
    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);

    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    assert!(rewritten);
    assert_stale_representation_headers_absent(&headers);

    let mut trailers = HashMap::new();
    insert_stale_representation_headers(&mut trailers);
    trailers.insert("grpc-status".to_string(), "0".to_string());
    discard_grpc_application_trailers_after_body_rewrite_for_test(&mut headers, &mut trailers, &[]);
    assert_eq!(
        trailers,
        HashMap::from([("grpc-status".to_string(), "0".to_string())]),
        "application trailer digests must be retired; terminal status preserved"
    );
    assert_stale_representation_headers_absent(&headers);
}

/// After a rewrite strips origin ETag / Last-Modified, response_caching must
/// store the cleaned headers so a later If-None-Match for the origin validator
/// cannot produce a conditional 304 for the transformed body.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn response_caching_does_not_revalidate_stripped_origin_etag() {
    let _policy_guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    let transformer = Arc::new(body_update_plugin()) as Arc<dyn Plugin>;
    let caching = ResponseCaching::new(&json!({
        "ttl_seconds": 60,
        "add_cache_status_header": true
    }))
    .unwrap();

    let path = "/transformed-cache";
    let original = br#"{"state":"origin"}"#.to_vec();
    let mut transform_ctx = make_ctx();
    transform_ctx.path = path.to_string();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );
    insert_stale_representation_headers(&mut headers);
    stamp_original_response_metadata_for_test(&mut transform_ctx, status, &headers);

    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[transformer],
        &mut transform_ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    assert!(rewritten);
    assert_stale_representation_headers_absent(&headers);

    // Store the post-rewrite representation through the final-body hook.
    let mut store_ctx = make_ctx();
    store_ctx.path = path.to_string();
    store_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    // Stand in for the proxy's transport-owned empty-request-body proof, which
    // `response_caching` requires before it may look up or store.
    set_replay_request_body_empty_proven_for_test(&mut store_ctx, true);
    set_response_presentation_policy_digest_for_test(&mut store_ctx, Some([0x51; 32]));
    let mut request_headers = HashMap::new();
    assert!(matches!(
        caching
            .before_proxy(&mut store_ctx, &mut request_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        caching
            .after_proxy(&mut store_ctx, status, &mut headers)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        caching
            .on_final_response_body(&mut store_ctx, status, &headers, &body)
            .await,
        PluginResult::Continue
    ));

    // A client carrying the origin ETag must not receive 304 — that validator
    // never identified the transformed bytes and was not stored.
    let mut hit_ctx = make_ctx();
    hit_ctx.path = path.to_string();
    hit_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    set_replay_request_body_empty_proven_for_test(&mut hit_ctx, true);
    set_response_presentation_policy_digest_for_test(&mut hit_ctx, Some([0x51; 32]));
    let mut conditional =
        HashMap::from([("if-none-match".to_string(), "\"origin-v1\"".to_string())]);
    match caching.before_proxy(&mut hit_ctx, &mut conditional).await {
        PluginResult::RejectBinary {
            status_code,
            body: hit_body,
            headers: hit_headers,
        } => {
            assert_eq!(status_code, 200, "must serve the transformed body, not 304");
            assert_eq!(hit_body.as_ref(), &body[..]);
            assert!(
                hit_headers
                    .keys()
                    .all(|key| !key.eq_ignore_ascii_case("etag")),
                "cached entry must not revive the stripped origin ETag"
            );
            assert_eq!(
                hit_headers.get("x-cache-status").map(String::as_str),
                Some("HIT")
            );
        }
        other => panic!("expected cache HIT with transformed body, got {other:?}"),
    }
}

/// Pin that H1/H2 buffered + synthetic paths and H3 buffered / cross-protocol
/// paths all reach the shared finalize contract used above.
#[test]
fn h1_h2_h3_paths_reach_shared_body_transform_finalize() {
    let h1_h2 = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/server.rs");
    let h3_cross = include_str!("../../../src/http3/cross_protocol.rs");

    assert!(
        h1_h2.contains("crate::plugins::finalize_response_body_transformation("),
        "H1/H2 buffered/synthetic paths must finalize after a body rewrite"
    );
    assert!(
        h1_h2.contains("transform_buffered_response_body_with_deadline("),
        "H1/H2 buffered path must use the shared transform helper"
    );
    assert!(
        h3.contains("crate::proxy::transform_buffered_response_body_with_deadline("),
        "native H3 buffered path must use the shared transform helper"
    );
    assert!(
        h3_cross.contains("crate::plugins::finalize_response_body_transformation("),
        "H3 cross-protocol path must finalize after a body rewrite"
    );
}

// ── Header mutation tracing must never emit configured values ─────────────

use std::future::Future;
use std::io::{self, Write};
use std::sync::Mutex;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

async fn capture_debug_logs<F, Fut>(operation: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let writer = SharedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    operation().await;
    String::from_utf8(writer.0.lock().unwrap().clone()).unwrap()
}

fn assert_secret_absent_from_logs(logs: &str, secret: &str) {
    assert!(
        !logs.contains(secret),
        "configured header value must not appear in tracing output: {secret:?}\nlogs:\n{logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_response_transformer_header_mutations_never_log_configured_values() {
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
        let plugin = ResponseTransformer::new(&json!({ "rules": [rule] })).unwrap();
        let logs = capture_debug_logs(|| async {
            let mut ctx = make_ctx();
            let mut headers = std::mem::take(&mut seed_headers);
            let _ = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
            assert_eq!(
                headers.get(expected_key).map(String::as_str),
                Some(secret),
                "{label}: header mutation must still apply"
            );
        })
        .await;
        assert_secret_absent_from_logs(&logs, secret);
        assert!(
            logs.contains("response_transformer:"),
            "{label}: expected transformer debug event, got:\n{logs}"
        );
    }

    let plugin = ResponseTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "Authorization"}
        ]
    }))
    .unwrap();
    let logs = capture_debug_logs(|| async {
        let mut ctx = make_ctx();
        let mut headers = HashMap::from([(
            "authorization".to_string(),
            "Bearer existing-token-never-log".to_string(),
        )]);
        let _ = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
        assert!(!headers.contains_key("authorization"));
    })
    .await;
    assert_secret_absent_from_logs(&logs, "Bearer existing-token-never-log");
    assert!(
        logs.contains("response_transformer: removed header authorization"),
        "remove should still emit a name-only diagnostic"
    );
}
