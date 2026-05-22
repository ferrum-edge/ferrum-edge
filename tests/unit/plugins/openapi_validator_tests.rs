use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, openapi_validator::OpenapiValidator,
    priority,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::json;
use std::collections::HashMap;
use std::io::Write as _;

use super::plugin_utils::{assert_continue, assert_reject};

fn validator_config(mode: &str) -> serde_json::Value {
    json!({
        "enforcement_mode": mode,
        "schema_draft": "draft7",
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {
                    "application/json": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"}
                        }
                    }
                }
            },
            "responses": {
                "200": {
                    "application/json": {
                        "type": "object",
                        "required": ["ok"],
                        "properties": {"ok": {"type": "boolean"}}
                    }
                },
                "default": {
                    "application/json": {
                        "type": "object",
                        "required": ["error"],
                        "properties": {"error": {"type": "string"}}
                    }
                }
            }
        }]
    })
}

fn json_headers() -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), "application/json".to_string())])
}

fn post_ctx(path: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), path.into());
    ctx.headers = json_headers();
    ctx
}

#[test]
fn metadata_and_protocol_scope() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    assert_eq!(plugin.name(), "openapi_validator");
    assert_eq!(plugin.priority(), priority::OPENAPI_VALIDATOR);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.needs_final_request_body_context());
}

#[test]
fn invalid_configs_are_rejected() {
    for config in [
        json!("bad"),
        json!({}),
        json!({"operations": []}),
        json!({"enforcement_mode": "monitor", "operations": []}),
        json!({"operations": [{"method": "GET", "path_template": "/x", "path_regex": "["}]}),
        json!({
            "operations": [{
                "method": "POST",
                "path_template": "/x",
                "path_regex": "^/x$",
                "request_body": {"content": {"application/json": {"type": "not-a-type"}}}
            }]
        }),
    ] {
        assert!(
            OpenapiValidator::new(&config).is_err(),
            "config should fail: {config:?}"
        );
    }
}

#[tokio::test]
async fn request_validation_blocks_or_logs_by_mode() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    assert!(plugin.should_buffer_request_body(&ctx));
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{"id":1}"#)
            .await,
        Some(400),
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("rejected_request")
    );

    let plugin = OpenapiValidator::new(&validator_config("log_only")).unwrap();
    let mut ctx = post_ctx("/items");
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{"id":1}"#)
            .await,
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("logged_request_mismatch")
    );
}

#[tokio::test]
async fn valid_request_and_gzip_body_continue() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(br#"{"name":"book"}"#).unwrap();
    let body = encoder.finish().unwrap();

    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &body)
            .await,
    );
}

#[tokio::test]
async fn unknown_operation_is_rejected_before_proxy() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/missing");
    let mut headers = json_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.request_error")
            .map(String::as_str),
        Some("No OpenAPI operation matched POST /missing")
    );
}

#[tokio::test]
async fn literal_path_beats_parameter_path() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [
            {"method": "GET", "path_template": "/users/{id}", "path_regex": "^/users/[^/]+$"},
            {"method": "GET", "path_template": "/users/me", "path_regex": "^/users/me$"}
        ]
    }))
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/users/me".into());
    let mut headers = HashMap::new();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.matched_operation")
            .map(String::as_str),
        Some("GET /users/me")
    );
}

#[tokio::test]
async fn bypass_header_skips_buffering_and_validation() {
    let config = json!({
        "schema_draft": "draft7",
        "bypass": {"header_present": {"x-bypass-validator": null}},
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {"application/json": {"type": "object"}}}
        }]
    });
    let plugin = OpenapiValidator::new(&config).unwrap();
    let mut ctx = post_ctx("/items");
    ctx.headers
        .insert("x-bypass-validator".to_string(), "1".to_string());
    let mut headers = ctx.headers.clone();

    assert!(!plugin.should_buffer_request_body(&ctx));
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("bypass_header")
    );
}

#[tokio::test]
async fn response_validation_uses_default_and_strict_missing_schema() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    assert!(plugin.should_buffer_response_body(&ctx));

    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &json_headers(), br#"{"ok":"yes"}"#)
            .await,
        Some(502),
    );

    let mut ctx = post_ctx("/items");
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 404, &json_headers(), br#"{"error":"missing"}"#)
            .await,
    );

    let strict = OpenapiValidator::new(&json!({
        "fail_on_missing_response_schema": true,
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/items");
    let result = strict
        .on_final_response_body(&mut ctx, 201, &json_headers(), br#"{}"#)
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));
}
