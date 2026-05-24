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

fn content_type_headers(content_type: &str) -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), content_type.to_string())])
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
                "request_body_required": "true"
            }]
        }),
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
async fn disabled_mode_skips_matching_and_buffering() {
    let plugin = OpenapiValidator::new(&validator_config("disabled")).unwrap();
    let mut ctx = post_ctx("/missing");
    let mut headers = json_headers();

    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.mode")
            .map(String::as_str),
        Some("disabled")
    );
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
async fn bypass_header_uses_before_proxy_headers_when_ctx_headers_are_moved() {
    let config = json!({
        "schema_draft": "draft7",
        "bypass": {"header_present": {"x-bypass-validator": null}},
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {"application/json": {"type": "object"}}},
            "responses": {"200": {"application/json": {"type": "object"}}}
        }]
    });
    let plugin = OpenapiValidator::new(&config).unwrap();
    let mut ctx = post_ctx("/missing");
    ctx.headers
        .insert("x-bypass-validator".to_string(), "1".to_string());
    let mut headers = std::mem::take(&mut ctx.headers);

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.skip_reason")
            .map(String::as_str),
        Some("bypass_header")
    );
    assert!(!plugin.should_buffer_response_body(&ctx));
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

#[tokio::test]
async fn xml_request_validation_honors_xml_metadata() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/orders",
            "path_regex": "^/orders$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "order"},
                        "required": ["id", "quantity"],
                        "additionalProperties": false,
                        "properties": {
                            "id": {"type": "string", "xml": {"attribute": true}},
                            "quantity": {"type": "integer", "xml": {"name": "qty"}}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/orders");
    ctx.headers = content_type_headers("application/xml");
    let headers = ctx.headers.clone();

    assert!(plugin.should_buffer_request_body(&ctx));
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<order id="A-1"><qty>3</qty></order>"#,
            )
            .await,
    );

    let mut ctx = post_ctx("/orders");
    ctx.headers = content_type_headers("application/xml");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/xml"),
                br#"<order><qty>bad</qty></order>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/orders");
    ctx.headers = content_type_headers("application/xml");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/xml"),
                br#"<order id="A-1" extra="nope"><qty>3</qty></order>"#,
            )
            .await,
        Some(400),
    );

    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/docs",
            "path_regex": "^/docs$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "doc"},
                        "properties": {
                            "body": {"type": "string"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/docs");
    ctx.headers = content_type_headers("application/xml");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/xml"),
                br#"<doc><body><![CDATA[<!doctype html>]]></body></doc>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn urlencoded_request_validation_converts_fields_to_schema_types() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/login",
            "path_regex": "^/login$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "type": "object",
                        "required": ["username", "remember"],
                        "properties": {
                            "username": {"type": "string", "minLength": 3},
                            "remember": {"type": "boolean"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/login");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");

    assert!(plugin.should_buffer_request_body(&ctx));
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"username=alice&remember=on",
            )
            .await,
    );

    let mut ctx = post_ctx("/login");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"username=al&remember=maybe",
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn multipart_request_validation_checks_fields_and_file_metadata() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["title", "file"],
                        "properties": {
                            "title": {"type": "string"},
                            "file": {
                                "type": "object",
                                "required": ["filename", "content_type", "size"],
                                "properties": {
                                    "filename": {"type": "string", "const": "a.txt"},
                                    "content_type": {"type": "string", "const": "text/plain"},
                                    "size": {"type": "integer", "minimum": 5}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"title\"\r\n\r\n",
        "Upload\r\n",
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
        "Content-Type: text/plain\r\n\r\n",
        "hello\r\n",
        "--abc--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");

    assert!(plugin.should_buffer_request_body(&ctx));
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                body.as_bytes(),
            )
            .await,
    );

    let bad_body = body.replace("filename=\"a.txt\"", "filename=\"b.txt\"");
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                bad_body.as_bytes(),
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn text_and_binary_response_validation_use_matching_schema_rules() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/download",
            "path_regex": "^/download$",
            "responses": {
                "200": {
                    "text/plain": {"type": "string", "pattern": "^ok:"},
                    "application/octet-stream": {"type": "string", "format": "binary", "minLength": 3, "maxLength": 3},
                    "application/pdf": {"type": "string", "format": "binary", "minLength": 4, "maxLength": 4}
                },
                "4XX": {
                    "application/json": {"type": "object", "required": ["error"]}
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/download");

    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("text/plain"),
                b"ok: ready",
            )
            .await,
    );
    let mut ctx = post_ctx("/download");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &content_type_headers("text/plain"), b"bad")
            .await,
        Some(502),
    );
    let mut ctx = post_ctx("/download");
    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/octet-stream"),
                &[0, 159, 255],
            )
            .await,
    );
    let mut ctx = post_ctx("/download");
    assert_continue(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/pdf"),
                &[0, 159, 255, 42],
            )
            .await,
    );
    let mut ctx = post_ctx("/download");
    assert_reject(
        plugin
            .on_final_response_body(
                &mut ctx,
                200,
                &content_type_headers("application/pdf"),
                &[0, 159, 255, 42, 100],
            )
            .await,
        Some(502),
    );
    let mut ctx = post_ctx("/download");
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 404, &json_headers(), br#"{"error":"missing"}"#)
            .await,
    );
}
