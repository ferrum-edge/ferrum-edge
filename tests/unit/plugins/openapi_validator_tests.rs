use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, openapi_validator::OpenapiValidator,
    priority,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write as _;

use super::plugin_utils::{assert_continue, assert_reject};

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn urlencoded_exploded_free_form_object_collects_unprefixed_children() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/labels",
            "path_regex": "^/labels$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["kind", "labels"],
                            "additionalProperties": false,
                            "properties": {
                                "kind": {"const": "fixed"},
                                "labels": {
                                    "type": "object",
                                    "required": ["red", "blue"],
                                    "additionalProperties": {"type": "integer"}
                                }
                            }
                        },
                        "encoding": {
                            "labels": {"style": "form", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/x-www-form-urlencoded");
    let mut ctx = post_ctx("/labels");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"kind=fixed&red=1&blue=2")
            .await,
    );
}

#[tokio::test]
async fn nested_composed_array_items_are_converted_before_form_validation() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/numbers",
            "path_regex": "^/numbers$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "type": "object",
                        "required": ["values"],
                        "properties": {
                            "values": {
                                "allOf": [{
                                    "anyOf": [
                                        {"type": "array", "items": {"type": "integer"}},
                                        {"type": "null"}
                                    ]
                                }]
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/x-www-form-urlencoded");
    let mut ctx = post_ctx("/numbers");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"values=1&values=2")
            .await,
    );
}

#[tokio::test]
async fn multipart_structured_object_uses_declared_json_content_type() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/profile",
            "path_regex": "^/profile$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["profile"],
                            "properties": {
                                "profile": {
                                    "type": "object",
                                    "required": ["name", "age"],
                                    "properties": {
                                        "name": {"const": "alice"},
                                        "age": {"type": "integer", "const": 42}
                                    }
                                }
                            }
                        },
                        "encoding": {
                            "profile": {"contentType": "application/json"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"profile\"\r\n",
        "Content-Type: application/json\r\n\r\n",
        "{\"name\":\"alice\",\"age\":42}\r\n",
        "--abc--\r\n"
    );
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let mut ctx = post_ctx("/profile");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );
}

#[tokio::test]
async fn multipart_exploded_free_form_object_and_nested_array_are_converted() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/mixed",
            "path_regex": "^/mixed$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["kind", "labels", "values"],
                            "additionalProperties": false,
                            "properties": {
                                "kind": {"const": "fixed"},
                                "labels": {
                                    "type": "object",
                                    "required": ["red", "blue"],
                                    "additionalProperties": {"type": "integer"}
                                },
                                "values": {
                                    "oneOf": [
                                        {"type": "array", "items": {"type": "integer"}},
                                        {"type": "null"}
                                    ]
                                }
                            }
                        },
                        "encoding": {
                            "labels": {"style": "form", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "--abc\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\nfixed\r\n",
        "--abc\r\nContent-Disposition: form-data; name=\"red\"\r\n\r\n1\r\n",
        "--abc\r\nContent-Disposition: form-data; name=\"blue\"\r\n\r\n2\r\n",
        "--abc\r\nContent-Disposition: form-data; name=\"values\"\r\n\r\n3\r\n",
        "--abc\r\nContent-Disposition: form-data; name=\"values\"\r\n\r\n4\r\n",
        "--abc--\r\n"
    );
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let mut ctx = post_ctx("/mixed");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );
}

#[test]
fn multiple_exploded_free_form_objects_are_rejected_as_ambiguous() {
    let result = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/ambiguous",
            "path_regex": "^/ambiguous$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "left": {"type": "object"},
                                "right": {"type": "object"}
                            }
                        },
                        "encoding": {
                            "left": {"style": "form", "explode": true},
                            "right": {"style": "form", "explode": true}
                        }
                    }
                }
            }
        }]
    }));
    let error = match result {
        Ok(_) => panic!("unprefixed dynamic keys cannot be assigned to two free-form objects"),
        Err(error) => error,
    };
    assert!(error.contains("multiple explode=true free-form object properties"));
}

fn brotli_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut input = body;
    brotli::BrotliCompress(
        &mut input,
        &mut encoded,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    encoded
}

fn encoding_headers(encoding: &str) -> HashMap<String, String> {
    let mut headers = json_headers();
    headers.insert("content-encoding".to_string(), encoding.to_string());
    headers
}

fn request_error(ctx: &RequestContext) -> Option<&str> {
    ctx.metadata
        .get("openapi_validator.request_error")
        .map(String::as_str)
}

fn response_error(ctx: &RequestContext) -> Option<&str> {
    ctx.metadata
        .get("openapi_validator.response_error")
        .map(String::as_str)
}

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
async fn delete_request_with_schema_buffers_and_validates_body() {
    let plugin = OpenapiValidator::new(&json!({
        "enforcement_mode": "block",
        "operations": [{
            "method": "DELETE",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {
                    "application/json": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "DELETE".into(), "/items".into());
    ctx.headers = json_headers();
    assert!(plugin.should_buffer_request_body(&ctx));
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{}"#)
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn valid_request_and_gzip_body_continue() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    let headers = encoding_headers("gzip");
    let body = gzip_bytes(br#"{"name":"book"}"#);

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
    assert!(
        !ctx.metadata.keys().any(|key| key
            .starts_with("openapi_validator.matched_operation_method.")
            || key.starts_with("openapi_validator.matched_operation_index.")),
        "internal operation cache keys must not be exposed in metadata: {:?}",
        ctx.metadata
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
    assert!(
        !ctx.metadata
            .keys()
            .any(|key| key.starts_with("openapi_validator.skip_reason.")),
        "internal skip cache keys must not be exposed in metadata: {:?}",
        ctx.metadata
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
async fn response_sse_intent_is_conservative_and_genuine_stream_fails_closed() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let mut ctx = post_ctx("/items");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    assert!(plugin.should_buffer_response_body(&ctx));

    let mut response_headers = content_type_headers("text/event-stream");
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &response_headers));
    assert!(
        plugin.should_release_response_body_before_content_type_rewrite(
            &ctx,
            200,
            &response_headers,
        )
    );
    let json_profile_headers = content_type_headers("application/json; profile=event-stream");
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &json_profile_headers,));
    assert!(
        !plugin.should_release_response_body_before_content_type_rewrite(
            &ctx,
            200,
            &json_profile_headers,
        )
    );
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &response_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; profile=event-stream"),
        200,
        &HashMap::new(),
    ));
    assert_reject(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        Some(502),
    );
    assert_eq!(
        ctx.metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("rejected_response")
    );

    let log_only = OpenapiValidator::new(&validator_config("log_only")).unwrap();
    let mut log_ctx = post_ctx("/items");
    let mut log_headers = content_type_headers("text/event-stream");
    assert_continue(
        log_only
            .after_proxy(&mut log_ctx, 200, &mut log_headers)
            .await,
    );
    assert_eq!(
        log_ctx
            .metadata
            .get("openapi_validator.action")
            .map(String::as_str),
        Some("logged_response_mismatch")
    );
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
async fn xml_request_validation_rejects_wrong_root_and_accepts_top_level_arrays() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/expected-root",
            "path_regex": "^/expected-root$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "expected"},
                        "additionalProperties": false
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/xml");
    let mut ctx = post_ctx("/expected-root");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, br#"<wrong/>"#)
            .await,
        Some(400),
    );

    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/values",
            "path_regex": "^/values$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "array",
                        "xml": {"name": "values"},
                        "items": {"type": "integer"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/values");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<values><value>1</value><value>2</value></values>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn xml_preserves_additional_properties_and_leaf_attributes() {
    // #3020: additionalProperties subschema must see unknown XML members.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/extra",
            "path_regex": "^/extra$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "known": {"type": "string"}
                        },
                        "additionalProperties": {"type": "integer"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/xml");
    let mut ctx = post_ctx("/extra");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><known>x</known><extra>not-an-integer</extra></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/extra");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><known>x</known><extra>7</extra></root>"#,
            )
            .await,
    );
    // Distinct attribute namespaces may reuse one local name, but the JSON
    // instance cannot represent both without a first/last-win differential.
    let mut ctx = post_ctx("/extra");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:a="urn:a" xmlns:b="urn:b" a:extra="7" b:extra="8">
                    <known>x</known>
                </root>"#,
            )
            .await,
        Some(400),
    );

    // Omitted additionalProperties still preserves members for object-wide keywords.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/max",
            "path_regex": "^/max$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "maxProperties": 1,
                        "properties": {
                            "known": {"type": "string"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/max");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><known>x</known><extra>1</extra></root>"#,
            )
            .await,
        Some(400),
    );

    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/pattern",
            "path_regex": "^/pattern$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "known": {"type": "string"}
                        },
                        "patternProperties": {
                            "^x_": {"type": "integer"}
                        },
                        "additionalProperties": false
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/pattern");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><known>x</known><x_count>3</x_count></root>"#,
            )
            .await,
    );
    let mut ctx = post_ctx("/pattern");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><known>x</known><x_count>nope</x_count></root>"#,
            )
            .await,
        Some(400),
    );

    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/names",
            "path_regex": "^/names$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "propertyNames": {"pattern": "^[a-z]+$"},
                        "additionalProperties": {"type": "string"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/names");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><BadName>x</BadName></root>"#,
            )
            .await,
        Some(400),
    );

    // Leaf attributes must survive generic conversion for empty property maps.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/leaf",
            "path_regex": "^/leaf$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "required": ["flag"],
                        "properties": {},
                        "additionalProperties": {"type": "string"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/leaf");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, br#"<root flag="on"/>"#)
            .await,
    );

    // Repeated unknown elements preserve multiplicity for schema evaluation.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/multi",
            "path_regex": "^/multi$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "known": {"type": "string"}
                        },
                        "additionalProperties": {"type": "integer"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/multi");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><known>x</known><extra>1</extra><extra>2</extra></root>"#,
            )
            .await,
        Some(400),
    );

    // A schema with no declared properties must still use its typed
    // additionalProperties schema during XML conversion.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/only-additional",
            "path_regex": "^/only-additional$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {},
                        "additionalProperties": {"type": "integer"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/only-additional");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><count>7</count></root>"#,
            )
            .await,
    );

    // Distinct expanded names cannot collapse into one local-name JSON key.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/ambiguous-additional",
            "path_regex": "^/ambiguous-additional$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {},
                        "additionalProperties": true
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/ambiguous-additional");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:a="urn:a" xmlns:b="urn:b"><a:extra>one</a:extra><b:extra>two</b:extra></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/ambiguous-additional");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root extra="attribute"><extra>element</extra></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/ambiguous-additional");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><extra><item>one</item><item>two</item></extra></root>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn xml_rejects_repeated_scalar_elements_fail_closed() {
    // #3021: duplicate scalar elements must not first-win.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/role",
            "path_regex": "^/role$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "required": ["role"],
                        "additionalProperties": false,
                        "properties": {
                            "role": {"type": "string", "const": "user"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/xml");

    // First-win style hostile document: first is valid, second would escalate.
    let mut ctx = post_ctx("/role");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><role>user</role><role>admin</role></root>"#,
            )
            .await,
        Some(400),
    );
    // Last-win style hostile document: last is valid, first would be ignored.
    let mut ctx = post_ctx("/role");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><role>admin</role><role>user</role></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/role");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><role>user</role></root>"#,
            )
            .await,
    );

    // Arrays continue to preserve ordered repeated elements.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/tags",
            "path_regex": "^/tags$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "required": ["tags"],
                        "additionalProperties": false,
                        "properties": {
                            "tags": {
                                "type": "array",
                                "minItems": 2,
                                "items": {"type": "string", "xml": {"name": "tag"}}
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/tags");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><tag>a</tag><tag>b</tag></root>"#,
            )
            .await,
    );

    // Wrapped arrays reject repeated wrappers.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/wrapped",
            "path_regex": "^/wrapped$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "tags": {
                                "type": "array",
                                "xml": {"name": "tags", "wrapped": true},
                                "items": {"type": "string", "xml": {"name": "tag"}}
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/wrapped");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><tags><tag>a</tag></tags><tags><tag>b</tag></tags></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/wrapped");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><tags><tag>a</tag><tag>b</tag></tags></root>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn xml_namespace_and_prefix_metadata_fail_closed() {
    // #3022: honor xml.namespace / xml.prefix via expanded-name matching.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/ns",
            "path_regex": "^/ns$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "required": ["name"],
                        "additionalProperties": false,
                        "properties": {
                            "name": {
                                "type": "string",
                                "const": "approved",
                                "xml": {
                                    "name": "name",
                                    "namespace": "https://trusted.example/schema",
                                    "prefix": "trusted"
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/xml");

    // Wrong namespace, matching local name + const: must reject.
    let mut ctx = post_ctx("/ns");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:evil="https://attacker.example/schema"><evil:name>approved</evil:name></root>"#,
            )
            .await,
        Some(400),
    );
    // Unqualified element when a namespace is required: reject.
    let mut ctx = post_ctx("/ns");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root><name>approved</name></root>"#,
            )
            .await,
        Some(400),
    );
    // Prefix alias bound to the required URI: accept.
    let mut ctx = post_ctx("/ns");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:other="https://trusted.example/schema"><other:name>approved</other:name></root>"#,
            )
            .await,
    );
    // Default namespace with the required URI: accept.
    let mut ctx = post_ctx("/ns");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns="https://trusted.example/schema"><name>approved</name></root>"#,
            )
            .await,
    );

    // Attribute namespaces.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/attr",
            "path_regex": "^/attr$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "required": ["id"],
                        "additionalProperties": false,
                        "properties": {
                            "id": {
                                "type": "string",
                                "const": "A-1",
                                "xml": {
                                    "name": "id",
                                    "attribute": true,
                                    "namespace": "https://trusted.example/schema",
                                    "prefix": "trusted"
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/attr");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:evil="https://attacker.example/schema" evil:id="A-1"/>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/attr");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:trusted="https://trusted.example/schema" trusted:id="A-1"/>"#,
            )
            .await,
    );

    // Array item / wrapper namespaces.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "required": ["items"],
                        "additionalProperties": false,
                        "properties": {
                            "items": {
                                "type": "array",
                                "minItems": 1,
                                "xml": {
                                    "name": "items",
                                    "wrapped": true,
                                    "namespace": "https://trusted.example/schema",
                                    "prefix": "trusted"
                                },
                                "items": {
                                    "type": "string",
                                    "xml": {
                                        "name": "item",
                                        "namespace": "https://trusted.example/schema",
                                        "prefix": "trusted"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/items");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:evil="https://attacker.example/schema"><evil:items><evil:item>a</evil:item></evil:items></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/items");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:trusted="https://trusted.example/schema"><trusted:items><trusted:item>a</trusted:item></trusted:items></root>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn xml_hardening_preserves_draft7_and_draft202012() {
    for draft in ["draft7", "draft2020-12"] {
        let plugin = OpenapiValidator::new(&json!({
            "schema_draft": draft,
            "operations": [{
                "method": "POST",
                "path_template": "/draft",
                "path_regex": "^/draft$",
                "request_body": {
                    "content": {
                        "application/xml": {
                            "type": "object",
                            "xml": {"name": "root"},
                            "required": ["role"],
                            "additionalProperties": {"type": "integer"},
                            "properties": {
                                "role": {
                                    "type": "string",
                                    "const": "user",
                                    "xml": {
                                        "name": "role",
                                        "namespace": "https://trusted.example/schema",
                                        "prefix": "trusted"
                                    }
                                }
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap_or_else(|error| panic!("draft {draft} must admit XML schemas: {error}"));
        let headers = content_type_headers("application/xml");

        let mut ctx = post_ctx("/draft");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:trusted="https://trusted.example/schema"><trusted:role>user</trusted:role><extra>9</extra></root>"#,
                )
                .await,
        );
        let mut ctx = post_ctx("/draft");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:trusted="https://trusted.example/schema"><trusted:role>user</trusted:role><trusted:role>admin</trusted:role></root>"#,
                )
                .await,
            Some(400),
        );
        let mut ctx = post_ctx("/draft");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:evil="https://attacker.example/schema"><evil:role>user</evil:role></root>"#,
                )
                .await,
            Some(400),
        );
    }
}

#[tokio::test]
async fn xml_wrong_namespace_cannot_rebind_modeled_json_key() {
    // Optional modeled properties: rejection must come from the wrong-namespace
    // collision itself, not from a missing required member (#3022). Covers
    // additionalProperties omitted and true for scalar elements, attributes,
    // wrapped arrays, and unwrapped arrays.
    let headers = content_type_headers("application/xml");

    for additional in [Value::Null, json!(true)] {
        let mut body_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "properties": {
                "role": {
                    "type": "string",
                    "const": "user",
                    "xml": {
                        "name": "role",
                        "namespace": "https://trusted.example/schema",
                        "prefix": "trusted"
                    }
                }
            }
        });
        if !additional.is_null() {
            body_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/rebind",
                "path_regex": "^/rebind$",
                "request_body": {
                    "content": {
                        "application/xml": body_schema
                    }
                }
            }]
        }))
        .unwrap_or_else(|error| {
            panic!("schema with additionalProperties={additional} must admit: {error}")
        });

        // Wrong-namespace local alone must fail closed (property is optional).
        let mut ctx = post_ctx("/rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:evil="https://attacker.example/schema"><evil:role>user</evil:role></root>"#,
                )
                .await,
            Some(400),
        );
        // Empty root is accepted when the modeled property is optional.
        let mut ctx = post_ctx("/rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, br#"<root/>"#)
                .await,
        );
        // Correct URI under an arbitrary prefix still accepted; unrelated
        // additional members still materialize when allowed.
        let mut ctx = post_ctx("/rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:other="https://trusted.example/schema"><other:role>user</other:role><note>ok</note></root>"#,
                )
                .await,
        );
    }

    // Optional wrong-namespace attribute with additionalProperties omitted/true.
    for additional in [Value::Null, json!(true)] {
        let mut body_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "properties": {
                "id": {
                    "type": "string",
                    "const": "A-1",
                    "xml": {
                        "name": "id",
                        "attribute": true,
                        "namespace": "https://trusted.example/schema",
                        "prefix": "trusted"
                    }
                }
            }
        });
        if !additional.is_null() {
            body_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/attr-rebind",
                "path_regex": "^/attr-rebind$",
                "request_body": {
                    "content": {
                        "application/xml": body_schema
                    }
                }
            }]
        }))
        .unwrap();

        let mut ctx = post_ctx("/attr-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:evil="https://attacker.example/schema" evil:id="A-1"/>"#,
                )
                .await,
            Some(400),
        );
        let mut ctx = post_ctx("/attr-rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, br#"<root/>"#)
                .await,
        );
        let mut ctx = post_ctx("/attr-rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:alias="https://trusted.example/schema" alias:id="A-1" note="ok"/>"#,
                )
                .await,
        );
    }

    // Optional wrapped array: wrong-namespace wrapper must reject on its own
    // for additionalProperties omitted and true. Correct wrapper + wrong-
    // namespace item local must also reject (not silently drop the item).
    for additional in [Value::Null, json!(true)] {
        let mut body_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "properties": {
                "items": {
                    "type": "array",
                    "xml": {
                        "name": "items",
                        "wrapped": true,
                        "namespace": "https://trusted.example/schema",
                        "prefix": "trusted"
                    },
                    "items": {
                        "type": "string",
                        "xml": {
                            "name": "item",
                            "namespace": "https://trusted.example/schema",
                            "prefix": "trusted"
                        }
                    }
                }
            }
        });
        if !additional.is_null() {
            body_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/wrapped-rebind",
                "path_regex": "^/wrapped-rebind$",
                "request_body": {
                    "content": {
                        "application/xml": body_schema
                    }
                }
            }]
        }))
        .unwrap_or_else(|error| {
            panic!("wrapped schema with additionalProperties={additional} must admit: {error}")
        });
        let mut ctx = post_ctx("/wrapped-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:evil="https://attacker.example/schema"><evil:items><evil:item>a</evil:item></evil:items></root>"#,
                )
                .await,
            Some(400),
        );
        // Wrong-namespace item local at the object level also fails closed.
        let mut ctx = post_ctx("/wrapped-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:evil="https://attacker.example/schema"><evil:item>a</evil:item></root>"#,
                )
                .await,
            Some(400),
        );
        // Correct wrapper + wrong-namespace modeled item local must reject
        // (optional array must not silently become empty / pass).
        let mut ctx = post_ctx("/wrapped-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:t="https://trusted.example/schema" xmlns:e="https://attacker.example/schema"><t:items><e:item>a</e:item></t:items></root>"#,
                )
                .await,
            Some(400),
        );
        // Mixed correct + wrong-namespace item under the wrapper still rejects.
        let mut ctx = post_ctx("/wrapped-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:t="https://trusted.example/schema" xmlns:e="https://attacker.example/schema"><t:items><t:item>a</t:item><e:item>b</e:item></t:items></root>"#,
                )
                .await,
            Some(400),
        );
        // Correct URI under an arbitrary prefix accepted; unrelated non-colliding
        // children (object-level and under the wrapper) remain non-fatal.
        let mut ctx = post_ctx("/wrapped-rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:x="https://trusted.example/schema"><x:items><x:item>a</x:item><note>ignored</note></x:items><note>ok</note></root>"#,
                )
                .await,
        );
    }

    // Nested/composed array item schema: xml.namespace on items resolved through
    // allOf must still reject wrong-namespace children inside a correct wrapper.
    for additional in [Value::Null, json!(true)] {
        let mut body_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "properties": {
                "items": {
                    "type": "array",
                    "xml": {
                        "name": "items",
                        "wrapped": true,
                        "namespace": "https://trusted.example/schema",
                        "prefix": "trusted"
                    },
                    "allOf": [{
                        "items": {
                            "type": "string",
                            "xml": {
                                "name": "item",
                                "namespace": "https://trusted.example/schema",
                                "prefix": "trusted"
                            }
                        }
                    }]
                }
            }
        });
        if !additional.is_null() {
            body_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/wrapped-composed-rebind",
                "path_regex": "^/wrapped-composed-rebind$",
                "request_body": {
                    "content": {
                        "application/xml": body_schema
                    }
                }
            }]
        }))
        .unwrap_or_else(|error| {
            panic!(
                "composed wrapped schema with additionalProperties={additional} must admit: {error}"
            )
        });
        let mut ctx = post_ctx("/wrapped-composed-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:t="https://trusted.example/schema" xmlns:e="https://attacker.example/schema"><t:items><e:item>a</e:item></t:items></root>"#,
                )
                .await,
            Some(400),
        );
        let mut ctx = post_ctx("/wrapped-composed-rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:t="https://trusted.example/schema"><t:items><t:item>a</t:item></t:items><note>ok</note></root>"#,
                )
                .await,
        );
    }

    // Optional unwrapped array with additionalProperties omitted and true.
    for additional in [Value::Null, json!(true)] {
        let mut body_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "properties": {
                "tags": {
                    "type": "array",
                    "xml": {
                        "namespace": "https://trusted.example/schema",
                        "prefix": "trusted"
                    },
                    "items": {
                        "type": "string",
                        "xml": {
                            "name": "tags",
                            "namespace": "https://trusted.example/schema",
                            "prefix": "trusted"
                        }
                    }
                }
            }
        });
        if !additional.is_null() {
            body_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/unwrapped-rebind",
                "path_regex": "^/unwrapped-rebind$",
                "request_body": {
                    "content": {
                        "application/xml": body_schema
                    }
                }
            }]
        }))
        .unwrap_or_else(|error| {
            panic!("unwrapped schema with additionalProperties={additional} must admit: {error}")
        });
        let mut ctx = post_ctx("/unwrapped-rebind");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:evil="https://attacker.example/schema"><evil:tags>a</evil:tags></root>"#,
                )
                .await,
            Some(400),
        );
        let mut ctx = post_ctx("/unwrapped-rebind");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root xmlns:trusted="https://trusted.example/schema"><trusted:tags>a</trusted:tags><note>ok</note></root>"#,
                )
                .await,
        );
    }

    // Properties that omit xml.namespace still match by local name only.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/local-only",
            "path_regex": "^/local-only$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "role": {
                                "type": "string",
                                "const": "user",
                                "xml": {"name": "role"}
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/local-only");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:any="https://attacker.example/schema"><any:role>user</any:role></root>"#,
            )
            .await,
    );

    // Root xml.namespace still requires a matching root expanded name when
    // xml.name is present.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/root-ns",
            "path_regex": "^/root-ns$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {
                            "name": "root",
                            "namespace": "https://trusted.example/schema",
                            "prefix": "trusted"
                        },
                        "properties": {
                            "role": {"type": "string", "const": "user"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/root-ns");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns:evil="https://attacker.example/schema"><role>user</role></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/root-ns");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<alias:root xmlns:alias="https://trusted.example/schema"><role>user</role></alias:root>"#,
            )
            .await,
    );

    // A root namespace remains authoritative even when xml.name is omitted.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/root-ns-only",
            "path_regex": "^/root-ns-only$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {
                            "namespace": "https://trusted.example/schema",
                            "prefix": "trusted"
                        },
                        "properties": {
                            "role": {"type": "string", "const": "user"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/root-ns-only");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root xmlns="https://attacker.example/schema"><role>user</role></root>"#,
            )
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/root-ns-only");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<alias:document xmlns:alias="https://trusted.example/schema">
                    <role>user</role>
                </alias:document>"#,
            )
            .await,
    );
}

#[tokio::test]
async fn xml_cross_construct_members_cannot_fill_modeled_slot() {
    // #3020 "attributes versus elements" / "without key rebinding": always
    // materializing undeclared members must not let an attribute fill a slot
    // modeled as an element (or an element fill a slot modeled as an attribute).
    // Otherwise a required/const property supplied via the wrong XML construct
    // passes validation while the backend, which binds by construct, sees it
    // absent: a validator/backend differential. Covers additionalProperties
    // omitted, true, and a permissive subschema.
    let headers = content_type_headers("application/xml");

    for additional in [Value::Null, json!(true), json!({"type": "string"})] {
        // Element-modeled property supplied as an attribute must fail closed.
        let mut element_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "required": ["role"],
            "properties": {
                "role": {"type": "string", "const": "user", "xml": {"name": "role"}}
            }
        });
        if !additional.is_null() {
            element_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/construct-element",
                "path_regex": "^/construct-element$",
                "request_body": {"content": {"application/xml": element_schema}}
            }]
        }))
        .unwrap_or_else(|error| {
            panic!("element schema with additionalProperties={additional} must admit: {error}")
        });

        let mut ctx = post_ctx("/construct-element");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, br#"<root role="user"/>"#)
                .await,
            Some(400),
        );
        // The correct construct still validates.
        let mut ctx = post_ctx("/construct-element");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root><role>user</role></root>"#,
                )
                .await,
        );

        // Attribute-modeled property supplied as an element must fail closed.
        let mut attribute_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "required": ["id"],
            "properties": {
                "id": {
                    "type": "string",
                    "const": "A-1",
                    "xml": {"name": "id", "attribute": true}
                }
            }
        });
        if !additional.is_null() {
            attribute_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/construct-attribute",
                "path_regex": "^/construct-attribute$",
                "request_body": {"content": {"application/xml": attribute_schema}}
            }]
        }))
        .unwrap_or_else(|error| {
            panic!("attribute schema with additionalProperties={additional} must admit: {error}")
        });

        let mut ctx = post_ctx("/construct-attribute");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root><id>A-1</id></root>"#,
                )
                .await,
            Some(400),
        );
        let mut ctx = post_ctx("/construct-attribute");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, br#"<root id="A-1"/>"#)
                .await,
        );
    }

    // Distinct additional members (a different name) still materialize and are
    // evaluated normally: the collision guard is scoped to modeled names only.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/construct-additional",
            "path_regex": "^/construct-additional$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "role": {"type": "string", "const": "user", "xml": {"name": "role"}}
                        },
                        "additionalProperties": {"type": "string"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/construct-additional");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root note="ok"><role>user</role></root>"#,
            )
            .await,
    );
    // A same-named attribute alongside the correct element still fails closed:
    // the modeled slot is already filled, but the attribute collides by name.
    let mut ctx = post_ctx("/construct-additional");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root role="user"><role>user</role></root>"#,
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn xml_renamed_local_cross_construct_collisions_fail_closed() {
    // Namespace-less xml.name renames must reserve the wire local as well as the
    // JSON key. Otherwise an opposite-construct member named like the rename
    // (attribute `wireRole` vs element-modeled `role`/`wireRole`, or element
    // `wireId` vs attribute-modeled `id`/`wireId`) materializes as an additional
    // property under additionalProperties omitted/true/permissive and can fill
    // or bypass the modeled slot contrary to #3020.
    let headers = content_type_headers("application/xml");

    for additional in [Value::Null, json!(true), json!({"type": "string"})] {
        // Element-modeled rename: attribute named like the xml.name local fails.
        let mut element_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "required": ["role"],
            "properties": {
                "role": {
                    "type": "string",
                    "const": "user",
                    "xml": {"name": "wireRole"}
                }
            }
        });
        if !additional.is_null() {
            element_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/rename-element",
                "path_regex": "^/rename-element$",
                "request_body": {"content": {"application/xml": element_schema}}
            }]
        }))
        .unwrap_or_else(|error| {
            panic!(
                "renamed element schema with additionalProperties={additional} must admit: {error}"
            )
        });

        let mut ctx = post_ctx("/rename-element");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root wireRole="user"/>"#,
                )
                .await,
            Some(400),
        );
        // Correct construct still validates.
        let mut ctx = post_ctx("/rename-element");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root><wireRole>user</wireRole></root>"#,
                )
                .await,
        );
        // Opposite construct alongside the correct element still fails closed.
        let mut ctx = post_ctx("/rename-element");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root wireRole="user"><wireRole>user</wireRole></root>"#,
                )
                .await,
            Some(400),
        );

        // Attribute-modeled rename: element named like the xml.name local fails.
        let mut attribute_schema = json!({
            "type": "object",
            "xml": {"name": "root"},
            "required": ["id"],
            "properties": {
                "id": {
                    "type": "string",
                    "const": "A-1",
                    "xml": {"name": "wireId", "attribute": true}
                }
            }
        });
        if !additional.is_null() {
            attribute_schema
                .as_object_mut()
                .unwrap()
                .insert("additionalProperties".to_string(), additional.clone());
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/rename-attribute",
                "path_regex": "^/rename-attribute$",
                "request_body": {"content": {"application/xml": attribute_schema}}
            }]
        }))
        .unwrap_or_else(|error| {
            panic!(
                "renamed attribute schema with additionalProperties={additional} must admit: {error}"
            )
        });

        let mut ctx = post_ctx("/rename-attribute");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root><wireId>A-1</wireId></root>"#,
                )
                .await,
            Some(400),
        );
        let mut ctx = post_ctx("/rename-attribute");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, br#"<root wireId="A-1"/>"#)
                .await,
        );
        let mut ctx = post_ctx("/rename-attribute");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &headers,
                    br#"<root wireId="A-1"><wireId>A-1</wireId></root>"#,
                )
                .await,
            Some(400),
        );
    }

    // Unrelated additional names remain allowed under a permissive subschema.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/rename-additional",
            "path_regex": "^/rename-additional$",
            "request_body": {
                "content": {
                    "application/xml": {
                        "type": "object",
                        "xml": {"name": "root"},
                        "properties": {
                            "role": {
                                "type": "string",
                                "const": "user",
                                "xml": {"name": "wireRole"}
                            }
                        },
                        "additionalProperties": {"type": "string"}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/rename-additional");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                br#"<root note="ok"><wireRole>user</wireRole></root>"#,
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
async fn multipart_file_part_with_structured_content_type_validates_actual_metadata() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "object",
                                "required": ["filename", "content_type", "size", "content"],
                                "properties": {
                                    "filename": {"type": "string", "const": "safe.png"},
                                    "content_type": {"type": "string", "const": "image/png"},
                                    "size": {"type": "integer", "maximum": 2},
                                    "content": {"type": "string", "const": "ok"}
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
        "Content-Disposition: form-data; name=\"file\"; filename=\"evil.svg\"\r\n",
        "Content-Type: application/json\r\n\r\n",
        "{\"filename\":\"safe.png\",\"content_type\":\"image/png\",\"size\":2,\"content\":\"ok\"}\r\n",
        "--abc--\r\n"
    );
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let mut ctx = post_ctx("/upload");
    ctx.headers = headers.clone();

    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(400),
    );

    let extended_filename_body = body.replace("filename=\"evil.svg\"", "filename*=UTF-8''evil.svg");
    let mut ctx = post_ctx("/upload");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &headers,
                extended_filename_body.as_bytes(),
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

// Finding #17: two openapi_validator instances on the same request share
// ctx.metadata. Before the per-instance cache keys, the instance that marks its
// matched operation FIRST would have its (method, index) overwritten by a
// sibling and then resolve the sibling's index against its OWN differently
// ordered entry vector -- validating the request against the wrong operation
// schema. This test reproduces that ordering: instance A matches `/items` at
// sorted index 1 (because the more-specific `/items/extra` sorts first), while
// instance B matches `/items` at index 0. With the bug, A's body phase reads
// B's index 0 and validates against A's `/items/extra` schema (requires "z"),
// rejecting a body that is valid for `/items` (requires "a").
#[tokio::test]
async fn sibling_instances_do_not_cross_apply_operation_schemas() {
    let instance_a = OpenapiValidator::new(&json!({
        "operations": [
            {
                "method": "POST",
                "path_template": "/items/extra",
                "path_regex": "^/items/extra$",
                "request_required": true,
                "request_body": {
                    "content": {"application/json": {
                        "type": "object",
                        "required": ["z"],
                        "properties": {"z": {"type": "string"}}
                    }}
                }
            },
            {
                "method": "POST",
                "path_template": "/items",
                "path_regex": "^/items$",
                "request_required": true,
                "request_body": {
                    "content": {"application/json": {
                        "type": "object",
                        "required": ["a"],
                        "properties": {"a": {"type": "string"}}
                    }}
                }
            }
        ]
    }))
    .unwrap();
    let instance_b = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {"application/json": {
                    "type": "object",
                    "required": ["b"],
                    "properties": {"b": {"type": "string"}}
                }}
            }
        }]
    }))
    .unwrap();

    // Production order: every instance's before_proxy runs before any body
    // phase. A marks first, then B overwrites the shared (legacy) keys.
    let mut ctx = post_ctx("/items");
    let mut headers = json_headers();
    assert_continue(instance_a.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(instance_b.before_proxy(&mut ctx, &mut headers).await);

    // Body valid for A's `/items` operation ("a"), invalid for `/items/extra`
    // ("z"). A must validate against its own matched operation and continue.
    assert_continue(
        instance_a
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{"a":"ok"}"#)
            .await,
    );
}

// Finding #17 (bypass facet): cached_bypass_reason must read a per-instance key.
// A sibling that bypasses the request must not cause a non-bypassing instance to
// silently skip its own validation.
#[tokio::test]
async fn sibling_bypass_does_not_skip_other_instance_validation() {
    let bypassing = OpenapiValidator::new(&json!({
        "bypass": {"paths": ["^/items$"]},
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {"application/json": {"type": "object"}}}
        }]
    }))
    .unwrap();
    let enforcing = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_required": true,
            "request_body": {
                "content": {"application/json": {
                    "type": "object",
                    "required": ["a"],
                    "properties": {"a": {"type": "string"}}
                }}
            }
        }]
    }))
    .unwrap();

    let mut ctx = post_ctx("/items");
    let mut headers = json_headers();
    // The bypassing instance runs first and records its skip reason.
    assert_continue(bypassing.before_proxy(&mut ctx, &mut headers).await);
    // The enforcing instance must still reject a body missing the required "a".
    assert_reject(
        enforcing
            .on_final_request_body_with_context(&mut ctx, &json_headers(), br#"{}"#)
            .await,
        Some(400),
    );
}

// Finding #89: operator-supplied path_regex must be anchored so a loose pattern
// cannot substring-match an unintended superstring path.
#[tokio::test]
async fn unanchored_operator_path_regex_does_not_substring_match() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET",
            "path_template": "/users/{id}",
            "path_regex": "/users/[0-9]+"
        }]
    }))
    .unwrap();

    // Legitimate full-path request still matches.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/users/1".into());
    let mut headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Superstring path must NOT match -> unknown operation -> reject.
    let mut ctx = RequestContext::new(
        "127.0.0.1".into(),
        "GET".into(),
        "/admin/users/1/secret".into(),
    );
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Finding #89 (alternation): a top-level alternation must be wrapped as
// `^(?:a|b)$` so every branch is anchored. A bare `^a|b$` would leave the `/b`
// branch suffix-anchored only, wrongly matching `/zzz/b`.
#[tokio::test]
async fn alternation_path_regex_anchors_every_branch() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET",
            "path_template": "/a",
            "path_regex": "/a|/b"
        }]
    }))
    .unwrap();

    // Both alternation branches match when they are the whole path.
    for path in ["/a", "/b"] {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), path.into());
        let mut headers = HashMap::new();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    }

    // A path that merely ends with `/b` must NOT match (would match a bare
    // `^a|b$`). Unknown operation -> reject.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/zzz/b".into());
    let mut headers = HashMap::new();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Finding #88: skipping the multipart `content` copy must stay
// outcome-preserving. A schema that validates `content` -- here via `required`
// plus a `pattern` constraint -- must still see the materialized content and
// enforce it.
#[tokio::test]
async fn multipart_content_validation_preserved_when_schema_requires_it() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["doc"],
                        "properties": {
                            "doc": {
                                "type": "object",
                                "required": ["content", "size"],
                                "properties": {
                                    "content": {"type": "string", "pattern": "^ok:"},
                                    "size": {"type": "integer"}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let valid = concat!(
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"doc\"\r\n\r\n",
        "ok: ready\r\n",
        "--abc--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                valid.as_bytes(),
            )
            .await,
    );

    let invalid = valid.replace("ok: ready", "nope");
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                invalid.as_bytes(),
            )
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn content_encoding_identity_and_single_codings_validate() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let plaintext = br#"{"name":"book"}"#;
    let response_plain = br#"{"ok":true}"#;

    for encoding in ["identity", "Identity", " identity "] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &encoding_headers(encoding),
                    plaintext,
                )
                .await,
        );
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &encoding_headers(encoding), response_plain)
                .await,
        );
    }

    for (encoding, body) in [
        ("gzip", gzip_bytes(plaintext)),
        ("GZIP", gzip_bytes(plaintext)),
        ("br", brotli_bytes(plaintext)),
        ("BR", brotli_bytes(plaintext)),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &encoding_headers(encoding), &body)
                .await,
        );
    }

    for (encoding, body) in [
        ("gzip", gzip_bytes(response_plain)),
        ("br", brotli_bytes(response_plain)),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &encoding_headers(encoding), &body)
                .await,
        );
    }
}

#[tokio::test]
async fn content_encoding_chains_decode_in_reverse_application_order() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let plaintext = br#"{"name":"book"}"#;
    let response_plain = br#"{"ok":true}"#;

    // Application order for `gzip, br` is gzip then brotli; undo br first.
    let gzip_then_br = brotli_bytes(&gzip_bytes(plaintext));
    let br_then_gzip = gzip_bytes(&brotli_bytes(plaintext));
    for (encoding, body) in [
        ("gzip, br", gzip_then_br.clone()),
        ("gzip,br", gzip_then_br.clone()),
        (" GZIP , BR ", gzip_then_br.clone()),
        ("br, gzip", br_then_gzip.clone()),
        ("BR,GZIP", br_then_gzip.clone()),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &encoding_headers(encoding), &body)
                .await,
        );
    }

    let response_gzip_then_br = brotli_bytes(&gzip_bytes(response_plain));
    let response_br_then_gzip = gzip_bytes(&brotli_bytes(response_plain));
    for (encoding, body) in [
        ("gzip, br", response_gzip_then_br.as_slice()),
        ("br, gzip", response_br_then_gzip.as_slice()),
    ] {
        let mut ctx = post_ctx("/items");
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &encoding_headers(encoding), body)
                .await,
        );
    }

    // Wrong outer coding for the same bytes must fail closed (no partial decode).
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("br, gzip"),
                &gzip_then_br,
            )
            .await,
        Some(400),
    );
    let error = request_error(&ctx).unwrap_or_default();
    assert!(
        error.contains("decompression failed")
            || error.contains("truncated")
            || error.contains("trailing"),
        "wrong chain order must surface a decode error, got {error:?}"
    );
}

#[tokio::test]
async fn content_encoding_malformed_unsupported_and_corrupt_fail_closed() {
    let plugin = OpenapiValidator::new(&validator_config("block")).unwrap();
    let plaintext = br#"{"name":"book"}"#;

    for encoding in [",", "gzip,", ",br", "gzip,,br", " , ", "gzip;q=1.0"] {
        let mut ctx = post_ctx("/items");
        assert_reject(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &encoding_headers(encoding),
                    plaintext,
                )
                .await,
            Some(400),
        );
        let error = request_error(&ctx).unwrap_or_default();
        assert!(
            error.contains("empty coding")
                || error.contains("not a valid HTTP token")
                || error.contains("unsupported parameters"),
            "malformed `{encoding}` must be clear, got {error:?}"
        );
    }

    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoding_headers("gzip foo"), plaintext)
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("not a valid HTTP token"),
        "non-token member must be rejected clearly, got {:?}",
        request_error(&ctx)
    );

    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoding_headers("deflate"), plaintext)
            .await,
        Some(400),
    );
    assert_eq!(
        request_error(&ctx),
        Some("unsupported content-encoding 'deflate'")
    );

    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &encoding_headers("zstd"), br#"{"ok":true}"#)
            .await,
        Some(502),
    );
    assert_eq!(
        response_error(&ctx),
        Some("unsupported content-encoding 'zstd'")
    );

    // Corrupt outer layer of a gzip,br chain.
    let mut corrupt_outer = brotli_bytes(&gzip_bytes(plaintext));
    if let Some(last) = corrupt_outer.last_mut() {
        *last ^= 0xff;
    }
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip, br"),
                &corrupt_outer,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx).is_some_and(|error| error.contains("brotli")),
        "corrupt outer brotli must fail, got {:?}",
        request_error(&ctx)
    );

    // Corrupt inner gzip while outer brotli framing stays valid: encode garbage
    // as brotli so the outer unwrap succeeds and the inner gzip fails.
    let corrupt_inner = brotli_bytes(b"not-gzip-payload");
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &encoding_headers("gzip, br"),
                &corrupt_inner,
            )
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx).is_some_and(|error| error.contains("gzip")),
        "corrupt inner gzip must fail after outer decode, got {:?}",
        request_error(&ctx)
    );

    // Corrupt single-layer bodies still fail closed on both sides.
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoding_headers("gzip"), b"not-gzip")
            .await,
        Some(400),
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &encoding_headers("br"), b"not-brotli")
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn content_encoding_respects_max_body_bytes_on_raw_and_each_layer() {
    let plugin = OpenapiValidator::new(&json!({
        "enforcement_mode": "block",
        "schema_draft": "draft7",
        "max_body_bytes": 64,
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
                }
            }
        }]
    }))
    .unwrap();

    let exact = format!(r#"{{"name":"{}"}}"#, "n".repeat(53));
    assert_eq!(exact.len(), 64);
    let mut ctx = post_ctx("/items");
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), exact.as_bytes())
            .await,
    );

    let oversized_raw = vec![b'a'; 65];
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &oversized_raw)
            .await,
        Some(400),
    );
    assert_eq!(
        request_error(&ctx),
        Some("Body exceeds max_body_bytes of 64 bytes")
    );

    // Highly compressible payload: wire size stays under the raw ceiling, but
    // the identity representation exceeds max_body_bytes after decoding.
    let large_json = format!(r#"{{"name":"{}"}}"#, "n".repeat(512));
    assert!(large_json.len() > 64);
    let gzip_large = gzip_bytes(large_json.as_bytes());
    assert!(
        gzip_large.len() <= 64,
        "gzip fixture must fit under raw max, got {}",
        gzip_large.len()
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoding_headers("gzip"), &gzip_large)
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("exceeds 64 bytes"),
        "single-layer expansion must honor max_body_bytes, got {:?}",
        request_error(&ctx)
    );

    // Chained expansion: outer layer may be small, but an intermediate/final
    // layer above max_body_bytes must still fail closed.
    let chained = brotli_bytes(&gzip_bytes(large_json.as_bytes()));
    assert!(
        chained.len() <= 64,
        "chained fixture must fit under raw max, got {}",
        chained.len()
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &encoding_headers("gzip, br"), &chained)
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("exceeds 64 bytes"),
        "chained expansion must honor max_body_bytes per layer, got {:?}",
        request_error(&ctx)
    );

    let response_large = format!(r#"{{"ok":true,"pad":"{}"}}"#, "p".repeat(512));
    let response_gzip = gzip_bytes(response_large.as_bytes());
    assert!(
        response_gzip.len() <= 64,
        "response gzip fixture must fit under raw max, got {}",
        response_gzip.len()
    );
    let mut ctx = post_ctx("/items");
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &encoding_headers("gzip"), &response_gzip)
            .await,
        Some(502),
    );
    assert!(
        response_error(&ctx)
            .unwrap_or_default()
            .contains("exceeds 64 bytes"),
        "response expansion must honor max_body_bytes, got {:?}",
        response_error(&ctx)
    );
}

#[test]
fn encoding_wrapper_is_explicit_and_strict() {
    for invalid in [
        json!({"encoding": {}}),
        json!({"schema": true, "encoding": null}),
        json!({"schema": true, "encoding": {}, "example": "ambiguous"}),
    ] {
        let error = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/strict",
                "path_regex": "^/strict$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": invalid
                    }
                }
            }]
        }))
        .err()
        .expect("ambiguous or malformed encoding wrapper must fail admission");
        assert!(
            error.contains("media type object") || error.contains("encoding must be an object"),
            "unexpected strict-wrapper error: {error}"
        );
    }

    // A bare JSON Schema with a custom `schema` keyword and no `encoding`
    // remains a schema; it is not silently reinterpreted as a wrapper.
    OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/bare",
            "path_regex": "^/bare$",
            "request_body": {
                "content": {
                    "application/json": {
                        "schema": {"type": "string"}
                    }
                }
            }
        }]
    }))
    .expect("bare schema with custom schema keyword must remain unambiguous");
}

#[tokio::test]
async fn urlencoded_encoding_explode_false_splits_comma_delimited_arrays() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/tags",
            "path_regex": "^/tags$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["tags"],
                            "properties": {
                                "tags": {
                                    "type": "array",
                                    "minItems": 2,
                                    "items": {"type": "string"}
                                }
                            }
                        },
                        "encoding": {
                            "tags": {"style": "form", "explode": false}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/tags");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"tags=red,green",
            )
            .await,
    );
}

#[tokio::test]
async fn urlencoded_space_and_pipe_delimited_arrays() {
    for (style, body) in [
        ("spaceDelimited", "tags=red%20green"),
        ("pipeDelimited", "tags=red%7Cgreen"),
    ] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/tags",
                "path_regex": "^/tags$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {
                                "type": "object",
                                "required": ["tags"],
                                "properties": {
                                    "tags": {
                                        "type": "array",
                                        "minItems": 2,
                                        "items": {"type": "string"}
                                    }
                                }
                            },
                            "encoding": {
                                "tags": {"style": style, "explode": false}
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let mut ctx = post_ctx("/tags");
        ctx.headers = content_type_headers("application/x-www-form-urlencoded");
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &content_type_headers("application/x-www-form-urlencoded"),
                    body.as_bytes(),
                )
                .await,
        );
    }
}

#[tokio::test]
async fn urlencoded_allow_reserved_controls_literal_reserved_bytes() {
    for (allow_reserved, body, expected_status) in [
        (true, "url=https://example.test/a?x=1", None),
        (false, "url=https://example.test/a?x=1", Some(400)),
        (false, "url=https%3A%2F%2Fexample.test%2Fa%3Fx%3D1", None),
    ] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/reserved",
                "path_regex": "^/reserved$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {
                                "type": "object",
                                "required": ["url"],
                                "properties": {"url": {"type": "string", "format": "uri"}}
                            },
                            "encoding": {
                                "url": {"style": "form", "allowReserved": allow_reserved}
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let headers = content_type_headers("application/x-www-form-urlencoded");
        let mut ctx = post_ctx("/reserved");
        ctx.headers = headers.clone();
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await;
        match expected_status {
            Some(status) => assert_reject(result, Some(status)),
            None => assert_continue(result),
        }
    }
}

#[tokio::test]
async fn urlencoded_deep_object_encoding_rebuilds_objects() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/color",
            "path_regex": "^/color$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["color"],
                            "properties": {
                                "color": {
                                    "type": "object",
                                    "required": ["R", "G"],
                                    "properties": {
                                        "R": {"type": "integer"},
                                        "G": {"type": "integer"}
                                    }
                                }
                            }
                        },
                        "encoding": {
                            "color": {"style": "deepObject", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/color");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"color[R]=100&color[G]=200",
            )
            .await,
    );
}

#[tokio::test]
async fn urlencoded_form_object_encoding_honors_explode_modes() {
    for (explode, body) in [(true, "R=100&G=200"), (false, "color=R,100,G,200")] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/color",
                "path_regex": "^/color$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {
                                "type": "object",
                                "required": ["color"],
                                "additionalProperties": false,
                                "properties": {
                                    "color": {
                                        "type": "object",
                                        "required": ["R", "G"],
                                        "additionalProperties": false,
                                        "properties": {
                                            "R": {"type": "integer", "const": 100},
                                            "G": {"type": "integer", "const": 200}
                                        }
                                    }
                                }
                            },
                            "encoding": {
                                "color": {"style": "form", "explode": explode}
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let headers = content_type_headers("application/x-www-form-urlencoded");
        let mut ctx = post_ctx("/color");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
        );
    }
}

#[tokio::test]
async fn urlencoded_explode_false_splits_before_percent_decoding() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/tags",
            "path_regex": "^/tags$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["tags"],
                            "properties": {
                                "tags": {
                                    "type": "array",
                                    "const": ["red,green", "blue"],
                                    "items": {"type": "string"}
                                }
                            }
                        },
                        "encoding": {
                            "tags": {"style": "form", "explode": false}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/x-www-form-urlencoded");
    let mut ctx = post_ctx("/tags");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"tags=red%2Cgreen,blue")
            .await,
    );
}

#[tokio::test]
async fn urlencoded_composed_oneof_is_branch_order_invariant() {
    for branches in [
        json!([{"type": "integer"}, {"type": "string", "pattern": "^[a-z]+$"}]),
        json!([{"type": "string", "pattern": "^[a-z]+$"}, {"type": "integer"}]),
    ] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/value",
                "path_regex": "^/value$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "type": "object",
                            "required": ["value"],
                            "properties": {
                                "value": {"oneOf": branches}
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let mut ctx = post_ctx("/value");
        ctx.headers = content_type_headers("application/x-www-form-urlencoded");
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &content_type_headers("application/x-www-form-urlencoded"),
                    b"value=abc",
                )
                .await,
        );
    }
}

#[tokio::test]
async fn urlencoded_composed_scalar_tries_later_valid_representation() {
    for branches in [
        json!([
            {"type": "integer", "minimum": 100},
            {"type": "string", "pattern": "^[0-9]+$"}
        ]),
        json!([
            {"type": "string", "pattern": "^[0-9]+$"},
            {"type": "integer", "minimum": 100}
        ]),
    ] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/constrained",
                "path_regex": "^/constrained$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "type": "object",
                            "required": ["value"],
                            "properties": {"value": {"oneOf": branches}}
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let mut ctx = post_ctx("/constrained");
        ctx.headers = content_type_headers("application/x-www-form-urlencoded");
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &content_type_headers("application/x-www-form-urlencoded"),
                    b"value=42",
                )
                .await,
        );
    }
}

#[tokio::test]
async fn urlencoded_nested_nullable_composition_uses_text_branch() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/nullable",
            "path_regex": "^/nullable$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "type": "object",
                        "required": ["value"],
                        "properties": {
                            "value": {
                                "allOf": [{
                                    "anyOf": [
                                        {"type": "null"},
                                        {"type": "string", "minLength": 1}
                                    ]
                                }]
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/nullable");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"value=present",
            )
            .await,
    );
}

#[tokio::test]
async fn urlencoded_allof_merges_object_property_types() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/profile",
            "path_regex": "^/profile$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "allOf": [
                            {
                                "type": "object",
                                "properties": {"name": {"type": "string"}}
                            },
                            {
                                "type": "object",
                                "required": ["age"],
                                "properties": {"age": {"type": "integer"}}
                            }
                        ]
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut ctx = post_ctx("/profile");
    ctx.headers = content_type_headers("application/x-www-form-urlencoded");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("application/x-www-form-urlencoded"),
                b"name=alice&age=42",
            )
            .await,
    );
}

#[tokio::test]
async fn unsupported_encoding_combinations_fail_at_admission() {
    let err = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/bad",
            "path_regex": "^/bad$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "properties": {"tags": {"type": "array", "items": {"type": "string"}}}
                        },
                        "encoding": {
                            "tags": {"style": "matrix", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .err()
    .expect("unsupported encoding style must fail admission");
    assert!(
        err.contains("unsupported"),
        "matrix style must fail closed, got {err}"
    );

    let err = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/bad",
            "path_regex": "^/bad$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "properties": {"tags": {"type": "array", "items": {"type": "string"}}}
                        },
                        "encoding": {
                            "tags": {"style": "spaceDelimited", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .err()
    .expect("unsupported explode combination must fail admission");
    assert!(
        err.contains("explode=false"),
        "spaceDelimited+explode true must fail, got {err}"
    );

    for (encoding, expected) in [
        (json!({"missing": {"style": "form"}}), "does not name"),
        (json!({"tags": {"style": 7}}), "must be a string"),
        (json!({"tags": {"explode": "yes"}}), "must be a boolean"),
        (
            json!({"tags": {"allowReserved": "yes"}}),
            "must be a boolean",
        ),
    ] {
        let error = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/bad",
                "path_regex": "^/bad$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "tags": {"type": "array", "items": {"type": "string"}}
                                }
                            },
                            "encoding": encoding
                        }
                    }
                }
            }]
        }))
        .err()
        .expect("invalid encoding configuration must fail admission");
        assert!(
            error.contains(expected),
            "invalid encoding must fail with {expected:?}, got {error}"
        );
    }
}

#[tokio::test]
async fn multipart_boundary_like_bytes_inside_part_body_are_preserved() {
    // Mid-part `--abc` must remain payload bytes (not a MIME delimiter line).
    // Length is derived from the payload so the size const cannot drift.
    const PART_CONTENT: &str = "hello--abcworld";
    assert_eq!(PART_CONTENT.len(), 15);
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "object",
                                "required": ["filename", "content", "size"],
                                "properties": {
                                    "filename": {"type": "string", "const": "a.txt"},
                                    "content": {"type": "string", "const": PART_CONTENT},
                                    "size": {"type": "integer", "const": PART_CONTENT.len()}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = format!(
        concat!(
            "--abc\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "{part_content}\r\n",
            "--abc--\r\n"
        ),
        part_content = PART_CONTENT
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                body.as_bytes(),
            )
            .await,
    );
}

#[tokio::test]
async fn multipart_boundary_prefix_line_without_terminator_is_preserved() {
    // A line starting with `--abc` is not a delimiter unless transport-padding
    // and CRLF/LF (or end-of-body) follow the boundary token exactly.
    const PART_CONTENT: &str = "line1\r\n--abcworld\r\nline3";
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "object",
                                "required": ["filename", "content", "size"],
                                "properties": {
                                    "filename": {"type": "string", "const": "a.txt"},
                                    "content": {"type": "string", "const": PART_CONTENT},
                                    "size": {"type": "integer", "const": PART_CONTENT.len()}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = format!(
        concat!(
            "--abc\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "{part_content}\r\n",
            "--abc--\r\n"
        ),
        part_content = PART_CONTENT
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                body.as_bytes(),
            )
            .await,
    );
}

#[tokio::test]
async fn multipart_quoted_filename_with_semicolon_and_escape() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "object",
                                "required": ["filename"],
                                "properties": {
                                    "filename": {"type": "string", "const": "a;b\"c.txt"}
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
        "Content-Disposition: form-data; name=\"file\"; filename=\"a;b\\\"c.txt\"\r\n",
        "Content-Type: text/plain\r\n\r\n",
        "hello\r\n",
        "--abc--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
    assert_continue(
        plugin
            .on_final_request_body_with_context(
                &mut ctx,
                &content_type_headers("multipart/form-data; boundary=abc"),
                body.as_bytes(),
            )
            .await,
    );
}

#[tokio::test]
async fn multipart_quoted_boundary_parameter_and_encoding_content_type() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["file"],
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "format": "binary",
                                    "minLength": 4
                                }
                            }
                        },
                        "encoding": {
                            "file": {"contentType": "application/pdf"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "------=_Part_0\r\n",
        "Content-Disposition: form-data; name=\"file\"; filename=\"doc.pdf\"\r\n",
        "Content-Type: application/pdf\r\n\r\n",
        "%PDF\r\n",
        "------=_Part_0--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    let headers = content_type_headers("multipart/form-data; boundary=\"----=_Part_0\"");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );

    let bad = body.replace("application/pdf", "text/plain");
    let mut ctx = post_ctx("/upload");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, bad.as_bytes())
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn multipart_encoding_headers_use_full_json_schema_validation() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/header",
            "path_regex": "^/header$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["title"],
                            "properties": {"title": {"type": "string"}}
                        },
                        "encoding": {
                            "title": {
                                "headers": {
                                    "X-Part-Token": {
                                        "schema": {"type": "string", "minLength": 5}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    for (token, expected_status) in [("abcde", None), ("abc", Some(400))] {
        let body = format!(
            "--abc\r\nContent-Disposition: form-data; name=\"title\"\r\nX-Part-Token: {token}\r\n\r\nhello\r\n--abc--\r\n"
        );
        let mut ctx = post_ctx("/header");
        ctx.headers = headers.clone();
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await;
        match expected_status {
            Some(status) => assert_reject(result, Some(status)),
            None => assert_continue(result),
        }
    }
}

#[tokio::test]
async fn multipart_encoding_headers_respect_header_object_required_default() {
    for (required, include_header, expected_status) in [
        (None, false, None),
        (Some(false), false, None),
        (Some(true), false, Some(400)),
        (Some(true), true, None),
    ] {
        let mut header_object = json!({
            "schema": {"type": "string", "minLength": 5}
        });
        if let Some(required) = required {
            header_object["required"] = json!(required);
        }
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/optional-header",
                "path_regex": "^/optional-header$",
                "request_body": {
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "required": ["title"],
                                "properties": {"title": {"type": "string"}}
                            },
                            "encoding": {
                                "title": {
                                    "headers": {"X-Part-Token": header_object}
                                }
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let optional_header = if include_header {
            "X-Part-Token: abcde\r\n"
        } else {
            ""
        };
        let body = format!(
            "--abc\r\nContent-Disposition: form-data; name=\"title\"\r\n{optional_header}\r\nhello\r\n--abc--\r\n"
        );
        let headers = content_type_headers("multipart/form-data; boundary=abc");
        let mut ctx = post_ctx("/optional-header");
        ctx.headers = headers.clone();
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await;
        match expected_status {
            Some(status) => assert_reject(result, Some(status)),
            None => assert_continue(result),
        }
    }
}

#[tokio::test]
async fn multipart_encoding_bare_schema_headers_remain_required() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/bare-required-header",
            "path_regex": "^/bare-required-header$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["title"],
                            "properties": {"title": {"type": "string"}}
                        },
                        "encoding": {
                            "title": {
                                "headers": {
                                    "X-Part-Token": {"type": "string", "minLength": 5}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let body =
        "--abc\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--abc--\r\n";
    let mut ctx = post_ctx("/bare-required-header");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(400),
    );
}

#[test]
fn multipart_encoding_header_bare_object_schema_is_not_a_header_object_wrapper() {
    OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/bare-header-schema",
            "path_regex": "^/bare-header-schema$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}}
                        },
                        "encoding": {
                            "title": {
                                "headers": {
                                    "X-Part-Metadata": {
                                        "type": "object",
                                        "description": "internal bare-schema form",
                                        "required": ["kind"],
                                        "properties": {"kind": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .expect("bare JSON Schema keywords must not be mistaken for a Header Object wrapper");
}

#[tokio::test]
async fn multipart_composed_anyof_scalar_is_branch_order_invariant() {
    for branches in [
        json!([{"type": "integer"}, {"type": "string", "pattern": "^[a-z]+$"}]),
        json!([{"type": "string", "pattern": "^[a-z]+$"}, {"type": "integer"}]),
    ] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/value",
                "path_regex": "^/value$",
                "request_body": {
                    "content": {
                        "multipart/form-data": {
                            "type": "object",
                            "required": ["value"],
                            "properties": {
                                "value": {"anyOf": branches}
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let body = concat!(
            "--abc\r\n",
            "Content-Disposition: form-data; name=\"value\"\r\n\r\n",
            "abc\r\n",
            "--abc--\r\n"
        );
        let mut ctx = post_ctx("/value");
        ctx.headers = content_type_headers("multipart/form-data; boundary=abc");
        assert_continue(
            plugin
                .on_final_request_body_with_context(
                    &mut ctx,
                    &content_type_headers("multipart/form-data; boundary=abc"),
                    body.as_bytes(),
                )
                .await,
        );
    }
}

#[tokio::test]
async fn multipart_form_object_encoding_honors_explode_modes() {
    for (explode, body) in [
        (
            true,
            concat!(
                "--abc\r\n",
                "Content-Disposition: form-data; name=\"R\"\r\n\r\n",
                "100\r\n",
                "--abc\r\n",
                "Content-Disposition: form-data; name=\"G\"\r\n\r\n",
                "200\r\n",
                "--abc--\r\n"
            ),
        ),
        (
            false,
            concat!(
                "--abc\r\n",
                "Content-Disposition: form-data; name=\"color\"\r\n\r\n",
                "R,100,G,200\r\n",
                "--abc--\r\n"
            ),
        ),
    ] {
        let plugin = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/color",
                "path_regex": "^/color$",
                "request_body": {
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "required": ["color"],
                                "additionalProperties": false,
                                "properties": {
                                    "color": {
                                        "type": "object",
                                        "required": ["R", "G"],
                                        "additionalProperties": false,
                                        "properties": {
                                            "R": {"type": "integer", "const": 100},
                                            "G": {"type": "integer", "const": 200}
                                        }
                                    }
                                }
                            },
                            "encoding": {
                                "color": {"style": "form", "explode": explode}
                            }
                        }
                    }
                }
            }]
        }))
        .unwrap();
        let headers = content_type_headers("multipart/form-data; boundary=abc");
        let mut ctx = post_ctx("/color");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
        );
    }
}

#[tokio::test]
async fn multipart_rejects_invalid_boundary_and_duplicate_headers() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "properties": {"title": {"type": "string"}}
                    }
                }
            }
        }]
    }))
    .unwrap();

    let mut ctx = post_ctx("/upload");
    let headers = content_type_headers("multipart/form-data; boundary=\"bad boundary\"");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"--bad boundary--\r\n")
            .await,
        Some(400),
    );

    let long_boundary = "a".repeat(71);
    let long_content_type = format!("multipart/form-data; boundary={long_boundary}");
    let headers = content_type_headers(&long_content_type);
    let mut ctx = post_ctx("/upload");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"ignored")
            .await,
        Some(400),
    );

    let body = concat!(
        "--abc\r\n",
        "Content-Disposition: form-data; name=\"title\"\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Type: text/html\r\n\r\n",
        "x\r\n",
        "--abc--\r\n"
    );
    let mut ctx = post_ctx("/upload");
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("duplicate header"),
        "duplicate headers must fail closed, got {:?}",
        request_error(&ctx)
    );
}

#[tokio::test]
async fn multipart_accepts_preamble_epilogue_and_lf_delimiters() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/mime",
            "path_regex": "^/mime$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["title"],
                        "properties": {"title": {"type": "string", "const": "hello"}}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = b"preamble\r\n--abc\nContent-Disposition: form-data; name=\"title\"\n\nhello\n--abc--\nepilogue";
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let mut ctx = post_ctx("/mime");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn multipart_rejects_missing_close_empty_parts_and_duplicate_parameters() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/mime",
            "path_regex": "^/mime$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "properties": {"title": {"type": "string"}}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    for body in [
        "--abc\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello",
        "--abc\r\n--abc--\r\n",
        "--abc\r\nContent-Disposition: form-data; name=\"title\"; name=\"other\"\r\n\r\nhello\r\n--abc--\r\n",
    ] {
        let mut ctx = post_ctx("/mime");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
            Some(400),
        );
    }
}

#[tokio::test]
async fn multipart_preserves_non_utf8_file_bytes_for_metadata_validation() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/binary",
            "path_regex": "^/binary$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "object",
                                "required": ["filename", "size"],
                                "properties": {
                                    "filename": {"const": "raw.bin"},
                                    "size": {"const": 3}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let mut body =
        b"--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"raw.bin\"\r\n\r\n"
            .to_vec();
    body.extend_from_slice(&[0, 0xff, 1]);
    body.extend_from_slice(b"\r\n--abc--\r\n");
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let mut ctx = post_ctx("/binary");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &body)
            .await,
    );
}

#[test]
fn composed_scalar_validators_are_precompiled_outside_request_conversion() {
    let source = include_str!("../../../src/plugins/openapi_validator.rs");
    assert_eq!(
        source.matches("jsonschema::validator_for(schema)").count(),
        1,
        "validator construction must stay inside the schema-draft compiler"
    );
    assert!(source.contains("composed_scalar_validators"));
    assert!(source.contains("ConversionPlan::compile"));
}

#[tokio::test]
async fn urlencoded_without_encoding_object_keeps_legacy_lenient_values() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/legacy-form",
            "path_regex": "^/legacy-form$",
            "request_body": {"content": {
                "application/x-www-form-urlencoded": {
                    "type": "object",
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}}
                }
            }}
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/x-www-form-urlencoded");
    for body in ["value=abc==", "value=https://example.com/a?b", "value=50%"] {
        let mut ctx = post_ctx("/legacy-form");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
        );
    }
}

#[test]
fn response_media_type_encoding_wrapper_is_rejected() {
    let error = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "GET",
            "path_template": "/response",
            "path_regex": "^/response$",
            "responses": {"200": {"content": {
                "application/json": {
                    "schema": {"type": "object"},
                    "encoding": {}
                }
            }}}
        }]
    }))
    .err()
    .expect("response Encoding Objects must fail admission");
    assert!(error.contains("must not contain an Encoding Object"));
}

#[tokio::test]
async fn multipart_accepts_quoted_boundary_with_interior_space() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/space-boundary",
            "path_regex": "^/space-boundary$",
            "request_body": {"content": {"multipart/form-data": {
                "type": "object",
                "required": ["title"],
                "properties": {"title": {"const": "hello"}}
            }}}
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=\"a b\"");
    let body =
        b"--a b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--a b--\r\n";
    let mut ctx = post_ctx("/space-boundary");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
    );

    let trailing = content_type_headers("multipart/form-data; boundary=\"a \"");
    let mut ctx = post_ctx("/space-boundary");
    ctx.headers = trailing.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &trailing, body)
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn multipart_encoding_content_type_accepts_any_wildcard() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/wildcard",
            "path_regex": "^/wildcard$",
            "request_body": {"content": {"multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {"file": {"type": "string", "format": "binary"}}
                },
                "encoding": {"file": {"contentType": "*/*"}}
            }}}
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let body = b"--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--abc--\r\n";
    let mut ctx = post_ctx("/wildcard");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn multipart_empty_header_block_does_not_promote_body_lines() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/empty-headers",
            "path_regex": "^/empty-headers$",
            "request_body": {"content": {"multipart/form-data": {
                "type": "object",
                "properties": {"title": {"type": "string"}}
            }}}
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=abc");
    let body =
        b"--abc\r\n\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--abc--\r\n";
    let mut ctx = post_ctx("/empty-headers");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn explode_false_arrays_require_one_serialized_property_occurrence() {
    let form = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/form-array",
            "path_regex": "^/form-array$",
            "request_body": {"content": {"application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {"tags": {"type": "array", "items": {"type": "string"}}}
                },
                "encoding": {"tags": {"style": "form", "explode": false}}
            }}}
        }]
    }))
    .unwrap();
    let form_headers = content_type_headers("application/x-www-form-urlencoded");
    let mut ctx = post_ctx("/form-array");
    ctx.headers = form_headers.clone();
    assert_reject(
        form.on_final_request_body_with_context(&mut ctx, &form_headers, b"tags=a,b&tags=c")
            .await,
        Some(400),
    );

    let multipart = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/multipart-array",
            "path_regex": "^/multipart-array$",
            "request_body": {"content": {"multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {"tags": {"type": "array", "items": {"type": "string"}}}
                },
                "encoding": {"tags": {"style": "form", "explode": false}}
            }}}
        }]
    }))
    .unwrap();
    let multipart_headers = content_type_headers("multipart/form-data; boundary=abc");
    let body = b"--abc\r\nContent-Disposition: form-data; name=\"tags\"\r\n\r\na,b\r\n--abc\r\nContent-Disposition: form-data; name=\"tags\"\r\n\r\nc\r\n--abc--\r\n";
    let mut ctx = post_ctx("/multipart-array");
    ctx.headers = multipart_headers.clone();
    assert_reject(
        multipart
            .on_final_request_body_with_context(&mut ctx, &multipart_headers, body)
            .await,
        Some(400),
    );
}

#[tokio::test]
async fn multipart_chooses_earliest_header_body_separator_over_later_crlf() {
    // Hostile case from #3015: LF-LF terminates headers first; a later CRLF-CRLF
    // in the body must not reclassify body bytes as part headers.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/payload",
            "path_regex": "^/payload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["payload"],
                        "properties": {
                            "payload": {"type": "string", "const": "safe"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = b"--b\r\nContent-Disposition: form-data; name=\"payload\"\n\nX-Reclassified: attacker-controlled\r\n\r\nsafe\r\n--b--\r\n";
    let headers = content_type_headers("multipart/form-data; boundary=b");
    let mut ctx = post_ctx("/payload");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
        Some(400),
    );
    let err = request_error(&ctx).unwrap_or_default();
    assert!(
        !err.contains("duplicate header"),
        "body prefix must remain body bytes, not reclassified headers: {err}"
    );

    // Valid LF-only and CRLF-only parts still accept.
    for body in [
        &b"--b\nContent-Disposition: form-data; name=\"payload\"\n\nsafe\n--b--\n"[..],
        &b"--b\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\nsafe\r\n--b--\r\n"[..],
    ] {
        let mut ctx = post_ctx("/payload");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body)
                .await,
        );
    }
}

#[tokio::test]
async fn multipart_rejects_unquoted_boundary_values_that_require_quoting() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["title"],
                        "properties": {"title": {"type": "string", "const": "ok"}}
                    }
                }
            }
        }]
    }))
    .unwrap();

    for (content_type, body) in [
        (
            "multipart/form-data; boundary=abc:def",
            &b"--abc:def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc:def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=abc/def",
            &b"--abc/def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc/def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=abc?def",
            &b"--abc?def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc?def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=abc=def",
            &b"--abc=def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc=def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=abc,def",
            &b"--abc,def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc,def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=abc(def)",
            &b"--abc(def)\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc(def)--\r\n"[..],
        ),
    ] {
        let headers = content_type_headers(content_type);
        let mut ctx = post_ctx("/upload");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body)
                .await,
            Some(400),
        );
        assert!(
            request_error(&ctx)
                .unwrap_or_default()
                .contains("Unquoted multipart boundary"),
            "unquoted non-token boundary must fail closed, got {:?}",
            request_error(&ctx)
        );
    }

    // Same values are accepted when correctly quoted.
    for (content_type, body) in [
        (
            "multipart/form-data; boundary=\"abc:def\"",
            &b"--abc:def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc:def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=\"abc def\"",
            &b"--abc def\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--abc def--\r\n"[..],
        ),
        (
            "multipart/form-data; boundary=simpleToken",
            &b"--simpleToken\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nok\r\n--simpleToken--\r\n"[..],
        ),
    ] {
        let headers = content_type_headers(content_type);
        let mut ctx = post_ctx("/upload");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body)
                .await,
        );
    }
}

#[tokio::test]
async fn multipart_requires_form_data_content_disposition_type() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/role",
            "path_regex": "^/role$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["role"],
                        "properties": {"role": {"type": "string", "const": "user"}}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=b");

    for disposition in ["attachment", "inline", "", "form-datax"] {
        let body = format!(
            "--b\r\nContent-Disposition: {disposition}; name=\"role\"\r\n\r\nuser\r\n--b--\r\n"
        );
        let mut ctx = post_ctx("/role");
        ctx.headers = headers.clone();
        assert_reject(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
            Some(400),
        );
        assert!(
            request_error(&ctx)
                .unwrap_or_default()
                .contains("Content-Disposition type must be form-data"),
            "non-form disposition must not reach schema conversion, got {:?}",
            request_error(&ctx)
        );
    }

    for disposition in ["form-data", "Form-Data", "FORM-DATA"] {
        let body = format!(
            "--b\r\nContent-Disposition: {disposition}; name=\"role\"\r\n\r\nuser\r\n--b--\r\n"
        );
        let mut ctx = post_ctx("/role");
        ctx.headers = headers.clone();
        assert_continue(
            plugin
                .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
                .await,
        );
    }
}

#[tokio::test]
async fn multipart_and_urlencoded_reject_duplicate_scalar_values() {
    let multipart = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/role",
            "path_regex": "^/role$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["role"],
                        "properties": {"role": {"type": "string", "const": "user"}}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=b");
    // First-win hostile body: validator must not accept by reading only "user".
    let body = concat!(
        "--b\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n",
        "--b\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n",
        "--b--\r\n"
    );
    let mut ctx = post_ctx("/role");
    ctx.headers = headers.clone();
    assert_reject(
        multipart
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("expects a scalar"),
        "duplicate scalar multipart values must reject, got {:?}",
        request_error(&ctx)
    );

    // Last-win hostile ordering is also rejected.
    let body = concat!(
        "--b\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n",
        "--b\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n",
        "--b--\r\n"
    );
    let mut ctx = post_ctx("/role");
    ctx.headers = headers.clone();
    assert_reject(
        multipart
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(400),
    );

    // Duplicate scalar file metadata objects are rejected the same way.
    let file_plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/file",
            "path_regex": "^/file$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "object",
                                "required": ["filename"],
                                "properties": {"filename": {"const": "a.txt"}}
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nx\r\n",
        "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\ny\r\n",
        "--b--\r\n"
    );
    let mut ctx = post_ctx("/file");
    ctx.headers = headers.clone();
    assert_reject(
        file_plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
        Some(400),
    );

    // Array fields still preserve every value in order.
    let array_plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/tags",
            "path_regex": "^/tags$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["tags"],
                        "properties": {
                            "tags": {
                                "type": "array",
                                "const": ["a", "b"]
                            }
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let body = concat!(
        "--b\r\nContent-Disposition: form-data; name=\"tags\"\r\n\r\na\r\n",
        "--b\r\nContent-Disposition: form-data; name=\"tags\"\r\n\r\nb\r\n",
        "--b--\r\n"
    );
    let mut ctx = post_ctx("/tags");
    ctx.headers = headers.clone();
    assert_continue(
        array_plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );

    // URL-encoded scalars follow the same schema-driven duplicate rule.
    let form = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/role-form",
            "path_regex": "^/role-form$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "type": "object",
                        "required": ["role"],
                        "properties": {"role": {"type": "string", "const": "user"}}
                    }
                }
            }
        }]
    }))
    .unwrap();
    let form_headers = content_type_headers("application/x-www-form-urlencoded");
    let mut ctx = post_ctx("/role-form");
    ctx.headers = form_headers.clone();
    assert_reject(
        form.on_final_request_body_with_context(&mut ctx, &form_headers, b"role=user&role=admin")
            .await,
        Some(400),
    );
    assert!(
        request_error(&ctx)
            .unwrap_or_default()
            .contains("Repeated form field values"),
        "duplicate scalar urlencoded values must reject, got {:?}",
        request_error(&ctx)
    );
}

#[test]
fn exploded_object_key_collisions_are_rejected_for_form_and_multipart() {
    for media_type in ["application/x-www-form-urlencoded", "multipart/form-data"] {
        let root_child = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/claims",
                "path_regex": "^/claims$",
                "request_body": {
                    "content": {
                        (media_type): {
                            "schema": {
                                "type": "object",
                                "required": ["tenant", "claims"],
                                "properties": {
                                    "tenant": {"type": "string"},
                                    "claims": {
                                        "type": "object",
                                        "properties": {
                                            "tenant": {"type": "string"}
                                        }
                                    }
                                }
                            },
                            "encoding": {
                                "claims": {"style": "form", "explode": true}
                            }
                        }
                    }
                }
            }]
        }));
        let error = match root_child {
            Ok(_) => panic!("{media_type}: root/child collision must fail admission"),
            Err(error) => error,
        };
        assert!(
            error.contains("collides with a root request-body property"),
            "{media_type}: unexpected admission error: {error}"
        );

        let child_child = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/overlap",
                "path_regex": "^/overlap$",
                "request_body": {
                    "content": {
                        (media_type): {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "left": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "properties": {"shared": {"type": "string"}}
                                    },
                                    "right": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "properties": {"shared": {"type": "string"}}
                                    }
                                }
                            },
                            "encoding": {
                                "left": {"style": "form", "explode": true},
                                "right": {"style": "form", "explode": true}
                            }
                        }
                    }
                }
            }]
        }));
        let error = match child_child {
            Ok(_) => panic!("{media_type}: child/child collision must fail admission"),
            Err(error) => error,
        };
        assert!(
            error.contains("emit colliding child keys"),
            "{media_type}: unexpected admission error: {error}"
        );
    }
}

#[tokio::test]
async fn non_overlapping_exploded_objects_convert_one_wire_key_to_one_property() {
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/colors",
            "path_regex": "^/colors$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["rgb", "alpha"],
                            "additionalProperties": false,
                            "properties": {
                                "rgb": {
                                    "type": "object",
                                    "required": ["R", "G"],
                                    "additionalProperties": false,
                                    "properties": {
                                        "R": {"type": "integer", "const": 1},
                                        "G": {"type": "integer", "const": 2}
                                    }
                                },
                                "alpha": {
                                    "type": "object",
                                    "required": ["A"],
                                    "additionalProperties": false,
                                    "properties": {
                                        "A": {"type": "integer", "const": 3}
                                    }
                                }
                            }
                        },
                        "encoding": {
                            "rgb": {"style": "form", "explode": true},
                            "alpha": {"style": "form", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("application/x-www-form-urlencoded");
    let mut ctx = post_ctx("/colors");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"R=1&G=2&A=3")
            .await,
    );

    let multipart = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/colors-mp",
            "path_regex": "^/colors-mp$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["rgb", "alpha"],
                            "additionalProperties": false,
                            "properties": {
                                "rgb": {
                                    "type": "object",
                                    "required": ["R", "G"],
                                    "additionalProperties": false,
                                    "properties": {
                                        "R": {"type": "integer", "const": 1},
                                        "G": {"type": "integer", "const": 2}
                                    }
                                },
                                "alpha": {
                                    "type": "object",
                                    "required": ["A"],
                                    "additionalProperties": false,
                                    "properties": {
                                        "A": {"type": "integer", "const": 3}
                                    }
                                }
                            }
                        },
                        "encoding": {
                            "rgb": {"style": "form", "explode": true},
                            "alpha": {"style": "form", "explode": true}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=b");
    let body = concat!(
        "--b\r\nContent-Disposition: form-data; name=\"R\"\r\n\r\n1\r\n",
        "--b\r\nContent-Disposition: form-data; name=\"G\"\r\n\r\n2\r\n",
        "--b\r\nContent-Disposition: form-data; name=\"A\"\r\n\r\n3\r\n",
        "--b--\r\n"
    );
    let mut ctx = post_ctx("/colors-mp");
    ctx.headers = headers.clone();
    assert_continue(
        multipart
            .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
            .await,
    );
}

#[tokio::test]
async fn multipart_earliest_separator_rejects_mixed_lf_crlf_blank_line() {
    // Residual of #3015: a header block that ends with an LF line followed by a
    // CRLF blank line (`...name"\n\r\n...`) matches neither `\n\n` nor
    // `\r\n\r\n`. Recognizing only those two patterns lets a later `\r\n\r\n`
    // win, promoting the intervening `X-Reclassified` line into part headers.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/payload",
            "path_regex": "^/payload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "type": "object",
                        "required": ["payload"],
                        "properties": {
                            "payload": {"type": "string", "const": "safe"}
                        }
                    }
                }
            }
        }]
    }))
    .unwrap();
    let headers = content_type_headers("multipart/form-data; boundary=b");

    // The mixed `\n\r\n` blank line must be the header/body separator, so the
    // `X-Reclassified` line stays body bytes and the const check sees the whole
    // smuggled prefix rather than a bare "safe".
    let body = b"--b\r\nContent-Disposition: form-data; name=\"payload\"\n\r\nX-Reclassified: attacker-controlled\r\n\r\nsafe\r\n--b--\r\n";
    let mut ctx = post_ctx("/payload");
    ctx.headers = headers.clone();
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
        Some(400),
    );
    let err = request_error(&ctx).unwrap_or_default();
    assert!(
        !err.contains("duplicate header"),
        "body prefix must remain body bytes, not reclassified headers: {err}"
    );

    // A part that legitimately uses the mixed `\n\r\n` blank line as its sole
    // header/body separator still parses, with the body consumed correctly.
    let body = b"--b\r\nContent-Disposition: form-data; name=\"payload\"\n\r\nsafe\r\n--b--\r\n";
    let mut ctx = post_ctx("/payload");
    ctx.headers = headers.clone();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await,
    );
}

#[test]
fn exploded_free_form_object_cannot_coexist_with_declared_exploded_object() {
    // Residual of #3019: admission rejects two free-form exploded objects and
    // declared-child collisions, but a single free-form object coexisting with a
    // declared exploded object was admitted. At runtime the free-form object
    // absorbs the declared object's child keys, so one wire occurrence populates
    // two logical properties depending on declaration order. Fail closed instead.
    for media_type in ["application/x-www-form-urlencoded", "multipart/form-data"] {
        let result = OpenapiValidator::new(&json!({
            "operations": [{
                "method": "POST",
                "path_template": "/mix",
                "path_regex": "^/mix$",
                "request_body": {
                    "content": {
                        (media_type): {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "freeform": {
                                        "type": "object",
                                        "additionalProperties": {"type": "string"}
                                    },
                                    "declared": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "properties": {"x": {"type": "string"}}
                                    }
                                }
                            },
                            "encoding": {
                                "freeform": {"style": "form", "explode": true},
                                "declared": {"style": "form", "explode": true}
                            }
                        }
                    }
                }
            }]
        }));
        let error = match result {
            Ok(_) => {
                panic!("{media_type}: free-form + declared exploded objects must fail admission")
            }
            Err(error) => error,
        };
        assert!(
            error.contains("free-form object") && error.contains("cannot coexist"),
            "{media_type}: unexpected admission error: {error}"
        );
    }

    // A lone free-form exploded object (no other exploded object) still admits.
    let plugin = OpenapiValidator::new(&json!({
        "operations": [{
            "method": "POST",
            "path_template": "/labels",
            "path_regex": "^/labels$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "required": ["labels"],
                            "additionalProperties": false,
                            "properties": {
                                "labels": {
                                    "type": "object",
                                    "additionalProperties": {"type": "integer"}
                                }
                            }
                        },
                        "encoding": {
                            "labels": {"style": "form", "explode": true}
                        }
                    }
                }
            }
        }]
    }));
    assert!(
        plugin.is_ok(),
        "a lone free-form exploded object must remain valid: {:?}",
        plugin.err()
    );
}
