//! Tests for body_validator plugin — XML CDATA, comments, processing instructions

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugins::body_validator::{
    BODY_VALIDATOR_CONFIG_KEYS, BODY_VALIDATOR_PROTOBUF_METHOD_KEYS, BodyValidator,
};
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject};

fn body_validator_plugin_config(
    id: &str,
    enabled: bool,
    config: serde_json::Value,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: "body_validator".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_xml_ctx(body: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/xml".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/xml".to_string());
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    ctx
}

fn make_xml_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/xml".to_string());
    headers
}

fn make_json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

fn xml_plugin() -> BodyValidator {
    BodyValidator::new(&json!({
        "validate_xml": true
    }))
    .unwrap()
}

fn xml_plugin_with_required(elements: Vec<&str>) -> BodyValidator {
    BodyValidator::new(&json!({
        "validate_xml": true,
        "required_xml_elements": elements
    }))
    .unwrap()
}

#[test]
fn test_plugin_metadata_and_protocol_scope() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    assert_eq!(plugin.name(), "body_validator");
    assert_eq!(plugin.priority(), priority::BODY_VALIDATOR);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_invalid_config_shapes_rejected() {
    for config in [
        json!("bad"),
        json!({"json_schema": {}}),
        json!({"json_schema": true}),
        json!({"json_schema": {"type": "string", "pattern": "["}}),
        json!({"required_fields": "name"}),
        json!({"required_fields": ["name", 123]}),
        json!({"required_fields": [""]}),
        json!({"validate_xml": "true"}),
        json!({"required_xml_elements": [123]}),
        json!({"content_types": "application/json"}),
        json!({"content_types": ["application/json", 123]}),
        json!({"grpc_max_decompressed_size_bytes": "10"}),
        json!({"response_json_schema": false}),
        json!({"response_json_schema": {"type": "string", "pattern": "["}}),
        json!({"response_required_fields": [false]}),
        json!({"response_validate_xml": "false"}),
        json!({"response_content_types": [""]}),
        json!({"protobuf_descriptor_path": 42}),
        json!({"protobuf_request_type": "test.HelloRequest"}),
        json!({"protobuf_reject_unknown_fields": "true"}),
        json!({
            "protobuf_descriptor_path": test_descriptor_path(),
            "protobuf_method_messages": []
        }),
        json!({
            "protobuf_descriptor_path": test_descriptor_path(),
            "protobuf_method_messages": {
                "/test.Greeter/SayHello": {}
            }
        }),
    ] {
        let result = BodyValidator::new(&config);
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_request_vs_response_buffering_flags_are_config_sensitive() {
    let request_plugin = BodyValidator::new(&json!({"validate_xml": true})).unwrap();
    assert!(request_plugin.requires_request_body_buffering());
    assert!(!request_plugin.requires_response_body_buffering());

    let response_only = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    assert!(!response_only.requires_request_body_buffering());
    assert!(response_only.requires_response_body_buffering());
}

#[test]
fn test_request_body_buffering_follows_representation_not_method() {
    let plugin = BodyValidator::new(&json!({"validate_xml": true})).unwrap();

    let xml_ctx = make_xml_ctx("<root/>");
    assert!(plugin.should_buffer_request_body(&xml_ctx));

    // GHSA-2vmr-ww8r-mww3: a governed representation must never bypass the
    // validator because of the request method alone.
    for method in [
        "GET", "HEAD", "OPTIONS", "DELETE", "PUT", "PATCH", "PROPFIND",
    ] {
        let mut ctx = make_xml_ctx("<root/>");
        ctx.method = method.to_string();
        assert!(
            plugin.should_buffer_request_body(&ctx),
            "method={method} must still buffer a configured representation"
        );
    }

    let mut json_only_ctx = make_xml_ctx("<root/>");
    json_only_ctx.headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );
    assert!(!plugin.should_buffer_request_body(&json_only_ctx));
}

#[tokio::test]
async fn test_case_insensitive_content_type_is_validated_without_lowercase_copy() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "Application/JSON; Charset=UTF-8".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), r#"{"other": true}"#.to_string());
    assert!(plugin.should_buffer_request_body(&ctx));

    let mut headers = ctx.headers.clone();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// body_validator must match Content-Type by normalized type/subtype only
// (parameters stripped, OWS trimmed, ASCII case-insensitive). Substring
// collisions against neighboring types or parameter values must not activate
// JSON/XML validation. Malformed / empty media-type tokens do not match.

/// Table of (Content-Type, should apply default whitelist validation).
#[test]
fn test_content_type_exact_media_type_matching() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();

    let cases: &[(&str, bool)] = &[
        // Exact configured defaults.
        ("application/json", true),
        ("application/xml", true),
        ("text/xml", true),
        // Case variants.
        ("Application/JSON", true),
        ("APPLICATION/JSON", true),
        ("APPLICATION/XML", true),
        ("Text/XML", true),
        // OWS and parameters are stripped before comparison.
        ("application/json; charset=utf-8", true),
        ("application/json; charset=UTF-8", true),
        ("application/json;charset=utf-8", true),
        ("application/json ; charset=utf-8", true),
        ("application/json\t; charset=utf-8", true),
        (" application/json ", true),
        ("application/xml; charset=utf-8", true),
        ("text/xml; charset=utf-8", true),
        // Neighboring / distinct types must NOT match.
        ("application/json-seq", false),
        ("application/jsonp", false),
        ("application/json-patch+json", false), // not in default list
        ("application/json2", false),
        ("text/xmlish", false),
        ("application/soap+xml", false), // not in default list
        // Parameter values that merely contain a configured string.
        (
            "application/octet-stream; profile=\"application/json\"",
            false,
        ),
        ("application/octet-stream; charset=application/json", false),
        ("text/plain; type=\"application/xml\"", false),
        // Malformed / empty media-type tokens do not match.
        ("", false),
        ("; charset=utf-8", false),
        (" ; charset=utf-8", false),
        (";", false),
        ("\t\n", false),
        ("application", false),
        ("/json", false),
        ("application/", false),
        ("application//json", false),
        ("application json", false),
        ("application/js(on)", false),
        ("application/json\n", false),
        // Unrelated types.
        ("text/plain", false),
        ("application/octet-stream", false),
        ("text/event-stream", false),
    ];

    for (content_type, should_match) in cases {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), (*content_type).to_string());
        let buffered = plugin.should_buffer_request_body(&ctx);
        assert_eq!(
            buffered, *should_match,
            "content_type={content_type:?}: should_buffer_request_body expected {should_match}, got {buffered}",
        );
    }
}

/// Custom content_types lists use the same exact type/subtype semantics.
#[test]
fn test_custom_content_types_exact_media_type_matching() {
    let plugin = BodyValidator::new(&json!({
        "required_fields": ["name"],
        "content_types": ["application/vnd.api+json", "text/csv"]
    }))
    .unwrap();

    let cases: &[(&str, bool)] = &[
        ("application/vnd.api+json", true),
        ("application/vnd.api+json; charset=utf-8", true),
        ("APPLICATION/VND.API+JSON", true),
        ("text/csv", true),
        ("text/csv; charset=us-ascii", true),
        ("application/vnd.api+jsonp", false),
        ("application/vnd.api+json-patch", false),
        ("text/csvp", false),
        (
            "application/octet-stream; profile=\"application/vnd.api+json\"",
            false,
        ),
        // Default JSON is not on the custom list.
        ("application/json", false),
        ("application/json; charset=utf-8", false),
    ];

    for (content_type, should_match) in cases {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), (*content_type).to_string());
        assert_eq!(
            plugin.should_buffer_request_body(&ctx),
            *should_match,
            "content_type={content_type:?}"
        );
    }
}

/// Configured content_types with parameters are normalized to type/subtype;
/// parameter-only and malformed entries are rejected.
#[test]
fn test_configured_content_types_normalize_and_reject_malformed() {
    let plugin = BodyValidator::new(&json!({
        "required_fields": ["name"],
        "content_types": ["application/json; charset=utf-8"]
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));

    for config in [
        json!({"required_fields": ["name"], "content_types": ["; charset=utf-8"]}),
        json!({"required_fields": ["name"], "content_types": [" ; charset=utf-8"]}),
        json!({"response_required_fields": ["id"], "response_content_types": [";"]}),
        json!({"required_fields": ["name"], "content_types": ["application"]}),
        json!({"required_fields": ["name"], "content_types": ["/json"]}),
        json!({"required_fields": ["name"], "content_types": ["application/"]}),
        json!({"required_fields": ["name"], "content_types": ["application//json"]}),
        json!({"required_fields": ["name"], "content_types": ["application json"]}),
        json!({"required_fields": ["name"], "content_types": ["application/js(on)"]}),
        json!({"required_fields": ["name"], "content_types": ["application/json\n"]}),
    ] {
        assert!(
            BodyValidator::new(&config).is_err(),
            "malformed media type must be rejected: {config:?}"
        );
    }
}

/// `application/json-seq` must not activate the single-document JSON validator
/// under the default content_types list (request → Continue, not 400).
#[tokio::test]
async fn test_request_json_seq_neighbor_type_is_not_validated() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    // RFC 7464 JSON text sequence framing — valid for json-seq, not for
    // application/json single-document parsing.
    let json_seq_body = "\u{001e}{\"name\":\"Alice\"}\n";
    ctx.headers.insert(
        "content-type".to_string(),
        "application/json-seq".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), json_seq_body.to_string());
    assert!(!plugin.should_buffer_request_body(&ctx));

    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

/// Parameter collision must not force request validation (Continue, not 400).
#[tokio::test]
async fn test_request_parameter_collision_is_not_validated() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/octet-stream; profile=\"application/json\"".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), "not-json".to_string());
    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

/// Malformed Content-Type is skipped without panic (Continue, not 400).
#[tokio::test]
async fn test_request_malformed_content_type_is_skipped() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    for content_type in [
        "",
        "; charset=utf-8",
        " ; charset=utf-8",
        ";",
        "\t",
        "application",
        "/json",
        "application/",
        "application//json",
        "application json",
        "application/js(on)",
        "application/json\n",
    ] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), content_type.to_string());
        ctx.metadata
            .insert("request_body".to_string(), "not-json".to_string());
        let mut headers = ctx.headers.clone();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    }
}

/// Parameterized application/json still rejects invalid bodies with 400.
#[tokio::test]
async fn test_request_parameterized_json_still_validated_400() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), r#"{"other": true}"#.to_string());
    let mut headers = ctx.headers.clone();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

/// Response path shares exact media-type matching: json-seq is skipped.
#[tokio::test]
async fn test_response_json_seq_neighbor_type_is_not_validated() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/json-seq".to_string(),
    );
    // Record-separator framed body that single-document JSON would reject.
    let body = b"\x1e{\"id\":1}\n";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

/// Response parameter collision must not activate validation.
#[tokio::test]
async fn test_response_parameter_collision_is_not_validated() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/octet-stream; profile=\"application/json\"".to_string(),
    );
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"not-json")
            .await,
    );
}

/// Response malformed Content-Type is skipped (Continue, not 502).
#[tokio::test]
async fn test_response_malformed_content_type_is_skipped() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    for content_type in [
        "",
        "; charset=utf-8",
        " ; charset=utf-8",
        ";",
        "application",
        "application/",
        "application//json",
        "application json",
        "application/json\n",
    ] {
        let mut ctx = make_response_ctx();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), content_type.to_string());
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &headers, b"not-json")
                .await,
        );
    }
}

/// Parameterized application/json on the response path still rejects with 502.
#[tokio::test]
async fn test_response_parameterized_json_still_validated_502() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["id"]
    }));
    let mut ctx = make_response_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, br#"{"name":"x"}"#)
            .await,
        Some(502),
    );
}

/// Structured-suffix JSON types on a custom whitelist dispatch to JSON
/// validation; neighboring non-suffix types do not.
#[tokio::test]
async fn test_json_dispatch_uses_essence_not_substring() {
    let plugin = BodyValidator::new(&json!({
        "required_fields": ["name"],
        "content_types": ["application/vnd.api+json", "application/json-seq"]
    }))
    .unwrap();

    // +json structured suffix → JSON validator → 400 for missing field.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/vnd.api+json".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), r#"{"other": true}"#.to_string());
    let mut headers = ctx.headers.clone();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    // json-seq is on the whitelist so applicability matches, but dispatch must
    // not treat it as single-document JSON (substring "json" is insufficient).
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/json-seq".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        "\u{001e}{\"name\":\"Alice\"}\n".to_string(),
    );
    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[test]
fn test_trait_object_dispatches_request_body_buffering_hooks() {
    let plugin: std::sync::Arc<dyn Plugin> =
        std::sync::Arc::new(BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());

    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.should_buffer_request_body(&ctx));
}

// ─── Basic XML Validation ──────────────────────────────────────────────

#[tokio::test]
async fn test_xml_simple_valid() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item>text</item></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_tag() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// Regression: self-closing tags with whitespace before `/` (`<br />`,
// `<input attr="v" />`, `<foo\n/>`) were previously rejected as unbalanced
// because the `/` detection only looked at the byte immediately before `>`.
#[tokio::test]
async fn test_xml_self_closing_with_space_before_slash() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br /></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_with_attr_and_whitespace() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx(r#"<root><img src="x.png" alt="" /></root>"#);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_with_newline_before_slash() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br\n/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_self_closing_with_tab_before_slash() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><br\t/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_unbalanced_tags_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_mismatched_tag_names_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><a></b></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// The unbalanced/mismatched tests above both land on the mismatched-tag
// branch (pop returns a non-matching name). These pin the two other
// structural error branches the parser introduces.

#[tokio::test]
async fn test_xml_unclosed_root_rejected() {
    // Stack non-empty at EOF with no mismatch: `item` opens and closes
    // cleanly, but `root` is never closed → "Unclosed XML tag".
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><item></item>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_unexpected_closing_tag_rejected() {
    // A closing tag with an empty stack → "Unexpected closing tag".
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<a></a></a>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// Required-element enforcement — unified gate (has_xml_request_validation):
// `on_final_request_body` is the authoritative gate for required-element
// enforcement when `validate_xml` is unset. Both `before_proxy` and
// `on_final_request_body` share the same `has_xml_request_validation` flag
// (true when validate_xml is set OR required_xml_elements is non-empty), so
// neither path can silently skip required-element checks.

#[tokio::test]
async fn test_on_final_request_body_enforces_xml_required_elements_without_validate_xml() {
    let plugin = BodyValidator::new(&json!({"required_xml_elements": ["item"]})).unwrap();
    let headers = make_xml_headers();
    let result = plugin
        .on_final_request_body(&headers, b"<root><other>x</other></root>")
        .await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_on_final_request_body_accepts_present_xml_required_elements_without_validate_xml() {
    let plugin = BodyValidator::new(&json!({"required_xml_elements": ["item"]})).unwrap();
    let headers = make_xml_headers();
    let result = plugin
        .on_final_request_body(&headers, b"<root><item>x</item></root>")
        .await;
    assert_continue(result);
}

// ─── CDATA Handling ────────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_cdata_with_fake_tags() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[This contains <fake> tags and </closing>]]></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_cdata_empty() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[]]></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_cdata_with_special_chars() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><![CDATA[<>&\"' special chars]]></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_multiple_cdata_sections() {
    let plugin = xml_plugin();
    let body =
        "<root><a><![CDATA[first <section>]]></a><b><![CDATA[second </section>]]></b></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Comment Handling ──────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_comment_with_fake_tags() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><!-- comment with <fake> tags --></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_comment_between_elements() {
    let plugin = xml_plugin();
    let body = "<root><a>text</a><!-- between --><b>more</b></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_comment_empty() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<root><!----></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Processing Instructions ───────────────────────────────────────────

#[tokio::test]
async fn test_xml_processing_instruction() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("<?xml version=\"1.0\"?>\n<root>content</root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_processing_instruction_with_encoding() {
    let plugin = xml_plugin();
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><item>text</item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── DOCTYPE Declarations ──────────────────────────────────────────────

#[tokio::test]
async fn test_xml_doctype_declaration() {
    let plugin = xml_plugin();
    let body = "<!DOCTYPE root>\n<root>content</root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_entity_declaration_quoted_gt_does_not_hide_nested_reference() {
    let plugin = xml_plugin();
    let body = r#"<!DOCTYPE root [<!ENTITY a "lol"><!ENTITY b ">&a;&a;">]><root>&b;</root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ─── Combined / Mixed Content ──────────────────────────────────────────

#[tokio::test]
async fn test_xml_mixed_cdata_and_comments() {
    let plugin = xml_plugin();
    let body = r#"<?xml version="1.0"?>
<root>
  <!-- header comment -->
  <item><![CDATA[data with <tags>]]></item>
  <!-- footer comment -->
  <other>text</other>
</root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_all_constructs() {
    let plugin = xml_plugin();
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<root>
  <!-- A comment -->
  <item attr="value"><![CDATA[Some <data>]]></item>
  <empty/>
  <?custom-pi param="value"?>
  <nested>
    <deep><!-- inner comment --></deep>
  </nested>
</root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Required Elements with Special Constructs ─────────────────────────

#[tokio::test]
async fn test_xml_required_element_with_cdata() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = "<root><item><![CDATA[content <here>]]></item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_required_element_missing() {
    let plugin = xml_plugin_with_required(vec!["missing"]);
    let body = "<root><item>content</item></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_required_element_in_cdata_does_not_match() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = "<root><![CDATA[<item>fake</item>]]></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_required_element_in_comment_does_not_match() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = "<root><!-- <item>fake</item> --></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_required_element_in_processing_instruction_does_not_match() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = r#"<root><?fake <item>fake</item> ?></root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_required_element_prefix_must_not_match() {
    // Body has `<username>` but `<user>` is required — the prefix match
    // alone must not satisfy the requirement.
    let plugin = xml_plugin_with_required(vec!["user"]);
    let body = "<root><username>alice</username></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_required_element_self_closing_tag_matches() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = "<root><item/></root>";
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_xml_required_element_with_attributes_matches() {
    let plugin = xml_plugin_with_required(vec!["item"]);
    let body = r#"<root><item id="1">content</item></root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ─── Edge Cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_xml_empty_body_rejected() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("");
    let mut headers = make_xml_headers();
    // GHSA-2vmr-ww8r-mww3: an empty body is decided by the configured
    // representation, and an empty XML document is not well-formed.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_xml_not_starting_with_angle_bracket() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("not xml at all");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_body_bearing_unusual_methods_are_validated() {
    // GHSA-2vmr-ww8r-mww3: GET, HEAD, OPTIONS, DELETE, and any other method are
    // no longer exempt. A body-bearing request under a governed representation
    // is validated exactly like a POST.
    let plugin = xml_plugin();
    for method in ["GET", "HEAD", "OPTIONS", "DELETE", "PUT", "PATCH", "REPORT"] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api/xml".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), "application/xml".to_string());
        ctx.request_body_bytes = Some(bytes::Bytes::from_static(b"not valid xml"));
        let mut headers = make_xml_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  JSON Schema Validation Tests
// ═══════════════════════════════════════════════════════════════════════

fn make_json_ctx(body: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/json".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    ctx
}

fn json_schema_plugin(schema: serde_json::Value) -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "json_schema": schema
    }))
    .unwrap()
}

// ─── Type validation ──────────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_type_object_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_json_ctx(r#"{"key": "value"}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_object_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_json_ctx(r#"[1, 2, 3]"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_type_string_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string"}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_integer_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer"}));
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_type_integer_rejects_float() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer"}));
    let mut ctx = make_json_ctx("3.14");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── String constraints ──────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_min_length_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_min_length_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 10}));
    let mut ctx = make_json_ctx(r#""hi""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_max_length_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 5}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_max_length_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_min_max_length_counts_code_points_not_bytes() {
    // "日本語" is 3 code points but 9 UTF-8 bytes. Per JSON Schema §6.3,
    // minLength/maxLength count characters (code points), not bytes.
    let plugin =
        json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3, "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""日本語""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // 2 code points fails minLength:3
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "minLength": 3}));
    let mut ctx = make_json_ctx(r#""日本""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    // 4 code points fails maxLength:3
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "maxLength": 3}));
    let mut ctx = make_json_ctx(r#""日本語x""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_pattern_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_pattern_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}));
    let mut ctx = make_json_ctx(r#""Hello123""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Numeric constraints ─────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_minimum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "minimum": 0}));
    let mut ctx = make_json_ctx("5");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_minimum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "minimum": 10}));
    let mut ctx = make_json_ctx("5");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_maximum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "maximum": 100}));
    let mut ctx = make_json_ctx("50");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_maximum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "maximum": 10}));
    let mut ctx = make_json_ctx("50");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_exclusive_minimum() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "exclusiveMinimum": 5}));
    let mut ctx = make_json_ctx("5");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_exclusive_maximum() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "exclusiveMaximum": 10}));
    let mut ctx = make_json_ctx("10");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Enum constraint ─────────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_enum_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"enum": ["red", "green", "blue"]}));
    let mut ctx = make_json_ctx(r#""green""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_enum_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"enum": ["red", "green", "blue"]}));
    let mut ctx = make_json_ctx(r#""yellow""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Array constraints ───────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_array_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "array",
        "items": {"type": "integer"}
    }));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_array_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "array",
        "items": {"type": "integer"}
    }));
    let mut ctx = make_json_ctx(r#"[1, "two", 3]"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_min_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "minItems": 2}));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_min_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "minItems": 5}));
    let mut ctx = make_json_ctx("[1, 2]");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_max_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "maxItems": 3}));
    let mut ctx = make_json_ctx("[1, 2]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_max_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "maxItems": 2}));
    let mut ctx = make_json_ctx("[1, 2, 3, 4]");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_unique_items_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx("[1, 2, 3]");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_unique_items_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx("[1, 2, 2, 3]");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── uniqueItems O(n) DoS-resistance and equality semantics (finding #16) ──

// A large all-distinct array must validate quickly. The previous O(n^2) scan did
// ~N^2/2 deep `Value` comparisons (~1.25e9 for N=50k), taking many seconds; the
// O(n) hash-set scan finishes in well under the generous bound below. The bound
// is loose enough to be CI-stable yet far below the old quadratic cost, so this
// regression test fails against the pre-fix implementation.
#[tokio::test]
async fn test_json_schema_unique_items_large_distinct_is_linear_and_accepted() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let n = 50_000;
    let mut body = String::with_capacity(n * 7);
    body.push('[');
    for i in 0..n {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&i.to_string());
    }
    body.push(']');

    let mut ctx = make_json_ctx(&body);
    let mut headers = make_json_headers();
    let start = std::time::Instant::now();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "uniqueItems scan over {n} distinct items took {elapsed:?}; expected sub-second O(n)"
    );
}

// A large array that does contain a duplicate must still be rejected, and quickly.
#[tokio::test]
async fn test_json_schema_unique_items_large_with_duplicate_is_rejected() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let n = 50_000;
    let mut body = String::with_capacity(n * 7);
    body.push('[');
    for i in 0..n {
        if i > 0 {
            body.push(',');
        }
        // Duplicate the very last element so the duplicate is found late.
        let v = if i == n - 1 { n - 2 } else { i };
        body.push_str(&v.to_string());
    }
    body.push(']');

    let mut ctx = make_json_ctx(&body);
    let mut headers = make_json_headers();
    let start = std::time::Instant::now();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "uniqueItems duplicate detection over {n} items took {elapsed:?}; expected sub-second O(n)"
    );
}

// Equality semantics are preserved for nested objects/arrays: two structurally
// equal objects (even with differently-ordered keys) count as duplicates.
#[tokio::test]
async fn test_json_schema_unique_items_detects_nested_object_duplicates() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx = make_json_ctx(r#"[{"a": 1, "b": [2, 3]}, {"b": [2, 3], "a": 1}]"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Structurally distinct nested values are accepted.
#[tokio::test]
async fn test_json_schema_unique_items_accepts_distinct_nested_values() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "array", "uniqueItems": true}));
    let mut ctx =
        make_json_ctx(r#"[{"a": 1, "b": [2, 3]}, {"a": 1, "b": [3, 2]}, [1, 2], [2, 1]]"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── multipleOf correctness for large/fractional values (finding #65) ──

// Fractional divisor: 0.3 IS a multiple of 0.1. The old absolute-EPSILON
// tolerance wrongly rejected this because 0.3 % 0.1 ≈ 0.0999… in IEEE-754.
#[tokio::test]
async fn test_json_schema_multiple_of_fractional_divisor_accepts_true_multiple() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "multipleOf": 0.1}));
    for value in ["0.3", "0.6", "1.0", "10", "12345.6"] {
        let mut ctx = make_json_ctx(value);
        let mut headers = make_json_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    }
}

// Fractional divisor: a genuine non-multiple is still rejected.
#[tokio::test]
async fn test_json_schema_multiple_of_fractional_divisor_rejects_non_multiple() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "multipleOf": 0.1}));
    let mut ctx = make_json_ctx("0.35");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_multiple_of_large_fractional_non_multiple_rejected() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "multipleOf": 0.1}));
    let mut ctx = make_json_ctx("100000000000000.05");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Currency-style divisor (0.01): valid amount accepted, invalid rejected.
#[tokio::test]
async fn test_json_schema_multiple_of_currency_divisor() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "multipleOf": 0.01}));
    let mut ok = make_json_ctx("19.99");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ok, &mut headers).await);

    let mut bad = make_json_ctx("19.999");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut bad, &mut headers).await, Some(400));
}

// Integral values inside the exactly-representable f64 range are judged with
// exact arithmetic by the compiled validator.
#[tokio::test]
async fn test_json_schema_multiple_of_large_integral_value_uses_exact_modulo() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer", "multipleOf": 3}));
    // 2^53 - 1 = 9007199254740991 has digit sum 76 and is not a multiple of 3;
    // 9007199254740990 has digit sum 75 and is.
    let mut ok = make_json_ctx("9007199254740990");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ok, &mut headers).await);

    let mut bad = make_json_ctx("9007199254740991");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut bad, &mut headers).await, Some(400));
}

// Beyond 2^53 an integer instance is no longer exactly representable as f64.
// The compiled validator resolves that conservatively — u64::MAX is a true
// multiple of 3 but is reported as a violation — which is fail-closed and is
// the documented trade-off of standards-compliant compilation.
#[tokio::test]
async fn test_json_schema_multiple_of_beyond_f64_precision_fails_closed() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer", "multipleOf": 3}));
    // u64::MAX = 18446744073709551615 = 3 * 6148914691236517205.
    let mut ctx = make_json_ctx("18446744073709551615");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Large integral non-multiple is rejected.
#[tokio::test]
async fn test_json_schema_multiple_of_large_integral_non_multiple_rejected() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer", "multipleOf": 7}));
    // 1_000_000_000_000_007 mod 7 == 6, so not a multiple.
    let mut ctx = make_json_ctx("1000000000000007");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// Small integer multiples (the common case) still behave correctly.
#[tokio::test]
async fn test_json_schema_multiple_of_small_integers() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "integer", "multipleOf": 2}));
    let mut ok = make_json_ctx("10");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ok, &mut headers).await);

    let mut bad = make_json_ctx("7");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut bad, &mut headers).await, Some(400));
}

// A fractional value against an integral divisor must take the float path and be
// rejected (0.5 is not a multiple of 2). Guards against the integer fast-path
// being entered when only the divisor is integral.
#[tokio::test]
async fn test_json_schema_multiple_of_fractional_value_integral_divisor_rejected() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "multipleOf": 2}));
    let mut ctx = make_json_ctx("0.5");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// An integral value that is a true multiple of a fractional divisor must be
// accepted via the float near-divisor branch (10 is a multiple of 0.1).
#[tokio::test]
async fn test_json_schema_multiple_of_integral_value_fractional_divisor_accepted() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "number", "multipleOf": 0.1}));
    let mut ctx = make_json_ctx("100");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Object constraints ──────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_additional_properties_false() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "additionalProperties": false
    }));
    let mut ctx = make_json_ctx(r#"{"name": "test", "extra": 123}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_additional_properties_false_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "additionalProperties": false
    }));
    let mut ctx = make_json_ctx(r#"{"name": "test"}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_additional_properties_false_no_properties_rejects_any() {
    // Without `properties`, `additionalProperties: false` should reject
    // ANY object that has fields (per JSON Schema spec: no properties allowed).
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "additionalProperties": false
    }));
    let mut ctx = make_json_ctx(r#"{"anything": "rejected"}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_additional_properties_false_no_properties_accepts_empty() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "additionalProperties": false
    }));
    let mut ctx = make_json_ctx("{}");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_required_and_properties() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["name", "age"],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "age": {"type": "integer", "minimum": 0, "maximum": 150}
        }
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice", "age": 30}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_required_missing() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["name", "age"]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice"}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_nested_property_validation() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "address": {
                "type": "object",
                "required": ["city"],
                "properties": {
                    "city": {"type": "string", "minLength": 1},
                    "zip": {"type": "string", "pattern": "^[0-9]{5}$"}
                }
            }
        }
    }));
    let mut ctx = make_json_ctx(r#"{"address": {"city": "NYC", "zip": "10001"}}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_nested_property_invalid_zip() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "address": {
                "type": "object",
                "properties": {
                    "zip": {"type": "string", "pattern": "^[0-9]{5}$"}
                }
            }
        }
    }));
    let mut ctx = make_json_ctx(r#"{"address": {"zip": "abc"}}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Composition: allOf / anyOf / oneOf / not ─────────────────────────

#[tokio::test]
async fn test_json_schema_all_of_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "allOf": [
            {"type": "object", "required": ["name"]},
            {"type": "object", "required": ["age"]}
        ]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice", "age": 30}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_all_of_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "allOf": [
            {"type": "object", "required": ["name"]},
            {"type": "object", "required": ["age"]}
        ]
    }));
    let mut ctx = make_json_ctx(r#"{"name": "Alice"}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_any_of_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "anyOf": [
            {"type": "string"},
            {"type": "integer"}
        ]
    }));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_any_of_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "anyOf": [
            {"type": "string"},
            {"type": "integer"}
        ]
    }));
    let mut ctx = make_json_ctx("true");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_one_of_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "oneOf": [
            {"type": "string"},
            {"type": "integer"}
        ]
    }));
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_one_of_multiple_match_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "oneOf": [
            {"type": "number"},
            {"type": "integer"}
        ]
    }));
    // integer 42 matches both "number" and "integer" type schemas
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_not_valid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "not": {"type": "string"}
    }));
    let mut ctx = make_json_ctx("42");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_not_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({
        "not": {"type": "string"}
    }));
    let mut ctx = make_json_ctx(r#""hello""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

// ─── Format validation ───────────────────────────────────────────────

#[tokio::test]
async fn test_json_schema_format_email_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "email"}));
    let mut ctx = make_json_ctx(r#""user@example.com""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_email_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "email"}));
    let mut ctx = make_json_ctx(r#""not-an-email""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_format_ipv4_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "ipv4"}));
    let mut ctx = make_json_ctx(r#""192.168.1.1""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_ipv4_invalid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "ipv4"}));
    let mut ctx = make_json_ctx(r#""999.999.999.999""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn test_json_schema_format_uuid_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "uuid"}));
    let mut ctx = make_json_ctx(r#""550e8400-e29b-41d4-a716-446655440000""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn test_json_schema_format_datetime_valid() {
    let plugin = json_schema_plugin(serde_json::json!({"type": "string", "format": "date-time"}));
    let mut ctx = make_json_ctx(r#""2024-01-15T10:30:00Z""#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Complex real-world schema ───────────────────────────────────────

#[tokio::test]
async fn test_json_schema_complex_api_payload() {
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["method", "params"],
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
            "params": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 1},
                    "timeout": {"type": "integer", "minimum": 0, "maximum": 30000},
                    "headers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "value"],
                            "properties": {
                                "name": {"type": "string"},
                                "value": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    }));
    let mut ctx = make_json_ctx(
        r#"{"method": "POST", "params": {"url": "/api/data", "timeout": 5000, "headers": [{"name": "X-Custom", "value": "test"}]}}"#,
    );
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Pre-compiled regex pattern reuse ─────────────────────────────────

#[tokio::test]
async fn test_json_schema_pattern_pre_compiled_reuse() {
    // Create a plugin with a pattern constraint — the regex is pre-compiled at config time
    let plugin = json_schema_plugin(serde_json::json!({
        "type": "string",
        "pattern": "^[A-Z]{3}-[0-9]{4}$"
    }));

    // First request: matching pattern
    let mut ctx1 = make_json_ctx(r#""ABC-1234""#);
    let mut headers1 = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx1, &mut headers1).await);

    // Second request: non-matching pattern (implicitly exercises the same pre-compiled regex)
    let mut ctx2 = make_json_ctx(r#""invalid""#);
    let mut headers2 = make_json_headers();
    assert_reject(
        plugin.before_proxy(&mut ctx2, &mut headers2).await,
        Some(400),
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Response Body Validation Tests
// ═══════════════════════════════════════════════════════════════════════

fn make_response_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/data".to_string(),
    )
}

fn response_json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn response_xml_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/xml".to_string());
    h
}

fn response_schema_plugin(schema: serde_json::Value) -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "response_json_schema": schema
    }))
    .unwrap()
}

// ─── requires_response_body_buffering ─────────────────────────────────

#[test]
fn test_response_buffering_required_when_response_schema_configured() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_response_buffering_required_when_response_required_fields() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_response_buffering_not_required_when_only_request_validation() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "json_schema": {"type": "object"}
    }))
    .unwrap();
    assert!(!plugin.requires_response_body_buffering());
}

// ─── Response JSON Schema Validation ──────────────────────────────────

#[tokio::test]
async fn test_response_json_schema_valid() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"}
        }
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"id": 1, "name": "Alice"}"#;
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_json_schema_missing_required_field() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "required": ["id", "name"]
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"id": 1}"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_json_schema_wrong_type() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"[1, 2, 3]"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_json_invalid_json() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = b"not json at all";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_json_empty_body_on_200_fails_closed() {
    // GHSA-2vmr-ww8r-mww3: 200 is an ordinary body-bearing success. An empty
    // body is not a JSON document and must not be exempt.
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"")
            .await,
        Some(502),
    );
}

/// Only the statuses/methods HTTP itself defines as content-free are exempt.
#[tokio::test]
async fn test_response_protocol_no_content_semantics_are_exempt() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let headers = response_json_headers();

    for status in [100u16, 101, 199, 204, 205, 304] {
        let mut ctx = make_response_ctx();
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, status, &headers, b"")
                .await,
        );
    }

    // A HEAD response legitimately omits the content of an otherwise
    // body-bearing status.
    let mut head_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "HEAD".to_string(),
        "/api/data".to_string(),
    );
    assert_continue(
        plugin
            .on_final_response_body(&mut head_ctx, 200, &headers, b"")
            .await,
    );

    // The exemption is about an ABSENT body only: a 204 that somehow carries
    // bytes is still validated.
    let mut ctx = make_response_ctx();
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 204, &headers, b"[]")
            .await,
        Some(502),
    );
}

/// A response the configured rules cannot decode is not a passing response, and
/// the client-visible detail never reproduces the offending bytes.
#[tokio::test]
async fn test_response_non_utf8_json_fails_closed_without_echoing_bytes() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, b"{\"a\":\"\xFF\xFE\"}")
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("not valid UTF-8"), "{body}");
            assert!(!body.contains('\u{FFFD}'), "{body}");
            assert!(!body.contains("\\u00ff"), "{body}");
        }
        other => panic!("expected reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_response_json_non_matching_content_type_skipped() {
    let plugin = response_schema_plugin(serde_json::json!({"type": "object"}));
    let mut ctx = make_response_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let body = b"not json";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

// ─── Response Required Fields ─────────────────────────────────────────

#[tokio::test]
async fn test_response_required_fields_valid() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_required_fields": ["status", "data"]
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"status": "ok", "data": []}"#;
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_required_fields_missing() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_required_fields": ["status", "data"]
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"status": "ok"}"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

// ─── Response XML Validation ──────────────────────────────────────────

#[tokio::test]
async fn test_response_xml_valid() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_validate_xml": true
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><item>text</item></root>";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_xml_invalid() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_validate_xml": true
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><item></root>";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_response_xml_required_elements() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "response_validate_xml": true,
        "response_required_xml_elements": ["result"]
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><data>text</data></root>";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

// Response-side required-element enforcement without response_validate_xml:
// A config with `response_required_xml_elements` set but `response_validate_xml`
// unset must still enforce required-element checks via has_xml_response_validation.
// This mirrors the request-side fix and closes the silent-skip bug on responses.

#[tokio::test]
async fn test_on_final_response_body_enforces_xml_required_elements_without_response_validate_xml()
{
    let plugin =
        BodyValidator::new(&json!({"response_required_xml_elements": ["result"]})).unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><data>text</data></root>";
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_on_final_response_body_accepts_present_xml_required_elements_without_response_validate_xml()
 {
    let plugin =
        BodyValidator::new(&json!({"response_required_xml_elements": ["result"]})).unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<root><result>ok</result></root>";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

// ─── Combined Request + Response Validation ───────────────────────────

#[tokio::test]
async fn test_both_request_and_response_validation() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "json_schema": {"type": "object", "required": ["action"]},
        "response_json_schema": {"type": "object", "required": ["result"]}
    }))
    .unwrap();

    // Request validation still works
    let mut req_ctx = make_json_ctx(r#"{"action": "create"}"#);
    let mut req_headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut req_ctx, &mut req_headers).await);

    // Request with missing field is rejected (400)
    let mut bad_req_ctx = make_json_ctx(r#"{"other": "value"}"#);
    let mut bad_req_headers = make_json_headers();
    assert_reject(
        plugin
            .before_proxy(&mut bad_req_ctx, &mut bad_req_headers)
            .await,
        Some(400),
    );

    // Response validation works
    let mut resp_ctx = make_response_ctx();
    let resp_headers = response_json_headers();
    assert_continue(
        plugin
            .on_final_response_body(&mut resp_ctx, 200, &resp_headers, br#"{"result": "ok"}"#)
            .await,
    );

    // Response with missing field is rejected (502)
    assert_reject(
        plugin
            .on_final_response_body(&mut resp_ctx, 200, &resp_headers, br#"{"other": "value"}"#)
            .await,
        Some(502),
    );

    // Buffering is required because response validation is configured
    assert!(plugin.requires_response_body_buffering());
}

// ─── Response schema with pattern (pre-compiled regex) ────────────────

#[tokio::test]
async fn test_response_json_schema_pattern_valid() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "code": {"type": "string", "pattern": "^[A-Z]{3}-[0-9]+$"}
        }
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"code": "ABC-123"}"#;
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

#[tokio::test]
async fn test_response_json_schema_pattern_invalid() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": {
            "code": {"type": "string", "pattern": "^[A-Z]{3}-[0-9]+$"}
        }
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"code": "invalid"}"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

// ─── Response with no validation configured skips ─────────────────────

#[tokio::test]
async fn test_response_no_validation_skips() {
    // Only request validation configured — response body should pass through
    let plugin = BodyValidator::new(&serde_json::json!({
        "json_schema": {"type": "object"}
    }))
    .unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = b"totally invalid json!!!";
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
    );
}

// ════════════════════════════════════��══════════════════════════════════
//  Protobuf Validation Tests (gRPC)
// ══════════════════��═════════════════════════════��══════════════════════

/// Path to the test descriptor file compiled from test_validator.proto.
fn test_descriptor_path() -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/tests/fixtures/test_validator.bin", manifest_dir)
}

/// Build a gRPC length-prefixed frame: [0x00] [4-byte big-endian length] [payload].
fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0); // not compressed
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Encode a valid HelloRequest protobuf using prost-reflect.
fn encode_hello_request(name: &str, age: i32) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let descriptor_bytes = std::fs::read(test_descriptor_path()).unwrap();
    let pool = DescriptorPool::decode(descriptor_bytes.as_slice()).unwrap();
    let msg_desc = pool.get_message_by_name("test.HelloRequest").unwrap();
    let mut msg = DynamicMessage::new(msg_desc);
    msg.set_field_by_name("name", Value::String(name.to_string()));
    msg.set_field_by_name("age", Value::I32(age));
    msg.encode_to_vec()
}

/// Encode a valid HelloResponse protobuf using prost-reflect.
fn encode_hello_response(message: &str, success: bool) -> Vec<u8> {
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    let descriptor_bytes = std::fs::read(test_descriptor_path()).unwrap();
    let pool = DescriptorPool::decode(descriptor_bytes.as_slice()).unwrap();
    let msg_desc = pool.get_message_by_name("test.HelloResponse").unwrap();
    let mut msg = DynamicMessage::new(msg_desc);
    msg.set_field_by_name("message", Value::String(message.to_string()));
    msg.set_field_by_name("success", Value::Bool(success));
    msg.encode_to_vec()
}

fn protobuf_plugin() -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "protobuf_response_type": "test.HelloResponse"
    }))
    .unwrap()
}

fn protobuf_plugin_with_method_messages() -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_method_messages": {
            "/test.Greeter/SayHello": {
                "request": "test.HelloRequest",
                "response": "test.HelloResponse"
            }
        }
    }))
    .unwrap()
}

fn protobuf_plugin_reject_unknown() -> BodyValidator {
    BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "protobuf_reject_unknown_fields": true
    }))
    .unwrap()
}

// ─── Config and Buffering Flags ─��───────────────────────────────────

#[test]
fn test_protobuf_config_sets_validation_flags() {
    let plugin = protobuf_plugin();
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_protobuf_request_only_config() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest"
    }))
    .unwrap();
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[test]
fn test_protobuf_response_only_config() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_response_type": "test.HelloResponse"
    }))
    .unwrap();
    assert!(!plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_protobuf_should_buffer_grpc_content_type() {
    let plugin = protobuf_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_protobuf_should_buffer_grpc_proto_content_type() {
    let plugin = protobuf_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    );
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_protobuf_does_not_buffer_non_matching_content_types() {
    // Protobuf-only config with content_types restricted to gRPC
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "content_types": ["application/grpc"]
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/json".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // JSON content-type doesn't match the explicit content_types list
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ─── gRPC Frame Parsing ───────��──────────────────────────────────────

#[tokio::test]
async fn test_protobuf_valid_request() {
    let plugin = protobuf_plugin();
    let payload = encode_hello_request("Alice", 30);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_invalid_request_body() {
    let plugin = protobuf_plugin();
    // Random bytes that are not valid protobuf for HelloRequest
    let invalid_payload = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
    let frame = grpc_frame(&invalid_payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_frame_too_short() {
    let plugin = protobuf_plugin();
    let frame = vec![0x00, 0x01]; // Only 2 bytes, need at least 5
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_frame_length_mismatch() {
    let plugin = protobuf_plugin();
    // Frame says 100 bytes but only has 3
    let mut frame = vec![0x00]; // not compressed
    frame.extend_from_slice(&100u32.to_be_bytes());
    frame.extend_from_slice(&[0x01, 0x02, 0x03]);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_frame_valid() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = protobuf_plugin();
    let payload = encode_hello_request("Bob", 25);
    // Compress with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();
    // Build frame with compressed flag = 1
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1); // compressed flag
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_frame_rejects_configured_decompressed_cap() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "grpc_max_decompressed_size_bytes": 8
    }))
    .unwrap();

    let payload = encode_hello_request("compressed-payload-that-exceeds-eight-bytes", 25);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_invalid_gzip_data_rejected() {
    let plugin = protobuf_plugin();
    // Not valid gzip — just raw protobuf bytes with compressed flag set
    let payload = encode_hello_request("Bob", 25);
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(1); // compressed flag = 1
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_invalid_protobuf_rejected() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = protobuf_plugin();
    // Compress garbage bytes that aren't valid protobuf
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"\xff\xff\xff\xff").unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

#[tokio::test]
async fn test_protobuf_compressed_gzip_response_valid() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = protobuf_plugin();
    let payload = encode_hello_response("Hi Bob!", true);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    frame.extend_from_slice(&compressed);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &frame)
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_empty_or_short_request_transport_body_fails_closed() {
    // GHSA-2vmr-ww8r-mww3: a zero-length native-gRPC transport body is not a
    // frame, and neither is anything shorter than the five-byte frame header.
    let plugin = protobuf_plugin();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    for body in [&b""[..], &b"\x00"[..], &b"\x00\x00\x00\x00"[..]] {
        assert_reject(
            plugin.on_final_request_body(&headers, body).await,
            Some(400),
        );
    }
}

/// The response side runs the same frame validation; only a Trailers-Only
/// *error* reply (single valid non-zero `grpc-status`) legitimately carries no
/// message. Successful unary replies still need a five-byte frame.
#[tokio::test]
async fn test_protobuf_empty_response_transport_body_fails_closed() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_response_type": "test.HelloResponse"
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"")
            .await,
        Some(502),
    );
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"\x00\x00")
            .await,
        Some(502),
    );

    // Empty successful unary (`grpc-status: 0`) still requires a frame.
    let mut ok_status = headers.clone();
    ok_status.insert("grpc-status".to_string(), "0".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &ok_status, b"")
            .await,
        Some(502),
    );

    // Malformed / unparsable / LF-joined duplicate values are not exemptions.
    for bad in ["", "abc", "5\n14", "5\r\n14", "99"] {
        let mut hostile = headers.clone();
        hostile.insert("grpc-status".to_string(), bad.to_string());
        assert_reject(
            plugin
                .on_final_response_body(&mut ctx, 200, &hostile, b"")
                .await,
            Some(502),
        );
    }

    // Terminal error: a single valid non-zero status and no message frame is
    // the legitimate empty native-gRPC response body.
    let mut trailers_only = headers.clone();
    trailers_only.insert("grpc-status".to_string(), "5".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &trailers_only, b"")
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_non_grpc_content_type_skipped() {
    let plugin = protobuf_plugin();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    assert_continue(
        plugin
            .on_final_request_body(&headers, b"not protobuf")
            .await,
    );
}

// ─── Method-based Message Type Routing ──────────────────────────────

#[tokio::test]
async fn test_protobuf_method_message_lookup() {
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_request("Charlie", 40);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_unknown_method_skipped_when_no_default() {
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_request("Charlie", 40);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(
        ":path".to_string(),
        "/test.Greeter/UnknownMethod".to_string(),
    );
    // No default type and method not in map — skip validation
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_unknown_method_uses_default_type() {
    let plugin = protobuf_plugin();
    let payload = encode_hello_request("Dave", 50);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/AnyMethod".to_string());
    // Default type is configured, so validation runs
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

// Regression: response-side per-method descriptor lookup must use the request
// path from `ctx.path` (or `grpc_full_method` metadata) — not the response
// headers, which never carry `:path`. Previously the lookup always failed and
// silently fell back to the global default, causing per-method
// `protobuf_method_messages` for response validation to be ignored entirely.
#[tokio::test]
async fn test_protobuf_response_per_method_descriptor_resolved_from_ctx_path() {
    // No global `protobuf_response_type` — only per-method config. With the bug,
    // this lookup would miss and the response would silently pass without
    // validation. With the fix, validation runs against the per-method type and
    // valid responses pass while invalid ones reject.
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_response("Hi", true);
    let frame = grpc_frame(&payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    // Note: no `:path` in response_headers — that's the bug being guarded against.
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &frame)
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_response_per_method_invalid_body_rejected() {
    let plugin = protobuf_plugin_with_method_messages();
    // Random bytes that don't decode as HelloResponse
    let invalid = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let frame = grpc_frame(&invalid);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &frame)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_protobuf_response_uses_grpc_full_method_metadata_when_present() {
    // When `grpc_method_router` ran upstream, it stores `grpc_full_method`
    // (without the leading slash) in metadata. The response validator must
    // accept that form and prepend the slash to look up the descriptor.
    let plugin = protobuf_plugin_with_method_messages();
    let payload = encode_hello_response("Hi", true);
    let frame = grpc_frame(&payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/some/other/path".to_string(), // ctx.path is misleading
    );
    ctx.metadata.insert(
        "grpc_full_method".to_string(),
        "test.Greeter/SayHello".to_string(),
    );
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, &frame)
            .await,
    );
}

// ���── Unknown Fields ���────────────────────────────────────────────────

#[tokio::test]
async fn test_protobuf_unknown_fields_allowed_by_default() {
    let plugin = protobuf_plugin();
    // Encode a message with an extra field (field number 99)
    let mut payload = encode_hello_request("Eve", 25);
    // Append a varint field: tag = (99 << 3) | 0 = 792, value = 42
    // 792 = 0x318, varint encoding: 0x98 0x06
    payload.extend_from_slice(&[0x98, 0x06, 42]);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

#[tokio::test]
async fn test_protobuf_unknown_fields_rejected_when_configured() {
    let plugin = protobuf_plugin_reject_unknown();
    let mut payload = encode_hello_request("Eve", 25);
    // Same unknown field as above
    payload.extend_from_slice(&[0x98, 0x06, 42]);
    let frame = grpc_frame(&payload);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_reject(
        plugin.on_final_request_body(&headers, &frame).await,
        Some(400),
    );
}

// ─── Response Validation ���────────────────────────────────���──────────

#[tokio::test]
async fn test_protobuf_valid_response() {
    let plugin = protobuf_plugin();
    let payload = encode_hello_response("Hello, Alice!", true);
    let frame = grpc_frame(&payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &frame)
            .await,
    );
}

#[tokio::test]
async fn test_protobuf_invalid_response() {
    let plugin = protobuf_plugin();
    let invalid_payload = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let frame = grpc_frame(&invalid_payload);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &frame)
            .await,
        Some(502),
    );
}

// ─── Invalid Config Graceful Handling ───────────���───────────────────

#[tokio::test]
async fn test_protobuf_missing_descriptor_fails_closed_for_applicable_request_and_response() {
    let config = serde_json::json!({
        "protobuf_descriptor_path": "/nonexistent/path/descriptor.bin",
        "protobuf_request_type": "test.HelloRequest",
        "protobuf_response_type": "test.HelloResponse"
    });
    let plugin = BodyValidator::new(&config)
        .expect("runtime construction must tolerate a missing node-local descriptor");
    assert!(
        ferrum_edge::plugins::validate_plugin_config("body_validator", &config).is_ok(),
        "shape-only admission must not open a DP-local descriptor"
    );
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_response_body_buffering());

    let headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        (":path".to_string(), "/test.Greeter/SayHello".to_string()),
    ]);
    assert_reject(
        plugin
            .on_final_request_body(&headers, &[0, 0, 0, 0, 0])
            .await,
        Some(400),
    );

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, &[0, 0, 0, 0, 0])
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_protobuf_missing_descriptor_only_rejects_configured_method_targets() {
    let plugin = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": "/nonexistent/path/descriptor.bin",
        "protobuf_method_messages": {
            "/test.Greeter/SayHello": {
                "request": "test.HelloRequest"
            }
        }
    }))
    .expect("missing node-local descriptor must produce a fail-closed runtime");
    let unmatched = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        (":path".to_string(), "/test.Greeter/Health".to_string()),
    ]);
    assert_continue(
        plugin
            .on_final_request_body(&unmatched, &[0, 0, 0, 0, 0])
            .await,
    );
    let matched = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        (":path".to_string(), "/test.Greeter/SayHello".to_string()),
    ]);
    assert_reject(
        plugin
            .on_final_request_body(&matched, &[0, 0, 0, 0, 0])
            .await,
        Some(400),
    );
}

#[test]
fn test_protobuf_invalid_message_type_degrades_gracefully() {
    const MESSAGE_TYPE: &str = "nonexistent.BODY_VALIDATOR_CONFIG_CANARY_TYPE";
    let result = BodyValidator::new(&serde_json::json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": MESSAGE_TYPE
    }));
    let err = result
        .err()
        .expect("expected error for invalid message type");
    assert!(
        err.contains("configured 'protobuf_request_type' was not found in the descriptor"),
        "got: {err}"
    );
    assert!(!err.contains(MESSAGE_TYPE), "got: {err}");
}

#[test]
fn test_protobuf_readable_malformed_descriptor_rejects_runtime_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join("BODY_VALIDATOR_CONFIG_CANARY_DESCRIPTOR_PATH.pb");
    std::fs::write(&path, b"not-a-file-descriptor-set").unwrap();
    let path_text = path.to_string_lossy().into_owned();
    let config = json!({
        "protobuf_descriptor_path": path_text,
        "protobuf_request_type": "test.HelloRequest"
    });
    let error = BodyValidator::new(&config)
        .err()
        .expect("a readable malformed descriptor must reject the runtime candidate");
    assert!(error.contains("failed to parse protobuf descriptor"));
    assert!(!error.contains("BODY_VALIDATOR_CONFIG_CANARY_DESCRIPTOR_PATH"));

    let gateway = GatewayConfig {
        plugin_configs: vec![body_validator_plugin_config("body-validator", true, config)],
        ..Default::default()
    };
    let errors = gateway.validate_plugin_file_dependencies();
    assert_eq!(errors.len(), 1, "unexpected dependency errors: {errors:?}");
    assert!(errors[0].contains("failed to parse protobuf descriptor"));
    assert!(!errors[0].contains("BODY_VALIDATOR_CONFIG_CANARY_DESCRIPTOR_PATH"));
}

#[test]
fn test_protobuf_descriptor_file_dependency_reports_missing_path_once() {
    let missing = "/nonexistent/BODY_VALIDATOR_CONFIG_CANARY_DESCRIPTOR_PATH/shared.bin";
    let gateway = GatewayConfig {
        plugin_configs: vec![
            body_validator_plugin_config(
                "body-validator-a",
                true,
                json!({
                    "protobuf_descriptor_path": missing,
                    "protobuf_request_type": "test.HelloRequest"
                }),
            ),
            body_validator_plugin_config(
                "body-validator-b",
                true,
                json!({
                    "protobuf_descriptor_path": missing,
                    "protobuf_response_type": "test.HelloResponse"
                }),
            ),
        ],
        ..Default::default()
    };
    let errors = gateway.validate_plugin_file_dependencies();
    assert_eq!(
        errors.len(),
        1,
        "shared descriptor paths must be read and reported once: {errors:?}"
    );
    assert!(errors[0].contains("failed to read protobuf descriptor file"));
    assert!(!errors[0].contains("BODY_VALIDATOR_CONFIG_CANARY_DESCRIPTOR_PATH"));
}

#[test]
fn test_protobuf_descriptor_file_dependency_validates_message_references() {
    const MESSAGE_TYPE: &str = "missing.BODY_VALIDATOR_CONFIG_CANARY_TYPE";
    let gateway = GatewayConfig {
        plugin_configs: vec![body_validator_plugin_config(
            "body-validator",
            true,
            json!({
                "protobuf_descriptor_path": test_descriptor_path(),
                "protobuf_request_type": MESSAGE_TYPE
            }),
        )],
        ..Default::default()
    };
    let errors = gateway.validate_plugin_file_dependencies();
    assert_eq!(errors.len(), 1, "unexpected dependency errors: {errors:?}");
    assert!(
        errors[0].contains("configured 'protobuf_request_type' was not found in the descriptor")
    );
    assert!(!errors[0].contains(MESSAGE_TYPE));
}

#[test]
fn protobuf_method_resolution_errors_redact_method_path_and_type() {
    const METHOD_PATH: &str = "/BODY_VALIDATOR_CONFIG_CANARY_METHOD/Call";
    const MESSAGE_TYPE: &str = "missing.BODY_VALIDATOR_CONFIG_CANARY_METHOD_TYPE";
    let config = json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_method_messages": {
            "/BODY_VALIDATOR_CONFIG_CANARY_METHOD/Call": {
                "request": MESSAGE_TYPE
            }
        }
    });
    let error = BodyValidator::new(&config)
        .err()
        .expect("missing per-method type must reject configuration");
    assert_eq!(
        error,
        "body_validator: a 'protobuf_method_messages' request type was not found in the descriptor"
    );
    assert!(!error.contains(METHOD_PATH), "{error}");
    assert!(!error.contains(MESSAGE_TYPE), "{error}");
}

#[test]
fn test_protobuf_descriptor_file_dependency_skips_disabled_plugins() {
    let gateway = GatewayConfig {
        plugin_configs: vec![body_validator_plugin_config(
            "body-validator",
            false,
            json!({
                "protobuf_descriptor_path": "/nonexistent/path/descriptor.bin",
                "protobuf_request_type": "test.HelloRequest"
            }),
        )],
        ..Default::default()
    };
    assert!(gateway.validate_plugin_file_dependencies().is_empty());
}

// ─── gRPC before_proxy is skipped (uses on_final_request_body instead) ──

#[tokio::test]
async fn test_protobuf_before_proxy_skips_grpc() {
    let plugin = protobuf_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    // before_proxy should return Continue for gRPC — validation happens in on_final_request_body
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ─── Empty protobuf message (valid for proto3) ──────────────────────

#[tokio::test]
async fn test_protobuf_empty_message_valid() {
    let plugin = protobuf_plugin();
    // Empty protobuf payload is valid in proto3 (all fields have defaults)
    let frame = grpc_frame(&[]);
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(plugin.on_final_request_body(&headers, &frame).await);
}

// ─── SSE response policy boundary ───────────────────────────────────

#[test]
fn test_sse_request_intent_cannot_skip_response_validation_buffering() {
    let plugin = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/events".to_string(),
    );
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
    let response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &response_headers));
    assert!(
        plugin.should_release_response_body_before_content_type_rewrite(
            &ctx,
            200,
            &response_headers,
        )
    );
    let json_profile_headers = HashMap::from([(
        "content-type".to_string(),
        "application/json; profile=event-stream".to_string(),
    )]);
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
}

#[tokio::test]
async fn test_genuine_sse_fails_closed_before_body_validation_streams() {
    let plugin = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/events".to_string(),
    );
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    assert_reject(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        Some(502),
    );
}

#[tokio::test]
async fn test_pristine_sse_relabel_cannot_erase_body_validation_boundary() {
    let plugin = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/events".to_string(),
    );
    ctx.metadata.insert(
        "ferrum:original_response_metadata_stamped".to_string(),
        "true".to_string(),
    );
    ctx.metadata.insert(
        "ferrum:original_response_content_type".to_string(),
        "text/event-stream".to_string(),
    );
    let mut relabeled_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    assert_reject(
        plugin
            .after_proxy(&mut ctx, 200, &mut relabeled_headers)
            .await,
        Some(502),
    );
}

#[test]
fn test_non_sse_request_still_validates_response() {
    // Default behavior must still buffer JSON responses for validation.
    let plugin = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[test]
fn test_response_content_type_refinement_releases_irrelevant_media_types() {
    let plugin = BodyValidator::new(&json!({
        "response_required_fields": ["id"]
    }))
    .unwrap();
    let ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/download".to_string(),
    );

    let png_headers = HashMap::from([("content-type".to_string(), "image/png".to_string())]);
    let octet_headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);
    let json_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let xml_headers = HashMap::from([("content-type".to_string(), "application/xml".to_string())]);

    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("image/png"),
        200,
        &png_headers,
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/octet-stream"),
        200,
        &octet_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &json_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; charset=utf-8"),
        200,
        &json_headers,
    ));
    // Default response_content_types include XML, but this config has no XML
    // response rules — only JSON required fields — so XML is not inspected.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/xml"),
        200,
        &xml_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));

    // Retry-aware release must stream irrelevant types once headers are known.
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &png_headers));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &octet_headers));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &json_headers));
    // Content-Type rewrite safety: only SSE uses the pre-rewrite release hook.
    assert!(
        !plugin.should_release_response_body_before_content_type_rewrite(&ctx, 200, &png_headers,)
    );
}

#[test]
fn test_response_content_type_refinement_keeps_xml_when_xml_validation_configured() {
    let plugin = BodyValidator::new(&json!({
        "response_validate_xml": true
    }))
    .unwrap();
    let ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/xml".to_string(),
    );
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/xml"),
        200,
        &HashMap::new(),
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("image/png"),
        200,
        &HashMap::new(),
    ));
}

#[test]
fn test_protobuf_response_refinement_retains_applicable_grpc_and_releases_others() {
    let plugin = BodyValidator::new(&json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_response_type": "test.HelloResponse"
    }))
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/test.Greeter/SayHello".to_string(),
    );
    let grpc_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let png_headers = HashMap::from([("content-type".to_string(), "image/png".to_string())]);
    let json_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/grpc"),
        200,
        &grpc_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/grpc+proto"),
        200,
        &grpc_headers,
    ));
    // Protobuf-only config does not claim ordinary JSON/XML responses.
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &json_headers,
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("image/png"),
        200,
        &png_headers,
    ));
    assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &grpc_headers));
    assert!(plugin.should_release_response_body_under_retries(&ctx, 200, &png_headers));

    // Method-scoped descriptors: non-applicable gRPC methods are released.
    let method_plugin = protobuf_plugin_with_method_messages();
    ctx.path = "/test.Greeter/OtherMethod".to_string();
    assert!(!method_plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/grpc"),
        200,
        &grpc_headers,
    ));
    ctx.path = "/test.Greeter/SayHello".to_string();
    assert!(method_plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/grpc"),
        200,
        &grpc_headers,
    ));
    ctx.metadata.insert(
        "grpc_full_method".to_string(),
        "test.Greeter/SayHello".to_string(),
    );
    assert!(method_plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/grpc"),
        200,
        &grpc_headers,
    ));
}

#[test]
fn test_no_response_validation_never_buffers_even_for_non_sse() {
    // When response validation is disabled, the buffer flag is false
    // regardless of Accept — guarding the existing config-driven default.
    let plugin = BodyValidator::new(&json!({"validate_xml": true})).unwrap();
    assert!(!plugin.requires_response_body_buffering());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_on_final_request_body_validates_json_when_before_proxy_cannot() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let headers = make_json_headers();

    let result = plugin
        .on_final_request_body(&headers, br#"{"missing":"field"}"#)
        .await;

    assert_reject(result, Some(400));
}

#[tokio::test]
async fn billion_laughs_nested_entities_are_rejected() {
    let plugin = xml_plugin();
    let body = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn parameter_entity_reference_in_entity_value_is_rejected() {
    let plugin = xml_plugin();
    let body = r#"<!DOCTYPE r [<!ENTITY % a "lol"><!ENTITY b "%a;%a;">]><r>&b;</r>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn numeric_ampersand_entity_reference_in_entity_value_is_rejected() {
    let plugin = xml_plugin();
    let body = r#"<!DOCTYPE r [<!ENTITY a "lol"><!ENTITY b "&#38;a;&#38;a;"><!ENTITY c "&#x26;b;&#x26;b;">]><r>&c;</r>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn numeric_encoded_entity_reference_semicolons_are_rejected() {
    let plugin = xml_plugin();
    let body = r#"<!DOCTYPE r [<!ENTITY a "lol"><!ENTITY b "&#38;a&#59;&#x26;a&#x3b;"><!ENTITY c "&#38;b&#59;&#x26;b&#x3b;">]><r>&c;</r>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn numeric_encoded_parameter_entity_references_are_rejected() {
    let plugin = xml_plugin();
    let body =
        r#"<!DOCTYPE r [<!ENTITY % a "lol"><!ENTITY b "&#37;a&#59;&#x25;a&#x3b;">]><r>&b;</r>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn long_xml_entity_names_are_checked_for_nested_references() {
    let plugin = xml_plugin();
    let long_name = "a".repeat(40);
    let long_ref = format!("&{long_name};");
    let body = format!(
        r#"<!DOCTYPE r [<!ENTITY {long_name} "lol"><!ENTITY b "{long_ref}{long_ref}">]><r>&b;</r>"#
    );
    let mut ctx = make_xml_ctx(&body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn parameter_entity_expanding_entity_declarations_is_rejected() {
    let plugin = BodyValidator::new(&json!({
        "validate_xml": true,
        "xml_max_entities": 1
    }))
    .unwrap();
    let body = r#"<!DOCTYPE r [<!ENTITY % many "<!ENTITY a 'x'><!ENTITY b 'y'>">%many;]><r/>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn attlist_parameter_entity_expansion_is_rejected() {
    // Bare `%many;` in the subset is already covered. The same expansion inside
    // another markup declaration (ATTLIST) must still fail closed — that is the
    // quote-aware `<!` skip path that charges parameter entities in markup.
    let plugin = xml_plugin();
    let body = concat!(
        r#"<!DOCTYPE r ["#,
        r#"<!ENTITY % many "<!ENTITY a 'x'><!ENTITY b 'y'">"#,
        r#"<!ATTLIST r id CDATA %many;>"#,
        r#"]><r/>"#
    );
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn attlist_parameter_entity_count_exceeds_cap_when_nesting_allowed() {
    let plugin = BodyValidator::new(&json!({
        "validate_xml": true,
        "xml_reject_nested_entities": false,
        "xml_max_entities": 1
    }))
    .unwrap();
    // The parameter entity declaration itself consumes the only allowed slot;
    // expanding it into two more declarations must still exceed the cap.
    let body = concat!(
        r#"<!DOCTYPE r ["#,
        r#"<!ENTITY % many "<!ENTITY a 'x'><!ENTITY b 'y'">"#,
        r#"<!ATTLIST r id CDATA %many;>"#,
        r#"]><r/>"#
    );
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn attlist_parameter_entity_without_nested_declarations_is_allowed() {
    let plugin = xml_plugin();
    // Empty replacement text contributes zero nested declarations, so the
    // markup charge is a no-op and the ATTLIST remains well-formed.
    let body = concat!(
        r#"<!DOCTYPE r ["#,
        r#"<!ENTITY % empty "">"#,
        r#"<!ATTLIST r id CDATA #IMPLIED%empty;>"#,
        r#"]><r/>"#
    );
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn quoted_parameter_entity_inside_attlist_is_not_charged() {
    let plugin = xml_plugin();
    // `%many;` appears only as a quoted default attribute value, so the
    // expansion policy must not treat it as an active parameter reference.
    let body = concat!(
        r#"<!DOCTYPE r ["#,
        r#"<!ENTITY % many "<!ENTITY a 'x'><!ENTITY b 'y'">"#,
        r#"<!ATTLIST r id CDATA "%many;">"#,
        r#"]><r/>"#
    );
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn incomplete_attlist_still_charges_parameter_entity_references() {
    let plugin = xml_plugin();
    // Missing `>` forces the declaration-end scan to the end of the body; the
    // unquoted `%many;` inside must still be charged and rejected.
    let body = concat!(
        r#"<!DOCTYPE r ["#,
        r#"<!ENTITY % many "<!ENTITY a 'x'><!ENTITY b 'y'">"#,
        r#"<!ATTLIST r id CDATA %many;"#
    );
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn too_many_xml_entities_are_rejected() {
    let plugin = BodyValidator::new(&json!({
        "validate_xml": true,
        "xml_max_entities": 2
    }))
    .unwrap();
    let body = r#"<!DOCTYPE r [<!ENTITY a "x"><!ENTITY b "y"><!ENTITY c "z">]><r>ok</r>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn benign_doctype_without_nested_entities_is_allowed() {
    let plugin = xml_plugin();
    let body = r#"<!DOCTYPE r [<!ENTITY a "hello">]><r>world</r>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn entity_literal_inside_cdata_is_not_treated_as_declaration() {
    let plugin = xml_plugin();
    let body = r#"<root><![CDATA[<!ENTITY x "&y;">]]></root>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[tokio::test]
async fn nested_entity_rejection_can_be_disabled() {
    let plugin = BodyValidator::new(&json!({
        "validate_xml": true,
        "xml_reject_nested_entities": false
    }))
    .unwrap();
    // Same nesting as the billion-laughs body, but under the count cap and with
    // the nested-reference check disabled — allowed through.
    let body = r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>"#;
    let mut ctx = make_xml_ctx(body);
    let mut headers = make_xml_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

// ═══════════════════════════════════════════════════════════════════════
//  GHSA-w7x7-ppx9-5v74 — unknown configuration keys fail closed
// ═══════════════════════════════════════════════════════════════════════

fn reject_body(result: PluginResult) -> String {
    match result {
        PluginResult::Reject { body, .. } => body,
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn unknown_top_level_config_keys_are_rejected() {
    // Each case pairs an intended-but-misspelled control with a valid rule,
    // which is exactly the shape that used to be admitted while silently
    // dropping the misspelled enforcement.
    let configs = [
        json!({
            "required_fields": ["tenant"],
            "response_json_scheam": {"type": "object"}
        }),
        json!({
            "required_fields": ["tenant"],
            "protobuf_reject_unknown_field": true
        }),
        json!({"validate_xml": true, "xml_reject_nested_entites": false}),
        json!({"validate_xml": true, "content_type": ["application/xml"]}),
        json!({
            "required_fields": ["tenant"],
            "grpc_max_decompressed_size_byte": 10
        }),
        json!({
            "required_fields": ["tenant"],
            "response_requred_fields": ["id"]
        }),
    ];
    for config in configs {
        let result = BodyValidator::new(&config);
        let error = result.err().expect("unknown key must be rejected");
        assert!(error.contains("unknown configuration key"), "{error}");
    }
}

#[test]
fn unknown_top_level_config_keys_are_rejected_by_shape_only_validation() {
    // CP/admin admission uses the shape-only path; it must fail closed too.
    let config = json!({
        "required_fields": ["tenant"],
        "response_json_scheam": {"type": "object"}
    });
    let result = BodyValidator::validate_config(&config);
    let error = result.expect_err("shape-only validation must reject it");
    assert!(error.contains("unknown configuration key"), "{error}");
}

#[test]
fn unknown_protobuf_method_keys_are_rejected() {
    let config = json!({
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_method_messages": {
            "/test.Greeter/SayHello": {
                "request": "test.HelloRequest",
                "respones": "test.HelloResponse"
            }
        }
    });
    let result = BodyValidator::new(&config);
    let error = result.err().expect("misspelled direction must be rejected");
    assert!(error.contains("has an unknown key"), "{error}");
}

fn assert_redacted_configuration_error(
    config: serde_json::Value,
    expected_message: &str,
    forbidden: &[&str],
) {
    let runtime_error = BodyValidator::new(&config)
        .err()
        .expect("runtime construction must reject the invalid configuration");
    let shape_error = BodyValidator::validate_config(&config)
        .expect_err("shape-only admission must reject the invalid configuration");

    for (surface, error) in [("runtime", runtime_error), ("shape-only", shape_error)] {
        assert_eq!(
            error, expected_message,
            "{surface} rejection must use the stable categorical message"
        );
        for supplied in forbidden {
            assert!(
                !error.contains(*supplied),
                "{surface} rejection must redact supplied text {supplied:?}: {error}"
            );
        }
    }
}

#[test]
fn configuration_errors_redact_supplied_schema_and_shape_text() {
    const DRAFT: &str = "draft-BODY_VALIDATOR_CONFIG_CANARY";
    const EXTERNAL_REF: &str =
        "https://ref-user:BODY_VALIDATOR_CONFIG_CANARY_REF@example.com/schema";
    const LOCAL_REF: &str = "#/$defs/BODY_VALIDATOR_CONFIG_CANARY_LOCAL_REF";
    const ID_URI: &str = "https://id-user:BODY_VALIDATOR_CONFIG_CANARY_ID@example.com/schema";
    const SCHEMA_URI: &str =
        "https://schema-user:BODY_VALIDATOR_CONFIG_CANARY_SCHEMA@example.com/draft";
    const PATTERN: &str = "(?P<BODY_VALIDATOR_CONFIG_CANARY_PATTERN>[";
    const UNKNOWN_KEY: &str = "unknown_BODY_VALIDATOR_CONFIG_CANARY_KEY";
    const XML_ENTRY: &str = "{https://BODY_VALIDATOR_CONFIG_CANARY_XML@example.com/ns";
    const METHOD_PATH: &str = "/BODY_VALIDATOR_CONFIG_CANARY_METHOD/Call";
    const METHOD_KEY: &str = "BODY_VALIDATOR_CONFIG_CANARY_METHOD_KEY";

    assert_redacted_configuration_error(
        json!({"json_schema_draft": DRAFT}),
        "body_validator: 'json_schema_draft' must be 'draft2020-12' or 'draft7'",
        &[DRAFT],
    );
    assert_redacted_configuration_error(
        json!({"json_schema": {"$ref": EXTERNAL_REF}}),
        "body_validator: 'json_schema' has a non-local '$ref'; only local references \
         (starting with '#') are supported and no external reference is ever retrieved",
        &[EXTERNAL_REF, "BODY_VALIDATOR_CONFIG_CANARY_REF"],
    );
    assert_redacted_configuration_error(
        json!({"json_schema": {"$ref": LOCAL_REF}}),
        "body_validator: 'json_schema' has a local '$ref' JSON Pointer that resolves nowhere",
        &[LOCAL_REF, "BODY_VALIDATOR_CONFIG_CANARY_LOCAL_REF"],
    );
    assert_redacted_configuration_error(
        json!({"json_schema": {"$id": ID_URI, "type": "object"}}),
        "body_validator: 'json_schema' has a non-fragment '$id'; a base URI would allow \
         external reference resolution",
        &[ID_URI, "BODY_VALIDATOR_CONFIG_CANARY_ID"],
    );
    assert_redacted_configuration_error(
        json!({"json_schema": {"$schema": SCHEMA_URI, "type": "object"}}),
        "body_validator: 'json_schema' declares an unsupported '$schema'; configured draft is \
         'draft2020-12'",
        &[SCHEMA_URI, "BODY_VALIDATOR_CONFIG_CANARY_SCHEMA"],
    );
    assert_redacted_configuration_error(
        json!({"json_schema": {"type": "string", "pattern": PATTERN}}),
        "body_validator: 'json_schema' is not a valid draft2020-12 JSON Schema",
        &[PATTERN, "BODY_VALIDATOR_CONFIG_CANARY_PATTERN"],
    );
    assert_redacted_configuration_error(
        json!({
            "required_fields": ["tenant"],
            "unknown_BODY_VALIDATOR_CONFIG_CANARY_KEY": true
        }),
        &format!(
            "body_validator: unknown configuration key; allowed keys: {}",
            BODY_VALIDATOR_CONFIG_KEYS.join(", ")
        ),
        &[UNKNOWN_KEY, "BODY_VALIDATOR_CONFIG_CANARY_KEY"],
    );
    assert_redacted_configuration_error(
        json!({"required_xml_elements": [XML_ENTRY]}),
        "body_validator: 'required_xml_elements' entry at index 0 opens Clark notation with '{' \
         but never closes it with '}'",
        &[XML_ENTRY, "BODY_VALIDATOR_CONFIG_CANARY_XML"],
    );
    assert_redacted_configuration_error(
        json!({
            "protobuf_descriptor_path": test_descriptor_path(),
            "protobuf_method_messages": {
                "/BODY_VALIDATOR_CONFIG_CANARY_METHOD/Call": {
                    "request": "test.HelloRequest",
                    "BODY_VALIDATOR_CONFIG_CANARY_METHOD_KEY": true
                }
            }
        }),
        &format!(
            "body_validator: a 'protobuf_method_messages' entry has an unknown key; allowed \
             keys: {}",
            BODY_VALIDATOR_PROTOBUF_METHOD_KEYS.join(", ")
        ),
        &[
            METHOD_PATH,
            METHOD_KEY,
            "BODY_VALIDATOR_CONFIG_CANARY_METHOD",
        ],
    );
}

#[test]
fn every_documented_config_key_is_accepted_together() {
    // The allow-list must not be narrower than the real surface: a config
    // that sets every key at once still constructs.
    let config = json!({
        "json_schema": {"type": "object"},
        "json_schema_draft": "draft2020-12",
        "required_fields": ["tenant"],
        "validate_xml": true,
        "required_xml_elements": ["item"],
        "xml_max_entities": 10,
        "xml_reject_nested_entities": true,
        "content_types": ["application/json"],
        "response_json_schema": {"type": "object"},
        "response_required_fields": ["id"],
        "response_validate_xml": true,
        "response_required_xml_elements": ["result"],
        "response_content_types": ["application/json"],
        "protobuf_descriptor_path": test_descriptor_path(),
        "protobuf_request_type": "test.HelloRequest",
        "protobuf_response_type": "test.HelloResponse",
        "protobuf_method_messages": {
            "/test.Greeter/SayHello": {
                "request": "test.HelloRequest",
                "response": "test.HelloResponse"
            }
        },
        "protobuf_reject_unknown_fields": true,
        "grpc_max_decompressed_size_bytes": 1024
    });

    let object = config.as_object().expect("object config");
    let mut exercised: Vec<&str> = object.keys().map(String::as_str).collect();
    exercised.sort_unstable();
    let mut allowed: Vec<&str> = BODY_VALIDATOR_CONFIG_KEYS.to_vec();
    allowed.sort_unstable();
    assert_eq!(exercised, allowed, "must exercise every allowed key");

    BodyValidator::new(&config).expect("full config must construct");
}

// ═══════════════════════════════════════════════════════════════════════
//  GHSA-5883-wg84-7rhm — JSON Schema is compiled, not approximated
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn json_schema_local_ref_and_defs_are_enforced() {
    let plugin = json_schema_plugin(json!({
        "$defs": {
            "Approved": {
                "type": "object",
                "required": ["approved"],
                "properties": {"approved": {"const": true}}
            }
        },
        "$ref": "#/$defs/Approved"
    }));

    for body in [r#"{}"#, r#"{"approved": false}"#] {
        let mut ctx = make_json_ctx(body);
        let mut headers = make_json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }

    let mut ctx = make_json_ctx(r#"{"approved": true}"#);
    let mut headers = make_json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn local_pointer_into_literal_container_enables_request_unique_items_policy() {
    let plugin = json_schema_plugin(json!({
        "default": {
            "hidden": {
                "type": "array",
                "uniqueItems": true
            }
        },
        "$ref": "#/default/hidden"
    }));

    // `serde_json/preserve_order` makes these objects insertion-order-distinct.
    // Reaching uniqueItems through the pointer must still enable construction-
    // time canonicalization and enforce JSON's order-insensitive equality.
    let mut ctx = make_json_ctx(r#"[{"a": 1, "b": 2}, {"b": 2, "a": 1}]"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[tokio::test]
async fn local_pointer_into_literal_container_enables_response_unique_items_policy() {
    let plugin = response_schema_plugin(json!({
        "examples": [{
            "hidden": {
                "type": "array",
                "uniqueItems": true
            }
        }],
        "$ref": "#/examples/0/hidden"
    }));

    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"[{"left": 1, "right": 2}, {"right": 2, "left": 1}]"#;
    assert_reject(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, body)
            .await,
        Some(502),
    );
}

#[test]
fn local_pointer_targets_apply_nested_forbidden_policy_in_both_directions() {
    let schema = json!({
        "examples": [{
            "hidden": {
                "properties": {
                    "secret": {
                        "$ref": "https://example.com/forbidden.json"
                    }
                }
            }
        }],
        "$ref": "#/examples/0/hidden"
    });

    for config in [
        json!({"json_schema": schema.clone()}),
        json!({"response_json_schema": schema.clone()}),
    ] {
        let error = BodyValidator::new(&config)
            .err()
            .expect("referenced nested external policy must be rejected");
        assert!(error.contains("non-local '$ref'"), "{error}");
    }
}

#[test]
fn unreferenced_literal_containers_remain_inactive_in_both_directions() {
    let schema = json!({
        "type": "string",
        "default": {
            "hidden": {
                "properties": {
                    "secret": {
                        "$ref": "https://literal.example/not-active.json"
                    }
                }
            }
        }
    });
    for config in [
        json!({"json_schema": schema.clone()}),
        json!({"response_json_schema": schema.clone()}),
    ] {
        BodyValidator::new(&config)
            .expect("an unreferenced literal container must not activate schema policy");
    }
}

#[test]
fn local_pointer_resolution_handles_cycles_root_and_encoded_segments() {
    let cyclic = json!({
        "default": {
            "a": {"$ref": "#/default/b"},
            "b": {"$ref": "#/default/a"}
        },
        "$ref": "#/default/a"
    });
    BodyValidator::new(&json!({"json_schema": cyclic}))
        .expect("identity deduplication must terminate on a pointer cycle");

    let root_cycle = json!({
        "default": {
            "literal": {
                "$ref": "https://literal.example/not-active.json"
            }
        },
        "$ref": "#"
    });
    BodyValidator::new(&json!({"json_schema": root_cycle}))
        .expect("root '#' must deduplicate without activating literal default data");

    let encoded = json!({
        "default": {
            "hidden schema": {
                "a/b~c": {"type": "integer"}
            }
        },
        "$ref": "#/default/hidden%20schema/a~1b~0c"
    });
    BodyValidator::new(&json!({"json_schema": encoded}))
        .expect("percent decoding and JSON Pointer unescaping must match referencing");

    let invalid_encoding = json!({
        "default": {"hidden": {"type": "string"}},
        "$ref": "#/default/%FF"
    });
    let error = BodyValidator::new(&json!({"json_schema": invalid_encoding}))
        .err()
        .expect("invalid UTF-8 pointer encoding must fail");
    assert!(error.contains("invalid UTF-8 percent encoding"), "{error}");

    for invalid_pointer in ["#/default/missing", "#/examples/not-an-index"] {
        let schema = json!({
            "default": {"hidden": {"type": "string"}},
            "examples": [{"type": "string"}],
            "$ref": invalid_pointer
        });
        let error = BodyValidator::new(&json!({"json_schema": schema}))
            .err()
            .expect("an invalid local pointer must fail construction");
        assert!(
            error.contains("resolves nowhere") || error.contains("invalid array index"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn percent_encoded_local_pointer_target_is_decisive_at_runtime() {
    let plugin = json_schema_plugin(json!({
        "default": {
            "hidden schema": {
                "a/b~c": {"type": "integer"}
            }
        },
        "$ref": "#/default/hidden%20schema/a~1b~0c"
    }));

    let mut ctx = make_json_ctx("7");
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let mut ctx = make_json_ctx(r#""seven""#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[test]
fn draft_specific_definition_maps_match_referencing_semantics() {
    // referencing 0.46.5 does not walk `$defs` under Draft 7, so its contents
    // remain literal when nothing points at them.
    let draft7_literal = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "type": "string",
            "$defs": {
                "hidden": {
                    "$ref": "https://literal.example/not-active.json"
                }
            }
        }
    });
    BodyValidator::new(&draft7_literal).expect("Draft 7 $defs is not a schema container");

    let draft7_dynamic_ref_literal = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "type": "string",
            "$dynamicRef": "https://literal.example/not-active.json"
        }
    });
    BodyValidator::new(&draft7_dynamic_ref_literal)
        .expect("Draft 7 $dynamicRef is an unknown, non-reference keyword");

    // A direct pointer still makes that same object an active schema target.
    let draft7_referenced = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "$defs": {
                "hidden": {
                    "$ref": "https://example.com/forbidden.json"
                }
            },
            "$ref": "#/$defs/hidden"
        }
    });
    let error = BodyValidator::new(&draft7_referenced)
        .err()
        .expect("Draft 7 pointer target under $defs must be audited");
    assert!(error.contains("non-local '$ref'"), "{error}");

    // The library's 2020-12 walker deliberately retains `definitions` as a
    // schema-bearing compatibility map in addition to `$defs`.
    let draft202012_definitions = json!({
        "json_schema": {
            "definitions": {
                "active": {
                    "$ref": "https://example.com/forbidden.json"
                }
            }
        }
    });
    let error = BodyValidator::new(&draft202012_definitions)
        .err()
        .expect("2020-12 definitions values are schema positions");
    assert!(error.contains("non-local '$ref'"), "{error}");
}

#[test]
fn anchor_targets_are_covered_by_the_ordinary_schema_position_walk() {
    // referencing indexes anchors only at positions reached by its configured-
    // draft child walker. `$defs/guarded` is therefore already audited without
    // a separate anchor-target traversal.
    let schema = json!({
        "$defs": {
            "guarded": {
                "$anchor": "guarded",
                "properties": {
                    "secret": {
                        "$ref": "https://example.com/forbidden.json"
                    }
                }
            }
        },
        "$ref": "#guarded"
    });
    let error = BodyValidator::new(&json!({"json_schema": schema}))
        .err()
        .expect("policy at an anchored schema position must be enforced");
    assert!(error.contains("non-local '$ref'"), "{error}");
}

#[tokio::test]
async fn json_schema_nested_and_recursive_local_refs_are_enforced() {
    let plugin = json_schema_plugin(json!({
        "$defs": {
            "Node": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "child": {"$ref": "#/$defs/Node"}
                }
            }
        },
        "$ref": "#/$defs/Node"
    }));

    let ok = r#"{"name": "a", "child": {"name": "b"}}"#;
    let mut ctx = make_json_ctx(ok);
    let mut headers = make_json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let bad = r#"{"name": "a", "child": {"child": {"name": "c"}}}"#;
    let mut ctx = make_json_ctx(bad);
    let mut headers = make_json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn json_schema_union_type_array_is_enforced() {
    let plugin = json_schema_plugin(json!({
        "type": "object",
        "properties": {"note": {"type": ["string", "null"]}}
    }));

    for body in [r#"{"note": "hi"}"#, r#"{"note": null}"#] {
        let mut ctx = make_json_ctx(body);
        let mut headers = make_json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }

    let mut ctx = make_json_ctx(r#"{"note": 7}"#);
    let mut headers = make_json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn json_schema_property_named_id_compiles_for_request_and_response() {
    let schema = json!({
        "type": "object",
        "required": ["id"],
        "properties": {"id": {"type": "integer"}}
    });

    let request_plugin = json_schema_plugin(schema.clone());
    let mut ctx = make_json_ctx(r#"{"id": 7}"#);
    let mut headers = make_json_headers();
    assert_continue(request_plugin.before_proxy(&mut ctx, &mut headers).await);

    let response_plugin = response_schema_plugin(schema);
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    assert_continue(
        response_plugin
            .on_final_response_body(&mut ctx, 200, &headers, br#"{"id": 7}"#)
            .await,
    );
}

#[test]
fn schema_keyword_spellings_are_allowed_as_property_and_definition_names() {
    let names = ["$ref", "$id", "$schema", "$vocabulary", "$dynamicRef"];
    let mut properties = serde_json::Map::new();
    let mut definitions = serde_json::Map::new();
    for name in names {
        properties.insert(name.to_string(), json!({"type": "string"}));
        definitions.insert(name.to_string(), json!({"type": "string"}));
    }

    let draft202012 = json!({
        "json_schema": {
            "type": "object",
            "properties": properties.clone(),
            "$defs": definitions.clone()
        }
    });
    BodyValidator::new(&draft202012).expect("2020-12 names are not active keywords");

    let draft7 = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "type": "object",
            "properties": properties,
            "definitions": definitions
        }
    });
    BodyValidator::new(&draft7).expect("Draft 7 names are not active keywords");
}

#[tokio::test]
async fn schema_literal_objects_do_not_activate_schema_keywords() {
    let literal = json!({
        "id": 7,
        "$ref": "https://literal.example/schema.json",
        "$id": 9,
        "$schema": false,
        "$vocabulary": {"https://literal.example/vocab": true},
        "$dynamicRef": "file:///literal.json"
    });
    let plugin = json_schema_plugin(json!({
        "type": "object",
        "required": ["enum_value", "const_value"],
        "properties": {
            "enum_value": {"enum": [literal.clone()]},
            "const_value": {"const": literal.clone()},
            "defaulted": {"type": "object", "default": literal.clone()},
            "exampled": {"type": "object", "examples": [literal.clone()]}
        },
        "default": literal.clone(),
        "examples": [literal.clone()]
    }));
    let body = json!({
        "enum_value": literal.clone(),
        "const_value": literal,
        "defaulted": {},
        "exampled": {}
    })
    .to_string();
    let mut ctx = make_json_ctx(&body);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
}

#[test]
fn non_local_references_are_rejected_in_supported_subschema_positions() {
    let external = json!({"$ref": "https://example.com/nested.json"});
    let draft202012 = [
        json!({"properties": {"x": external.clone()}}),
        json!({"patternProperties": {"^x": external.clone()}}),
        json!({"$defs": {"x": external.clone()}}),
        json!({"definitions": {"x": external.clone()}}),
        json!({"dependentSchemas": {"x": external.clone()}}),
        json!({"allOf": [external.clone()]}),
        json!({"anyOf": [external.clone()]}),
        json!({"oneOf": [external.clone()]}),
        json!({"prefixItems": [external.clone()]}),
        json!({"items": external.clone()}),
        json!({"additionalProperties": external.clone()}),
        json!({"unevaluatedProperties": external.clone()}),
        json!({"contains": external.clone()}),
        json!({"propertyNames": external.clone()}),
        json!({"not": external.clone()}),
        json!({"if": external.clone()}),
        json!({"then": external.clone()}),
        json!({"else": external.clone()}),
        json!({"unevaluatedItems": external.clone()}),
        json!({"contentSchema": external.clone()}),
    ];
    for schema in draft202012 {
        let config = json!({"json_schema": schema});
        let error = BodyValidator::new(&config)
            .err()
            .expect("nested non-local reference must be rejected");
        assert!(error.contains("non-local '$ref'"), "{error}");
    }

    let draft7 = [
        json!({"dependencies": {"x": external.clone()}}),
        json!({"items": [true, external.clone()]}),
        json!({"additionalItems": external}),
    ];
    for schema in draft7 {
        let config = json!({
            "json_schema_draft": "draft7",
            "json_schema": schema
        });
        let error = BodyValidator::new(&config)
            .err()
            .expect("nested Draft 7 non-local reference must be rejected");
        assert!(error.contains("non-local '$ref'"), "{error}");
    }
}

#[test]
fn nested_schema_nodes_still_enforce_reference_identifier_and_dialect_policy() {
    let schemas = [
        json!({"properties": {"x": {"$dynamicRef": "https://example.com/dynamic"}}}),
        json!({"properties": {"x": {"$id": "https://example.com/base"}}}),
        json!({"properties": {"x": {"id": "https://example.com/legacy-base"}}}),
        json!({"properties": {"x": {"$vocabulary": {"https://example.com/v": true}}}}),
        json!({
            "properties": {
                "x": {
                    "$schema": "http://json-schema.org/draft-07/schema#"
                }
            }
        }),
    ];

    for schema in schemas {
        assert!(
            BodyValidator::new(&json!({"json_schema": schema})).is_err(),
            "nested schema policy must fail closed"
        );
    }
}

#[tokio::test]
async fn boolean_subschemas_compile_and_are_enforced() {
    let plugin = json_schema_plugin(json!({
        "type": "object",
        "properties": {
            "allowed": true,
            "denied": false
        }
    }));

    let mut ctx = make_json_ctx(r#"{"allowed": {"anything": true}}"#);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let mut ctx = make_json_ctx(r#"{"denied": null}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

#[test]
fn malformed_schemas_fail_configuration_closed() {
    let configs = [
        // Invalid type name — used to be treated as "any type is valid".
        json!({"json_schema": {"type": "objcet"}}),
        // Malformed keyword shapes.
        json!({"json_schema": {"required": "tenant"}}),
        json!({"json_schema": {"properties": []}}),
        json!({"json_schema": {"minLength": "3"}}),
        // Unresolvable local reference.
        json!({"json_schema": {"$ref": "#/$defs/Missing"}}),
        // Non-local references would require retrieval.
        json!({"json_schema": {"$ref": "https://example.com/s.json"}}),
        json!({"json_schema": {"$ref": "file:///etc/schema.json"}}),
        json!({"json_schema": {"$ref": "other.json#/$defs/X"}}),
        // A base URI could re-point an otherwise local reference.
        json!({
            "json_schema": {"$id": "https://example.com/root", "type": "object"}
        }),
        // Custom vocabularies cannot be honoured.
        json!({
            "json_schema": {"$vocabulary": {"https://example.com/v": true}}
        }),
        // Draft mismatch must be explicit, not silently reinterpreted.
        json!({
            "json_schema": {
                "$schema": "http://json-schema.org/draft-04/schema#",
                "type": "object"
            }
        }),
        json!({
            "json_schema_draft": "draft4",
            "json_schema": {"type": "object"}
        }),
        // The response direction uses the same compiler.
        json!({"response_json_schema": {"type": "objcet"}}),
        json!({
            "response_json_schema": {"$ref": "https://example.com/s.json"}
        }),
    ];
    for config in configs {
        assert!(
            BodyValidator::new(&config).is_err(),
            "config should fail closed: {config:?}"
        );
        assert!(
            BodyValidator::validate_config(&config).is_err(),
            "shape-only validation should fail closed: {config:?}"
        );
    }
}

#[test]
fn draft7_schemas_compile_under_the_matching_configured_draft() {
    let config = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "definitions": {"Id": {"type": "string"}},
            "properties": {"id": {"$ref": "#/definitions/Id"}}
        }
    });
    BodyValidator::new(&config).expect("draft7 schema must compile");

    let mismatched = json!({
        "json_schema_draft": "draft2020-12",
        "json_schema": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object"
        }
    });
    assert!(BodyValidator::new(&mismatched).is_err());
}

#[test]
fn non_string_schema_keywords_fail_closed() {
    // Active keyword values must be strings; a typed mismatch used to skip the
    // decisive policy check while admission still reported the schema as live.
    let cases = [
        (json!({"$ref": true}), "non-string '$ref'"),
        (json!({"$dynamicRef": 7}), "non-string '$dynamicRef'"),
        (json!({"$id": false}), "non-string '$id'"),
        (json!({"id": ["legacy"]}), "non-string 'id'"),
        (json!({"$schema": {"uri": "x"}}), "non-string '$schema'"),
    ];
    for (schema, needle) in cases {
        let error = BodyValidator::new(&json!({"json_schema": schema}))
            .err()
            .expect("non-string schema keyword must fail closed");
        assert!(error.contains(needle), "expected {needle:?} in {error}");
    }
}

#[test]
fn draft7_schema_mismatch_names_the_configured_draft() {
    let mismatched = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        }
    });
    let error = BodyValidator::new(&mismatched)
        .err()
        .expect("draft mismatch must fail closed");
    assert!(error.contains("unsupported '$schema'"), "{error}");
    assert!(
        error.contains("draft7"),
        "rejection must name the configured draft: {error}"
    );
}

#[test]
fn draft7_boolean_dependencies_are_active_schema_positions() {
    // Draft 7 dependency values may be schemas (object or boolean) or property-
    // name arrays. A boolean schema must be walked so `false` is decisive.
    let config = json!({
        "json_schema_draft": "draft7",
        "json_schema": {
            "type": "object",
            "dependencies": {
                "flag": true
            }
        }
    });
    BodyValidator::new(&config).expect("boolean dependency schema must compile");
}

#[test]
fn local_pointer_rejects_scalar_and_array_out_of_range_targets() {
    let array_oob = json!({
        "examples": [{"type": "string"}],
        "$ref": "#/examples/5"
    });
    let error = BodyValidator::new(&json!({"json_schema": array_oob}))
        .err()
        .expect("array out-of-range pointer must fail");
    assert!(error.contains("resolves nowhere"), "{error}");

    let through_scalar = json!({
        "type": "string",
        "$ref": "#/type/next"
    });
    let error = BodyValidator::new(&json!({"json_schema": through_scalar}))
        .err()
        .expect("pointer through a scalar must fail");
    assert!(error.contains("resolves nowhere"), "{error}");
}

#[test]
fn local_pointer_unusual_tilde_escapes_still_resolve() {
    // referencing keeps unknown `~` escapes and a trailing `~` as literal text
    // after the `~0` / `~1` substitutions. Construction must follow that exact
    // spelling so a key that only exists under the library's unescape is found.
    let unknown_escape = json!({
        "default": {
            "a~2b": {"type": "integer"}
        },
        "$ref": "#/default/a~2b"
    });
    BodyValidator::new(&json!({"json_schema": unknown_escape}))
        .expect("unknown tilde escape must round-trip as a literal key");

    let trailing_tilde = json!({
        "default": {
            "trail~": {"type": "string"}
        },
        "$ref": "#/default/trail~"
    });
    BodyValidator::new(&json!({"json_schema": trailing_tilde}))
        .expect("trailing tilde must round-trip as a literal key");
}

#[test]
fn schema_recursion_and_size_budgets_are_bounded() {
    // 40 levels of nesting exceeds the 32-level budget.
    let mut schema = json!({"type": "string"});
    for _ in 0..40 {
        schema = json!({"type": "object", "properties": {"next": schema}});
    }
    let deep = json!({"json_schema": schema});
    let error = BodyValidator::new(&deep)
        .err()
        .expect("over-deep is rejected");
    assert!(error.contains("schema budget"), "{error}");

    // A wide schema past the node budget is rejected on size, not depth.
    let mut properties = serde_json::Map::new();
    for index in 0..12_000 {
        properties.insert(format!("f{index}"), json!({"type": "string"}));
    }
    let properties = serde_json::Value::Object(properties);
    let wide = json!({"json_schema": {"properties": properties}});
    let error = BodyValidator::new(&wide)
        .err()
        .expect("over-wide is rejected");
    assert!(error.contains("schema budget"), "{error}");

    // Literal annotation data is still part of the supplied JSON value and
    // cannot evade either budget merely because it is not a schema position.
    let mut literal = json!("leaf");
    for _ in 0..40 {
        literal = json!({"annotation": literal});
    }
    let deep_literal = json!({
        "json_schema": {
            "type": "string",
            "default": literal
        }
    });
    let error = BodyValidator::new(&deep_literal)
        .err()
        .expect("over-deep literal annotation is rejected");
    assert!(error.contains("schema budget"), "{error}");

    let wide_literal = json!({
        "json_schema": {
            "type": "integer",
            "enum": vec![json!(0); 20_000]
        }
    });
    let error = BodyValidator::new(&wide_literal)
        .err()
        .expect("over-wide literal instance data is rejected");
    assert!(error.contains("schema budget"), "{error}");
}

#[tokio::test]
async fn schema_violations_do_not_echo_request_or_response_values() {
    let request_plugin = json_schema_plugin(json!({
        "type": "object",
        "properties": {"ssn": {"const": "redacted"}}
    }));
    let mut ctx = make_json_ctx(r#"{"ssn": "123-45-6789"}"#);
    let mut headers = make_json_headers();
    let result = request_plugin.before_proxy(&mut ctx, &mut headers).await;
    let body = reject_body(result);
    assert!(
        !body.contains("123-45-6789"),
        "request rejection must not echo the rejected value: {body}"
    );
    assert!(
        body.contains("/ssn"),
        "request rejection should locate the failure: {body}"
    );

    let response_plugin = response_schema_plugin(json!({
        "type": "object",
        "properties": {"token": {"const": "redacted"}}
    }));
    let mut ctx = make_response_ctx();
    let headers = response_json_headers();
    let body = br#"{"token": "upstream-secret"}"#;
    let result = response_plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    let body = reject_body(result);
    assert!(
        !body.contains("upstream-secret"),
        "response rejection must not echo the upstream value: {body}"
    );
    assert!(
        !body.contains("/token"),
        "response rejection must not describe the upstream shape: {body}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  GHSA-mg9q-6h9j-9mmv — XML well-formedness is parser-decided
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn malformed_xml_documents_are_rejected() {
    let bodies = [
        // Two document elements.
        "<approved/><payload/>",
        "<a></a><b></b>",
        // Text outside the root element.
        "<root/>trailing",
        // Invalid XML names.
        "<1root></1root>",
        // Attribute grammar.
        r#"<root role=admin></root>"#,
        r#"<root role="safe" role="admin"></root>"#,
        r#"<root role="unterminated></root>"#,
        r#"<root role></root>"#,
        // Undeclared or malformed entity references.
        "<root>&undeclared;</root>",
        "<root>bare & ampersand</root>",
        // Malformed declaration and unterminated constructs.
        "<?xml version=\"1.0\"><root/>",
        "<root><!-- unterminated</root>",
        "<root><![CDATA[unterminated</root>",
        // Unknown namespace prefix.
        r#"<ns:root></ns:root>"#,
    ];
    for body in bodies {
        let plugin = xml_plugin();
        let mut ctx = make_xml_ctx(body);
        let mut headers = make_xml_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
    }
}

#[tokio::test]
async fn well_formed_xml_edge_cases_are_accepted() {
    let bodies = [
        // A quoted '>' inside an attribute value does not end the tag.
        r#"<root attr="a > b"><child/></root>"#,
        // Declared namespaces resolve.
        NAMESPACED_XML,
        // Predefined entities and character references are valid.
        "<root>&amp;&lt;&#65;</root>",
        // Comments around the root element are allowed.
        "<!-- lead --><root/><!-- trail -->",
    ];
    for body in bodies {
        let plugin = xml_plugin();
        let mut ctx = make_xml_ctx(body);
        let mut headers = make_xml_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }
}

#[tokio::test]
async fn exact_xml_document_text_preserves_outer_whitespace_semantics() {
    let legal = " \t\r\n<root/>\r\n\t ";
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx(legal);
    let mut headers = make_xml_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let plugin = BodyValidator::new(&json!({"response_validate_xml": true})).unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    assert_continue(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, legal.as_bytes())
            .await,
    );

    for body in ["\u{00a0}<root/>", "<root/>\u{0085}"] {
        let plugin = xml_plugin();
        let mut ctx = make_xml_ctx(body);
        let mut headers = make_xml_headers();
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

        let plugin = BodyValidator::new(&json!({"response_validate_xml": true})).unwrap();
        let mut ctx = make_response_ctx();
        let headers = response_xml_headers();
        assert_reject(
            plugin
                .on_final_response_body(&mut ctx, 200, &headers, body.as_bytes())
                .await,
            Some(502),
        );
    }
}

#[tokio::test]
async fn external_xml_identifiers_are_rejected_for_request_and_response() {
    let bodies = [
        r#"<!DOCTYPE r SYSTEM "https://example.com/external.dtd"><r/>"#,
        r#"<!DOCTYPE r PUBLIC "-//Example//DTD R 1.0//EN" "https://example.com/r.dtd"><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY x PUBLIC "-//a//b" "http://e/x">]><r>&x;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY % p SYSTEM "http://e/e.dtd">%p;]><r/>"#,
    ];
    for body in bodies {
        let plugin = xml_plugin();
        let mut ctx = make_xml_ctx(body);
        let mut headers = make_xml_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));

        let plugin = BodyValidator::new(&json!({"response_validate_xml": true})).unwrap();
        let mut ctx = make_response_ctx();
        let headers = response_xml_headers();
        let result = plugin
            .on_final_response_body(&mut ctx, 200, &headers, body.as_bytes())
            .await;
        assert_reject(result, Some(502));
    }
}

#[tokio::test]
async fn internal_dtd_and_quoted_keyword_text_remain_valid() {
    let bodies = [
        r#"<!DOCTYPE r [<!ENTITY safe "hello">]><r>&safe;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY unused "<!DOCTYPE fake SYSTEM 'x'>">]><r/>"#,
        r#"<r><!-- <!DOCTYPE fake SYSTEM "x"> --><![CDATA[<!DOCTYPE fake PUBLIC "x" "y">]]></r>"#,
    ];
    for body in bodies {
        let plugin = xml_plugin();
        let mut ctx = make_xml_ctx(body);
        let mut headers = make_xml_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

        let plugin = BodyValidator::new(&json!({"response_validate_xml": true})).unwrap();
        let mut ctx = make_response_ctx();
        let headers = response_xml_headers();
        assert_continue(
            plugin
                .on_final_response_body(&mut ctx, 200, &headers, body.as_bytes())
                .await,
        );
    }
}

/// `item` in the `http://example.com/ns` namespace.
const NAMESPACED_XML: &str = r#"<ns:root xmlns:ns="http://e.com/ns"><ns:item/></ns:root>"#;

#[tokio::test]
async fn required_xml_elements_match_parsed_expanded_names() {
    // A bare configured name matches the local name in any namespace.
    let plugin = xml_plugin_with_required(vec!["item"]);
    let mut ctx = make_xml_ctx(NAMESPACED_XML);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Clark notation requires the expanded namespace URI to match too.
    let required = vec!["{http://e.com/ns}item"];
    let plugin = xml_plugin_with_required(required);
    let mut ctx = make_xml_ctx(NAMESPACED_XML);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let required = vec!["{http://e.com/other}item"];
    let plugin = xml_plugin_with_required(required);
    let mut ctx = make_xml_ctx(NAMESPACED_XML);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));

    // "{}local" requires the element to be in no namespace.
    let plugin = xml_plugin_with_required(vec!["{}item"]);
    let mut ctx = make_xml_ctx("<root><item/></root>");
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let plugin = xml_plugin_with_required(vec!["{}item"]);
    let mut ctx = make_xml_ctx(NAMESPACED_XML);
    let mut headers = make_xml_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[test]
fn malformed_required_xml_element_entries_are_rejected() {
    let configs = [
        json!({"required_xml_elements": ["{http://example.com/ns"]}),
        json!({"required_xml_elements": ["{http://example.com/ns}"]}),
        json!({"response_required_xml_elements": ["{ns"]}),
        // Local names must not embed Clark braces after the namespace closes.
        json!({"required_xml_elements": ["item{bad}"]}),
        json!({"response_required_xml_elements": ["{http://e.com/ns}a}b"]}),
    ];
    for config in configs {
        assert!(
            BodyValidator::new(&config).is_err(),
            "malformed entry must be rejected: {config:?}"
        );
    }
}

#[tokio::test]
async fn malformed_response_xml_does_not_echo_the_upstream_body() {
    let config = json!({"response_validate_xml": true});
    let plugin = BodyValidator::new(&config).unwrap();
    let mut ctx = make_response_ctx();
    let headers = response_xml_headers();
    let body = b"<approved/><secret>upstream-secret</secret>";
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    let body = reject_body(result);
    assert!(
        !body.contains("upstream-secret"),
        "XML rejection must not echo upstream content: {body}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  GHSA-qvrp-m3v9-345m — proto2 required-field initialization
// ═══════════════════════════════════════════════════════════════════════
//
// The checked-in `tests/fixtures/test_validator.bin` fixture is proto3, which
// has no `required` cardinality. These tests build a proto2
// `FileDescriptorSet` in-process by encoding `descriptor.proto` messages
// directly, so no `protoc` run or new fixture binary is needed.

const PB_LABEL_OPTIONAL: u64 = 1;
const PB_LABEL_REQUIRED: u64 = 2;
const PB_LABEL_REPEATED: u64 = 3;
const PB_TYPE_INT32: u64 = 5;
const PB_TYPE_STRING: u64 = 9;
const PB_TYPE_MESSAGE: u64 = 11;
const PB_COMMAND: &str = ".t2.Command";
const PB_MAP_ENTRY: &str = ".t2.MapHolder.EntriesEntry";

fn pb_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn pb_tag(out: &mut Vec<u8>, field: u32, wire: u64) {
    pb_varint(out, (u64::from(field) << 3) | wire);
}

fn pb_len_field(field: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    pb_tag(&mut out, field, 2);
    pb_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

fn pb_str_field(field: u32, value: &str) -> Vec<u8> {
    pb_len_field(field, value.as_bytes())
}

fn pb_varint_field(field: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    pb_tag(&mut out, field, 0);
    pb_varint(&mut out, value);
    out
}

/// One `FieldDescriptorProto`.
fn pb_field(name: &str, number: u32, label: u64, kind: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(pb_str_field(1, name));
    out.extend(pb_varint_field(3, u64::from(number)));
    out.extend(pb_varint_field(4, label));
    out.extend(pb_varint_field(5, kind));
    out
}

/// A message-typed `FieldDescriptorProto` (`type_name` is field 6).
fn pb_message_field(name: &str, number: u32, label: u64, ty: &str) -> Vec<u8> {
    let mut out = pb_field(name, number, label, PB_TYPE_MESSAGE);
    out.extend(pb_str_field(6, ty));
    out
}

/// Attach `oneof_index` (field 9) to an existing field descriptor.
fn pb_in_oneof(mut field: Vec<u8>, index: u64) -> Vec<u8> {
    field.extend(pb_varint_field(9, index));
    field
}

/// One `DescriptorProto`.
fn pb_message(name: &str, fields: &[Vec<u8>]) -> Vec<u8> {
    let mut out = pb_str_field(1, name);
    for field in fields {
        out.extend(pb_len_field(2, field));
    }
    out
}

fn pb_with_nested(mut message: Vec<u8>, nested: &[u8]) -> Vec<u8> {
    message.extend(pb_len_field(3, nested));
    message
}

/// Set `MessageOptions.map_entry` (options is field 7; map_entry is field 7).
fn pb_as_map_entry(mut message: Vec<u8>) -> Vec<u8> {
    let options = pb_varint_field(7, 1);
    message.extend(pb_len_field(7, &options));
    message
}

fn pb_with_oneof(mut message: Vec<u8>, name: &str) -> Vec<u8> {
    let oneof = pb_str_field(1, name);
    message.extend(pb_len_field(8, &oneof));
    message
}

/// A proto2 `FileDescriptorSet` for package `t2`:
///
/// ```proto
/// syntax = "proto2";
/// package t2;
/// message Command   { required string action = 1; optional int32 n = 2; }
/// message Wrapper   { optional Command inner = 1; }
/// message Batch     { repeated Command items = 1; }
/// message MapHolder { map<string, Command> entries = 1; }
/// message Choice    { oneof pick { Command cmd = 1; string other = 2; } }
/// message Defaulted { required string label = 1; required int32 count = 2; }
/// message Reply     { required string status = 1; }
/// ```
fn proto2_descriptor_set() -> Vec<u8> {
    let action = pb_field("action", 1, PB_LABEL_REQUIRED, PB_TYPE_STRING);
    let retries = pb_field("n", 2, PB_LABEL_OPTIONAL, PB_TYPE_INT32);
    let command = pb_message("Command", &[action, retries]);

    let inner = pb_message_field("inner", 1, PB_LABEL_OPTIONAL, PB_COMMAND);
    let wrapper = pb_message("Wrapper", &[inner]);

    let items = pb_message_field("items", 1, PB_LABEL_REPEATED, PB_COMMAND);
    let batch = pb_message("Batch", &[items]);

    let key = pb_field("key", 1, PB_LABEL_OPTIONAL, PB_TYPE_STRING);
    let value = pb_message_field("value", 2, PB_LABEL_OPTIONAL, PB_COMMAND);
    let entry = pb_message("EntriesEntry", &[key, value]);
    let entry = pb_as_map_entry(entry);
    let entries = pb_message_field("entries", 1, PB_LABEL_REPEATED, PB_MAP_ENTRY);
    let map_holder = pb_message("MapHolder", &[entries]);
    let map_holder = pb_with_nested(map_holder, &entry);

    let cmd = pb_message_field("cmd", 1, PB_LABEL_OPTIONAL, PB_COMMAND);
    let cmd = pb_in_oneof(cmd, 0);
    let other = pb_field("other", 2, PB_LABEL_OPTIONAL, PB_TYPE_STRING);
    let other = pb_in_oneof(other, 0);
    let choice = pb_message("Choice", &[cmd, other]);
    let choice = pb_with_oneof(choice, "pick");

    let label = pb_field("label", 1, PB_LABEL_REQUIRED, PB_TYPE_STRING);
    let count = pb_field("count", 2, PB_LABEL_REQUIRED, PB_TYPE_INT32);
    let defaulted = pb_message("Defaulted", &[label, count]);

    let status = pb_field("status", 1, PB_LABEL_REQUIRED, PB_TYPE_STRING);
    let reply = pb_message("Reply", &[status]);

    let mut file = pb_str_field(1, "t2.proto");
    file.extend(pb_str_field(2, "t2"));
    // `syntax` is intentionally omitted: absent means proto2.
    let messages = [
        command, wrapper, batch, map_holder, choice, defaulted, reply,
    ];
    for message in messages {
        file.extend(pb_len_field(4, &message));
    }
    pb_len_field(1, &file)
}

fn proto2_descriptor_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes = proto2_descriptor_set();
    std::fs::write(dir.path().join("t2.bin"), bytes).expect("write pb set");
    dir
}

fn proto2_path(dir: &tempfile::TempDir) -> String {
    dir.path().join("t2.bin").to_string_lossy().into_owned()
}

fn proto2_plugin(dir: &tempfile::TempDir, message: &str) -> BodyValidator {
    let config = json!({
        "protobuf_descriptor_path": proto2_path(dir),
        "protobuf_request_type": message
    });
    BodyValidator::new(&config).expect("proto2 plugin config")
}

fn grpc_request_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let grpc = "application/grpc".to_string();
    headers.insert("content-type".to_string(), grpc);
    headers.insert(":path".to_string(), "/t2.Svc/Run".to_string());
    headers
}

fn grpc_response_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let grpc = "application/grpc".to_string();
    headers.insert("content-type".to_string(), grpc);
    headers
}

fn grpc_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/t2.Svc/Run".to_string(),
    )
}

#[tokio::test]
async fn proto2_missing_top_level_required_field_is_rejected() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Command");

    // The advisory's exact reproduction: a correctly framed, zero-length
    // payload used to decode cleanly with no unknown fields.
    let frame = grpc_frame(&[]);
    assert_eq!(frame, vec![0, 0, 0, 0, 0]);
    let headers = grpc_request_headers();
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));

    // An initialized message still passes.
    let frame = grpc_frame(&pb_str_field(1, "go"));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);
}

#[tokio::test]
async fn proto2_required_field_at_its_default_value_is_present() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Defaulted");
    let headers = grpc_request_headers();

    let mut payload = pb_str_field(1, "");
    payload.extend(pb_varint_field(2, 0));
    let frame = grpc_frame(&payload);
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);

    // Dropping either presence marker makes the message uninitialized.
    let frame = grpc_frame(&pb_str_field(1, ""));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn proto2_missing_required_field_in_nested_message_is_rejected() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Wrapper");
    let headers = grpc_request_headers();

    // An absent optional message field is fine.
    let frame = grpc_frame(&[]);
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);

    // A present but uninitialized nested message is not.
    let frame = grpc_frame(&pb_len_field(1, &[]));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));

    // An initialized nested message passes.
    let inner = pb_str_field(1, "go");
    let frame = grpc_frame(&pb_len_field(1, &inner));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);
}

#[tokio::test]
async fn proto2_required_fields_in_repeated_values_are_checked() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Batch");
    let headers = grpc_request_headers();

    let ok = pb_str_field(1, "ok");
    let mut payload = pb_len_field(1, &ok);
    payload.extend(pb_len_field(1, &[]));
    let frame = grpc_frame(&payload);
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));

    let frame = grpc_frame(&pb_len_field(1, &ok));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);
}

#[tokio::test]
async fn proto2_required_fields_in_map_values_are_checked() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.MapHolder");
    let headers = grpc_request_headers();

    let mut entry = pb_str_field(1, "k");
    entry.extend(pb_len_field(2, &[]));
    let frame = grpc_frame(&pb_len_field(1, &entry));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));

    let mut entry = pb_str_field(1, "k");
    entry.extend(pb_len_field(2, &pb_str_field(1, "go")));
    let frame = grpc_frame(&pb_len_field(1, &entry));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);
}

#[tokio::test]
async fn proto2_required_fields_in_oneof_values_are_checked() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Choice");
    let headers = grpc_request_headers();

    let frame = grpc_frame(&pb_len_field(1, &[]));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));

    // The other oneof arm carries no required field and stays valid.
    let frame = grpc_frame(&pb_str_field(2, "text"));
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);
}

#[tokio::test]
async fn proto2_initialization_is_enforced_for_compressed_frames() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Command");

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&[]).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut frame = Vec::with_capacity(5 + compressed.len());
    frame.push(1);
    let length = compressed.len() as u32;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&compressed);

    let headers = grpc_request_headers();
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn proto2_initialization_applies_to_per_method_descriptors() {
    let dir = proto2_descriptor_dir();
    let config = json!({
        "protobuf_descriptor_path": proto2_path(&dir),
        "protobuf_method_messages": {
            "/t2.Svc/Run": {"request": "t2.Command", "response": "t2.Reply"}
        }
    });
    let plugin = BodyValidator::new(&config).expect("per-method config");

    let headers = grpc_request_headers();
    let frame = grpc_frame(&[]);
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_reject(result, Some(400));

    let headers = grpc_response_headers();
    let mut ctx = grpc_ctx();
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, &frame)
        .await;
    assert_reject(result, Some(502));

    let frame = grpc_frame(&pb_str_field(1, "OK"));
    let mut ctx = grpc_ctx();
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, &frame)
        .await;
    assert_continue(result);
}

#[tokio::test]
async fn proto2_initialization_failures_do_not_echo_payload_values() {
    let dir = proto2_descriptor_dir();
    let plugin = proto2_plugin(&dir, "t2.Batch");
    let headers = grpc_request_headers();

    let secret = pb_str_field(1, "topsecret");
    let mut payload = pb_len_field(1, &secret);
    payload.extend(pb_len_field(1, &[]));
    let frame = grpc_frame(&payload);
    let result = plugin.on_final_request_body(&headers, &frame).await;
    let body = reject_body(result);
    assert!(
        !body.contains("topsecret"),
        "protobuf rejection must not echo payload values: {body}"
    );
    assert!(
        body.contains("action"),
        "rejection should name the descriptor field path: {body}"
    );
}

#[tokio::test]
async fn proto3_descriptors_are_unaffected_by_initialization_checks() {
    // The proto3 fixture has no `required` cardinality, so an empty message
    // stays valid exactly as before.
    let plugin = protobuf_plugin();
    let mut headers = HashMap::new();
    let grpc = "application/grpc".to_string();
    headers.insert("content-type".to_string(), grpc);
    let path = "/test.Greeter/SayHello".to_string();
    headers.insert(":path".to_string(), path);
    let frame = grpc_frame(&[]);
    let result = plugin.on_final_request_body(&headers, &frame).await;
    assert_continue(result);
}

// ---------------------------------------------------------------------------
// GHSA-c78j-5w9p-cpq6 — duplicate JSON object member names
//
// `serde_json` collapses duplicate members to the LAST value while many other
// parsers keep the FIRST. `body_validator` evaluates the collapsed view but
// forwards the ORIGINAL bytes, so a schema-passing document could still deliver
// a schema-forbidden value to a first-key-wins backend. Ambiguity is therefore
// rejected outright on both directions.
// ---------------------------------------------------------------------------

/// A schema that only permits `role: "safe"`.
fn role_schema_plugin() -> BodyValidator {
    json_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": { "role": { "type": "string", "enum": ["safe"] } },
        "required": ["role"]
    }))
}

/// The exact advisory reproduction: an earlier forbidden `role` and a later
/// permitted one. `serde_json` validates the later value and would pass; the
/// duplicate screen must reject before that.
#[tokio::test]
async fn duplicate_member_first_key_wins_differential_is_rejected_on_request() {
    let body = r#"{"role":"admin","role":"safe"}"#;

    // The differential is real: serde only sees the safe value.
    let parsed: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
    assert_eq!(parsed["role"], "safe");
    assert_eq!(parsed.as_object().expect("object").len(), 1);

    let plugin = role_schema_plugin();
    let mut ctx = make_json_ctx(body);
    let mut headers = make_json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

/// The mirrored order is rejected too — nothing here depends on which spelling
/// the schema happens to allow.
#[tokio::test]
async fn duplicate_member_last_key_wins_differential_is_rejected_on_request() {
    let plugin = role_schema_plugin();
    let mut ctx = make_json_ctx(r#"{"role":"safe","role":"admin"}"#);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

/// The rejection detail is the fixed-cardinality scanner reason and never
/// echoes a member name or value from the body.
#[tokio::test]
async fn duplicate_member_rejection_detail_echoes_no_body_bytes() {
    let plugin = role_schema_plugin();
    let mut ctx = make_json_ctx(r#"{"role":"admin","role":"safe","SECRET":"VALUE"}"#);
    let mut headers = make_json_headers();
    let body = reject_body(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(
        body.contains("duplicate object member names"),
        "detail should name the duplicate-member cause: {body}"
    );
    assert!(
        !body.contains("SECRET"),
        "detail leaked a member name: {body}"
    );
    assert!(!body.contains("VALUE"), "detail leaked a value: {body}");
    assert!(!body.contains("admin"), "detail leaked a value: {body}");
}

/// A member spelled with a `u`-escape for the same code point is the SAME
/// member. Comparing raw key bytes would miss this.
#[tokio::test]
async fn escaped_member_name_equal_to_a_literal_one_is_rejected() {
    let escaped_r = format!("{}u0072", '\\');
    let body = format!(r#"{{"role":"admin","{escaped_r}ole":"safe"}}"#);

    // serde_json treats these as one member, so the bytes really are ambiguous.
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(parsed.as_object().expect("object").len(), 1);

    let plugin = role_schema_plugin();
    let mut ctx = make_json_ctx(&body);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

/// Nesting and arrays are covered: the screen walks the whole document, not
/// just the top-level object.
#[tokio::test]
async fn duplicate_member_nested_inside_arrays_and_objects_is_rejected() {
    let plugin = json_schema_plugin(serde_json::json!({ "type": "object" }));
    for body in [
        r#"{"role":"safe","nested":{"role":"admin","role":"safe"}}"#,
        r#"{"role":"safe","items":[{"ok":1},{"role":"admin","role":"safe"}]}"#,
        r#"{"role":"safe","a":{"b":{"c":[[{"x":1,"x":2}]]}}}"#,
    ] {
        let mut ctx = make_json_ctx(body);
        let mut headers = make_json_headers();
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    }
}

/// Clean documents — including ones that reuse a name in SIBLING objects or at
/// different nesting levels — must still pass. The screen must not over-reject.
#[tokio::test]
async fn unambiguous_documents_still_pass_request_validation() {
    let plugin = json_schema_plugin(serde_json::json!({ "type": "object" }));
    for body in [
        r#"{"role":"safe"}"#,
        r#"{"a":{"a":{"a":1}}}"#,
        r#"{"items":[{"role":"safe"},{"role":"safe"},{"role":"safe"}]}"#,
        r#"{"a":1,"b":[1,2,3],"c":null,"d":true,"e":-1.5e3,"f":""}"#,
    ] {
        let mut ctx = make_json_ctx(body);
        let mut headers = make_json_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    }
}

/// The final backend-visible body (post request transforms) is screened too, so
/// a transform cannot re-introduce ambiguity after `before_proxy` passed.
#[tokio::test]
async fn duplicate_member_in_final_request_body_is_rejected() {
    let plugin = role_schema_plugin();
    let headers = make_json_headers();
    let result = plugin
        .on_final_request_body(&headers, br#"{"role":"admin","role":"safe"}"#)
        .await;
    assert_reject(result, Some(400));

    let clean = plugin
        .on_final_request_body(&headers, br#"{"role":"safe"}"#)
        .await;
    assert_continue(clean);
}

/// A backend response with duplicate members is a differential in the other
/// direction (the CLIENT is the first-key-wins parser), and fails closed with
/// the response status.
#[tokio::test]
async fn duplicate_member_in_response_body_is_rejected() {
    let plugin = response_schema_plugin(serde_json::json!({
        "type": "object",
        "properties": { "role": { "type": "string", "enum": ["safe"] } }
    }));
    let headers = response_json_headers();

    let mut ctx = make_response_ctx();
    let result = plugin
        .on_final_response_body(
            &mut ctx,
            200,
            &headers,
            br#"{"role":"admin","role":"safe"}"#,
        )
        .await;
    assert_reject(result, Some(502));

    let mut clean_ctx = make_response_ctx();
    assert_continue(
        plugin
            .on_final_response_body(&mut clean_ctx, 200, &headers, br#"{"role":"safe"}"#)
            .await,
    );
}

/// Malformed input keeps its existing "invalid JSON" handling: the duplicate
/// screen must not reclassify every parse error, and must never panic.
#[tokio::test]
async fn malformed_bodies_keep_invalid_json_handling() {
    let plugin = json_schema_plugin(serde_json::json!({ "type": "object" }));
    for body in ["{", "{\"a\":}", "not json at all", "{\"a\":1} trailing"] {
        let mut ctx = make_json_ctx(body);
        let mut headers = make_json_headers();
        let rejection = reject_body(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert!(
            rejection.contains("Invalid JSON"),
            "malformed body {body:?} should stay an invalid-JSON rejection: {rejection}"
        );
    }
}

/// The screen is non-recursive: a pathologically deep document is refused on a
/// budget rather than overflowing the stack.
#[tokio::test]
async fn pathologically_deep_body_is_refused_without_stack_overflow() {
    let plugin = json_schema_plugin(serde_json::json!({ "type": "object" }));
    let depth = 50_000usize;
    let mut body = String::with_capacity(depth * 2 + 16);
    body.push_str("{\"a\":");
    for _ in 0..depth {
        body.push('[');
    }
    for _ in 0..depth {
        body.push(']');
    }
    body.push('}');
    let mut ctx = make_json_ctx(&body);
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
}

/// Narrow XML-activated config with `content_types: ["application/json"]` and
/// no JSON schema/required fields: `before_proxy` still screens matching JSON,
/// so the final backend-visible hook must too — a transform must not be able to
/// reintroduce duplicate members after the first screen.
#[tokio::test]
async fn xml_activated_json_content_type_final_rejects_reintroduced_duplicates() {
    let plugin = BodyValidator::new(&json!({
        "validate_xml": true,
        "content_types": ["application/json"]
    }))
    .unwrap();

    let clean = r#"{"role":"safe"}"#;
    let mut ctx = make_json_ctx(clean);
    let mut headers = make_json_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Transform reintroduces ambiguity on the backend-visible bytes.
    let ambiguous = br#"{"role":"admin","role":"safe"}"#;
    assert_reject(
        plugin.on_final_request_body(&headers, ambiguous).await,
        Some(400),
    );

    // Unambiguous final body still passes (parity with before_proxy).
    assert_continue(
        plugin
            .on_final_request_body(&headers, clean.as_bytes())
            .await,
    );

    // XML gating preserved: XML content type is outside this content_types list.
    let xml_headers = make_xml_headers();
    assert_continue(plugin.on_final_request_body(&xml_headers, b"<root/>").await);
}

/// Protobuf-only configs must not treat arbitrary non-gRPC payloads as JSON on
/// the final request-body hook (early Continue before the JSON branch).
#[tokio::test]
async fn protobuf_only_final_request_does_not_json_screen_non_grpc() {
    let plugin = protobuf_plugin();
    let headers = make_json_headers();
    // Duplicate members would fail a JSON screen; protobuf-only must Continue.
    assert_continue(
        plugin
            .on_final_request_body(&headers, br#"{"role":"admin","role":"safe"}"#)
            .await,
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  GHSA-2vmr-ww8r-mww3 — body-policy representation must never fail open
// ═══════════════════════════════════════════════════════════════════════

/// Non-UTF-8 JSON fails closed from the raw-byte fallback when no UTF-8
/// metadata view exists. A body that is not valid UTF-8 has no shared string
/// copy (the proxy removes it), and used to make the whole policy `Continue`.
#[tokio::test]
async fn advisory_2vmr_non_utf8_json_request_fails_closed_without_echoing_bytes() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // Valid JSON framing, invalid UTF-8 inside the string value.
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(b"{\"name\":\"\xFF\xFE\"}"));
    let mut headers = ctx.headers.clone();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("not valid UTF-8"), "{body}");
            assert!(!body.contains('\u{FFFD}'), "{body}");
        }
        other => panic!("expected reject, got {other:?}"),
    }

    // The final backend-visible hook enforces the same rule over raw bytes.
    assert_reject(
        plugin
            .on_final_request_body(&make_json_headers(), b"{\"name\":\"\xFF\xFE\"}")
            .await,
        Some(400),
    );
}

/// Non-UTF-8 XML is rejected identically.
#[tokio::test]
async fn advisory_2vmr_non_utf8_xml_request_fails_closed() {
    let plugin = xml_plugin();
    let mut ctx = make_xml_ctx("");
    ctx.metadata.remove("request_body");
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(b"<root>\xFF\xFE</root>"));
    let mut headers = make_xml_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    assert_reject(
        plugin
            .on_final_request_body(&make_xml_headers(), b"<root>\xFF\xFE</root>")
            .await,
        Some(400),
    );
}

/// An empty JSON request body is not a JSON document.
#[tokio::test]
async fn advisory_2vmr_empty_json_request_fails_closed() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = make_json_ctx("");
    let mut headers = make_json_headers();
    assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

    assert_reject(
        plugin
            .on_final_request_body(&make_json_headers(), b"")
            .await,
        Some(400),
    );
}

/// Early `before_proxy` validation prefers a downstream-rewritten metadata text
/// view (as `ai_prompt_shield` redact writes) over the original raw bytes, so
/// the shielded/redacted representation is what the early hook decides over.
/// The final request-body hook still validates the exact backend-visible bytes.
#[tokio::test]
async fn advisory_2vmr_before_proxy_prefers_transformed_metadata_over_raw_bytes() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    // Original client bytes lack the required field and would reject.
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(br#"{"ssn":"123-45-6789"}"#));
    // Earlier shield/redact rewrite publishes the admission view in metadata.
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"ssn":"[REDACTED:ssn]","name":"ok"}"#.to_string(),
    );
    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    // Final hook still decides over the backend-visible bytes independently.
    assert_reject(
        plugin
            .on_final_request_body(&make_json_headers(), br#"{"ssn":"123-45-6789"}"#)
            .await,
        Some(400),
    );
    assert_continue(
        plugin
            .on_final_request_body(
                &make_json_headers(),
                br#"{"ssn":"[REDACTED:ssn]","name":"ok"}"#,
            )
            .await,
    );
}

/// A body-bearing DELETE / PUT reaches the validator and is rejected on the
/// same terms as a POST.
#[tokio::test]
async fn advisory_2vmr_body_bearing_delete_and_put_are_validated() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    for method in ["DELETE", "PUT"] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), "application/json".to_string());
        ctx.request_body_bytes = Some(bytes::Bytes::from_static(br#"{"other":true}"#));
        assert!(plugin.should_buffer_request_body(&ctx));
        let mut headers = ctx.headers.clone();
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));

        // A valid body on the same unusual method still passes.
        let mut ok_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api".to_string(),
        );
        ok_ctx
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
        ok_ctx.request_body_bytes = Some(bytes::Bytes::from_static(br#"{"name":"ok"}"#));
        let mut ok_headers = ok_ctx.headers.clone();
        assert_continue(plugin.before_proxy(&mut ok_ctx, &mut ok_headers).await);
    }
}

/// A governed representation with no buffered body and no transport proof of
/// emptiness is a gateway inconsistency, and fails closed rather than skipping
/// the policy. The diagnostic is fixed and value-free.
#[tokio::test]
async fn advisory_2vmr_missing_request_representation_fails_closed() {
    let plugin = BodyValidator::new(&json!({"required_fields": ["name"]})).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    let mut headers = ctx.headers.clone();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(body.contains("representation was unavailable"), "{body}");
        }
        other => panic!("expected reject, got {other:?}"),
    }
}

/// Media types outside the configured allowlist, and allowlisted types no
/// configured rule can inspect, still `Continue` — including when empty or
/// binary. The advisory closes fail-open holes; it does not widen applicability.
#[tokio::test]
async fn advisory_2vmr_ungoverned_representations_still_continue() {
    let plugin = BodyValidator::new(&json!({
        "required_fields": ["name"],
        "content_types": ["application/json", "text/plain"]
    }))
    .unwrap();

    for (content_type, body) in [
        ("text/plain", &b""[..]),
        ("text/plain", &b"\xFF\xFE"[..]),
        ("application/octet-stream", &b"\xFF\xFE"[..]),
        ("", &b""[..]),
    ] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), content_type.to_string());
        ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(body));
        let mut headers = ctx.headers.clone();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

        let mut hook_headers = HashMap::new();
        hook_headers.insert("content-type".to_string(), content_type.to_string());
        assert_continue(plugin.on_final_request_body(&hook_headers, body).await);
    }
}

/// An empty protobuf message inside a well-formed five-byte frame is
/// structurally valid for proto3 and must be validated, not skipped.
#[tokio::test]
async fn advisory_2vmr_empty_protobuf_message_is_validated_not_skipped() {
    let plugin = protobuf_plugin();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(":path".to_string(), "/test.Greeter/SayHello".to_string());
    assert_continue(
        plugin
            .on_final_request_body(&headers, &grpc_frame(&[]))
            .await,
    );
}

/// Two configured instances stay isolated and deterministic: each decides only
/// its own configured representation over the same request.
#[tokio::test]
async fn advisory_2vmr_multiple_instances_remain_isolated() {
    let json_instance = BodyValidator::new(&json!({
        "required_fields": ["name"],
        "content_types": ["application/json"]
    }))
    .unwrap();
    let xml_instance = BodyValidator::new(&json!({
        "validate_xml": true,
        "content_types": ["application/xml"]
    }))
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(br#"{"other":true}"#));

    assert!(json_instance.should_buffer_request_body(&ctx));
    assert!(!xml_instance.should_buffer_request_body(&ctx));

    let mut headers = ctx.headers.clone();
    assert_continue(xml_instance.before_proxy(&mut ctx, &mut headers).await);
    let mut headers = ctx.headers.clone();
    assert_reject(
        json_instance.before_proxy(&mut ctx, &mut headers).await,
        Some(400),
    );
}
