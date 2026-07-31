//! Diagnostic-confidentiality coverage for `body_validator` and
//! `openapi_validator` (advisory `GHSA-5p2h-fq6q-gwh9`).
//!
//! Both validators write a violation detail into two places with different
//! audiences: the client-visible reject/problem body, and transaction metadata
//! that every configured logging plugin exports. Neither may reproduce the
//! rejected instance value, an expected secret constant, a payload-chosen JSON
//! / XML / form / multipart member name, or a raw parser rendering.
//!
//! Every test plants a canary and asserts it is absent from all of those
//! surfaces at once, then separately asserts that the safe signal (category,
//! schema keyword, declared field path) survives and that the rejection still
//! happens with the documented status. The canaries are placed so that a "fix"
//! which only truncated after the offending token, or which regex-redacted a
//! known key name, would still fail:
//!
//! * `CANARY` contains no substring a key-name redactor would match;
//! * canaries are planted at the *front* of an oversized offending value, so
//!   truncation cannot remove them;
//! * hostile member names, not just hostile values, are asserted absent.

use ferrum_edge::plugins::body_validator::BodyValidator;
use ferrum_edge::plugins::openapi_validator::OpenapiValidator;
use ferrum_edge::plugins::utils::validation_diagnostics::{
    MAX_DIAGNOSTIC_CHARS, MAX_RAW_SEGMENT_CHARS, MAX_SEGMENT_CHARS, NUMERIC_SEGMENT,
    REDACTED_SEGMENT, ROOT_LOCATION, SafeFieldNames, TRUNCATED_LOCATION_MARKER, UNKNOWN_KEYWORD,
    bound_detail, safe_keyword, safe_location, xml_error_category,
};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Planted secret. Chosen so no key-name-based redactor would ever match it.
const CANARY: &str = "qzvx-canary-9f3a1c7e";

/// A payload-chosen member name that must never be echoed.
const HOSTILE_MEMBER: &str = "qzvxMemberCanary9f3a";

const JSON: &str = "application/json";
const XML: &str = "application/xml";
const FORM: &str = "application/x-www-form-urlencoded";

fn headers_with(content_type: &str) -> HashMap<String, String> {
    HashMap::from([("content-type".into(), content_type.to_string())])
}

fn post_ctx(path: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), path.into());
    ctx.headers = headers_with(JSON);
    ctx
}

/// Status plus reject body, or a panic naming what came back instead.
fn reject_parts(result: &PluginResult) -> (u16, String) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => (*status_code, body.clone()),
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// Every metadata entry a logging plugin would export, flattened.
fn metadata_surfaces(ctx: &RequestContext) -> String {
    let mut out = String::new();
    for (key, value) in &ctx.metadata {
        // The buffered body itself is plugin input, not a diagnostic.
        if key == "request_body" {
            continue;
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// Assert a canary is absent from the reject body and from every metadata
/// value at once.
fn assert_no_disclosure(reject_body: &str, metadata: &str, canary: &str) {
    assert!(
        !reject_body.contains(canary),
        "client body disclosed {canary:?}: {reject_body}"
    );
    assert!(
        !metadata.contains(canary),
        "transaction metadata disclosed {canary:?}: {metadata}"
    );
}

// ───────────────────────── body_validator helpers ───────────────────────────

fn body_validator_with(config: Value) -> BodyValidator {
    BodyValidator::new(&config).expect("valid body_validator config")
}

/// Run the final request-body hook and return `(status, body)`.
async fn bv_request_reject(
    plugin: &BodyValidator,
    content_type: &str,
    body: &[u8],
) -> (u16, String) {
    let headers = headers_with(content_type);
    let result = plugin.on_final_request_body(&headers, body).await;
    reject_parts(&result)
}

/// Run the final response-body hook and return `(status, body, metadata)`.
async fn bv_response_reject(
    plugin: &BodyValidator,
    content_type: &str,
    body: &[u8],
) -> (u16, String, String) {
    let headers = headers_with(content_type);
    let mut ctx = post_ctx("/api/items");
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    let (status, reject_body) = reject_parts(&result);
    (status, reject_body, metadata_surfaces(&ctx))
}

// ───────────────────────── body_validator: request ──────────────────────────

#[tokio::test]
async fn body_validator_request_pattern_failure_hides_value() {
    let plugin = body_validator_with(json!({
        "json_schema": {
            "type": "object",
            "required": ["token"],
            "properties": {"token": {"type": "string", "pattern": "^redacted$"}}
        }
    }));
    let body = format!(r#"{{"token":"{CANARY}-live-credential"}}"#);
    let (status, detail) = bv_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400, "request policy must still fail closed");
    assert_no_disclosure(&detail, "", CANARY);
    assert!(detail.contains("pattern"), "keyword must survive: {detail}");
    assert!(
        detail.contains("/token"),
        "a schema-declared field path is safe and must survive: {detail}"
    );
}

#[tokio::test]
async fn body_validator_request_enum_failure_hides_expected_constants() {
    // `enum` members are *expected* constants. An operator can legitimately
    // place a shared secret there, so they are never enumerated back.
    let plugin = body_validator_with(json!({
        "json_schema": {
            "type": "object",
            "properties": {"mode": {"enum": [CANARY, "other"]}}
        }
    }));
    let (status, detail) = bv_request_reject(&plugin, JSON, br#"{"mode":"x"}"#).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, "", CANARY);
    assert!(detail.contains("enum"), "{detail}");
}

#[tokio::test]
async fn body_validator_request_hostile_member_name_is_replaced() {
    // An undeclared member name lands in the instance path. It is payload
    // data, so it collapses to the placeholder instead of being echoed.
    let plugin = body_validator_with(json!({
        "json_schema": {
            "type": "object",
            "additionalProperties": {"type": "integer"},
            "properties": {"kind": {"type": "string"}}
        }
    }));
    let body = format!(r#"{{"{HOSTILE_MEMBER}":"not-an-integer"}}"#);
    let (status, detail) = bv_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, "", HOSTILE_MEMBER);
    assert!(
        detail.contains(REDACTED_SEGMENT),
        "an undeclared member name must collapse: {detail}"
    );
}

#[tokio::test]
async fn body_validator_request_deep_hostile_document_stays_bounded() {
    let plugin = body_validator_with(json!({
        "json_schema": {
            "type": "object",
            "properties": {"a": {"type": "string"}}
        }
    }));
    // 40 nested levels of hostile member names, each carrying the canary plus
    // a control character and non-ASCII text, hung under the failing property.
    let mut instance = json!(1);
    for depth in 0..40 {
        let key = format!("{CANARY}\u{1}\u{e9}\u{4e2d}{depth}");
        let mut level = serde_json::Map::new();
        level.insert(key, instance);
        instance = Value::Object(level);
    }
    let body = serde_json::to_string(&json!({"a": instance})).unwrap();
    let (status, detail) = bv_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400, "the type violation is still rejected");
    assert_no_disclosure(&detail, "", CANARY);
    assert!(detail.len() < 1024, "diagnostic inflated: {detail}");
    assert!(detail.contains("/a"), "declared property lost: {detail}");
}

#[tokio::test]
async fn body_validator_request_large_value_never_reaches_the_diagnostic() {
    let plugin = body_validator_with(json!({
        "json_schema": {
            "type": "object",
            "properties": {"blob": {"type": "integer"}}
        }
    }));
    // Canary first, then 200 KiB of filler: truncating after the offending
    // token would still disclose it.
    let value = format!("{CANARY}{}", "A".repeat(200 * 1024));
    let body = serde_json::to_string(&json!({"blob": value})).unwrap();
    let (status, detail) = bv_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, "", CANARY);
    assert!(detail.len() < 1024, "{}", detail.len());
}

// ───────────────────────── body_validator: response ─────────────────────────

#[tokio::test]
async fn body_validator_response_failure_hides_value_and_shape() {
    let plugin = body_validator_with(json!({
        "response_json_schema": {
            "type": "object",
            "required": ["ok"],
            "properties": {
                "ok": {"type": "boolean"},
                "sessionToken": {"type": "string", "pattern": "^redacted$"}
            }
        }
    }));
    let body = format!(r#"{{"ok":true,"sessionToken":"{CANARY}"}}"#);
    let (status, detail, metadata) = bv_response_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 502, "an invalid upstream body is still a 502");
    assert_no_disclosure(&detail, &metadata, CANARY);
    // Coarser than the request side on purpose: an instance location would
    // describe the upstream body's shape back to the client.
    assert!(
        !detail.contains("sessionToken"),
        "response diagnostics must not describe upstream structure: {detail}"
    );
    assert!(
        detail.contains("Response body does not satisfy the configured JSON Schema"),
        "{detail}"
    );
}

#[tokio::test]
async fn body_validator_response_xml_error_is_a_category_not_a_token() {
    let plugin = body_validator_with(json!({
        "response_required_xml_elements": ["report"],
        "response_content_types": ["application/xml"]
    }));
    let body = format!("<report><entry>&{CANARY};</entry></report>");
    let (status, detail, metadata) = bv_response_reject(&plugin, XML, body.as_bytes()).await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        detail.contains("entity reference is undeclared or malformed"),
        "the well-formedness category must survive: {detail}"
    );
}

// ───────────────────────── openapi_validator helpers ────────────────────────

fn openapi_request_plugin(schema: Value, content_type: &str) -> OpenapiValidator {
    OpenapiValidator::new(&json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "request_body": {"content": {content_type: schema}}
        }]
    }))
    .expect("valid openapi_validator config")
}

fn openapi_response_plugin(schema: Value, content_type: &str) -> OpenapiValidator {
    OpenapiValidator::new(&json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "responses": {"200": {content_type: schema}}
        }]
    }))
    .expect("valid openapi_validator config")
}

async fn oa_request_reject(
    plugin: &OpenapiValidator,
    content_type: &str,
    body: &[u8],
) -> (u16, String, String) {
    let headers = headers_with(content_type);
    let mut ctx = post_ctx("/items");
    ctx.headers = headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body)
        .await;
    let (status, reject_body) = reject_parts(&result);
    (status, reject_body, metadata_surfaces(&ctx))
}

async fn oa_response_reject(
    plugin: &OpenapiValidator,
    content_type: &str,
    body: &[u8],
) -> (u16, String, String) {
    let headers = headers_with(content_type);
    let mut ctx = post_ctx("/items");
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    let (status, reject_body) = reject_parts(&result);
    (status, reject_body, metadata_surfaces(&ctx))
}

// ───────────────────────── openapi_validator: request ───────────────────────

#[tokio::test]
async fn openapi_request_schema_failure_keeps_declared_path_only() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "object",
            "required": ["token"],
            "properties": {"token": {"type": "string", "pattern": "^redacted$"}}
        }),
        JSON,
    );
    let body = format!(r#"{{"token":"{CANARY}"}}"#);
    let (status, detail, metadata) = oa_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        metadata.contains("request body does not satisfy the request schema"),
        "{metadata}"
    );
    assert!(
        metadata.contains("/token"),
        "a schema-declared field path is safe and must survive: {metadata}"
    );
    assert!(
        metadata.contains("pattern"),
        "allowlisted keyword must survive: {metadata}"
    );
}

#[tokio::test]
async fn openapi_request_nested_array_failure_uses_numeric_marker() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "object",
            "properties": {
                "rows": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"count": {"type": "integer"}}
                    }
                }
            }
        }),
        JSON,
    );
    let body = format!(r#"{{"rows":[{{"count":1}},{{"count":"{CANARY}"}}]}}"#);
    let (status, detail, metadata) = oa_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        metadata.contains(&format!("/rows/{NUMERIC_SEGMENT}/count")),
        "numeric pointer segments must render as the fixed marker: {metadata}"
    );
    assert!(
        !metadata.contains("/rows/1/"),
        "raw digits must never appear in the location: {metadata}"
    );
}

#[tokio::test]
async fn openapi_request_hostile_member_name_is_not_echoed() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "object",
            "additionalProperties": {"type": "integer"},
            "properties": {"kind": {"type": "string"}}
        }),
        JSON,
    );
    let body = format!(r#"{{"{HOSTILE_MEMBER}":"x"}}"#);
    let (status, detail, metadata) = oa_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, HOSTILE_MEMBER);
    assert!(metadata.contains(REDACTED_SEGMENT), "{metadata}");
}

#[tokio::test]
async fn openapi_request_scalar_conversion_hides_the_form_value() {
    let schema = json!({
        "type": "object",
        "properties": {"count": {"type": "integer"}}
    });
    let plugin = openapi_request_plugin(schema, FORM);
    let body = format!("count={CANARY}");
    let (status, detail, metadata) = oa_request_reject(&plugin, FORM, body.as_bytes()).await;

    assert_eq!(status, 400, "conversion failures still fail closed");
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(metadata.contains("Invalid integer value"), "{metadata}");
}

#[tokio::test]
async fn openapi_request_multipart_hides_part_name_and_value() {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"file": {"type": "string"}}
    });
    let plugin = openapi_request_plugin(schema, "multipart/form-data");
    let body = format!(
        "--abc\r\nContent-Disposition: form-data; \
         name=\"{HOSTILE_MEMBER}\"\r\n\r\n{CANARY}\r\n--abc--\r\n"
    );
    let ct = "multipart/form-data; boundary=abc";
    let (status, detail, metadata) = oa_request_reject(&plugin, ct, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, HOSTILE_MEMBER);
}

#[tokio::test]
async fn openapi_request_xml_root_mismatch_hides_document_and_configured_names() {
    let schema = json!({
        "type": "object",
        "xml": {"name": "order", "namespace": "urn:qzvx-ns-canary"},
        "properties": {"id": {"type": "integer"}}
    });
    let plugin = openapi_request_plugin(schema, XML);
    let body = format!("<{HOSTILE_MEMBER}><id>{CANARY}</id></{HOSTILE_MEMBER}>");
    let (status, detail, metadata) = oa_request_reject(&plugin, XML, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, HOSTILE_MEMBER);
    assert_no_disclosure(&detail, &metadata, "order");
    assert_no_disclosure(&detail, &metadata, "urn:qzvx-ns-canary");
    assert!(
        metadata.contains("XML root element does not match the configured schema"),
        "fixed category must survive: {metadata}"
    );
}

#[tokio::test]
async fn openapi_request_malformed_xml_reports_a_category() {
    let schema = json!({
        "type": "object",
        "properties": {"id": {"type": "integer"}}
    });
    let plugin = openapi_request_plugin(schema, XML);
    let body = format!("<root>&{CANARY};</root>");
    let (status, detail, metadata) = oa_request_reject(&plugin, XML, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        metadata.contains("entity reference is undeclared or malformed"),
        "{metadata}"
    );
}

#[tokio::test]
async fn openapi_unmatched_operation_does_not_echo_the_target() {
    let schema = json!({"type": "object"});
    let plugin = openapi_request_plugin(schema, JSON);
    let mut ctx = post_ctx(&format!("/missing/{CANARY}"));
    let mut headers = headers_with(JSON);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status, detail) = reject_parts(&result);
    let metadata = metadata_surfaces(&ctx);

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
}

// ───────────────────────── openapi_validator: response ──────────────────────

#[tokio::test]
async fn openapi_response_schema_failure_hides_value_and_shape() {
    let schema = json!({
        "type": "object",
        "properties": {"sessionToken": {"type": "integer"}}
    });
    let plugin = openapi_response_plugin(schema, JSON);
    let body = format!(r#"{{"sessionToken":"{CANARY}"}}"#);
    let (status, detail, metadata) = oa_response_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        metadata.contains("response body does not satisfy the response schema"),
        "{metadata}"
    );
    assert!(
        !metadata.contains("sessionToken"),
        "response diagnostics must not describe upstream structure: {metadata}"
    );
}

#[tokio::test]
async fn openapi_response_conversion_failure_hides_upstream_bytes() {
    let schema = json!({
        "type": "object",
        "properties": {"count": {"type": "integer"}}
    });
    let plugin = openapi_response_plugin(schema, FORM);
    let body = format!("count={CANARY}");
    let (status, detail, metadata) = oa_response_reject(&plugin, FORM, body.as_bytes()).await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
}

#[tokio::test]
async fn openapi_response_xml_conversion_failure_hides_upstream_and_configured_names() {
    let schema = json!({
        "type": "object",
        "xml": {"name": "order", "namespace": "urn:qzvx-ns-canary"},
        "properties": {"id": {"type": "integer"}}
    });
    let plugin = openapi_response_plugin(schema, XML);
    let body = format!("<{HOSTILE_MEMBER}><id>{CANARY}</id></{HOSTILE_MEMBER}>");
    let (status, detail, metadata) = oa_response_reject(&plugin, XML, body.as_bytes()).await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, HOSTILE_MEMBER);
    assert_no_disclosure(&detail, &metadata, "order");
    assert_no_disclosure(&detail, &metadata, "urn:qzvx-ns-canary");
}

#[tokio::test]
async fn openapi_response_diagnostic_is_bounded_whatever_the_config_says() {
    // `error_truncate_chars` is a size bound, not the confidentiality
    // mechanism, and it can no longer be raised into a disclosure.
    let plugin = OpenapiValidator::new(&json!({
        "error_truncate_chars": 1_000_000,
        "operations": [{
            "method": "POST",
            "path_template": "/items",
            "path_regex": "^/items$",
            "responses": {
                "200": {
                    "application/json": {
                        "type": "object",
                        "properties": {"blob": {"type": "integer"}}
                    }
                }
            }
        }]
    }))
    .expect("valid openapi_validator config");
    let value = format!("{CANARY}{}", "B".repeat(300 * 1024));
    let body = serde_json::to_string(&json!({"blob": value})).unwrap();
    let (status, detail, metadata) = oa_response_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
    let recorded = metadata
        .lines()
        .find(|line| line.starts_with("openapi_validator.response_error="))
        .expect("response error metadata must be recorded");
    assert!(
        recorded.chars().count() <= MAX_DIAGNOSTIC_CHARS + 64,
        "diagnostic exceeded the compiled-in ceiling: {recorded}"
    );
}

// ───────────────────────── diagnostic primitives ────────────────────────────

#[test]
fn safe_location_keeps_declared_names_and_numeric_markers_only() {
    let names = SafeFieldNames::from_schema(&json!({
        "type": "object",
        "properties": {
            "rows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"count": {"type": "integer"}}
                }
            },
            "123456789012": {"type": "string"}
        }
    }));
    let redacted = format!("/{REDACTED_SEGMENT}");

    assert_eq!(safe_location("", &names), ROOT_LOCATION);
    assert_eq!(
        safe_location("/rows/2/count", &names),
        format!("/rows/{NUMERIC_SEGMENT}/count")
    );
    let hostile = safe_location(&format!("/{HOSTILE_MEMBER}"), &names);
    assert_eq!(hostile, redacted);
    // Pointer escapes are decoded before classification, so `~1` cannot
    // smuggle a separator into the rendered location.
    assert_eq!(safe_location("/a~1b", &names), redacted);
    // A numeric object-member spelling is indistinguishable from an array
    // index under JSON Pointer alone, so digits never survive.
    assert_eq!(
        safe_location(&format!("/{HOSTILE_MEMBER}/9"), &names),
        format!("/{REDACTED_SEGMENT}/{NUMERIC_SEGMENT}")
    );
    assert!(
        !safe_location("/rows/2/count", &names).contains('2'),
        "raw digits must never be emitted"
    );
    assert_eq!(
        safe_location("/123456789012", &names),
        format!("/{NUMERIC_SEGMENT}"),
        "even a declared numeric-looking member must not emit raw digits"
    );
}

#[test]
fn safe_location_bounds_depth_and_total_length() {
    let names = SafeFieldNames::default();
    let deep: String = (0..64).map(|i| format!("/seg{i}")).collect();
    let rendered = safe_location(&deep, &names);
    assert!(rendered.ends_with("/..."), "{rendered}");
    assert!(rendered.len() <= 100, "{}", rendered.len());

    let wide = format!("/{}", "z".repeat(4096));
    assert_eq!(safe_location(&wide, &names), format!("/{REDACTED_SEGMENT}"));
}

#[test]
fn safe_location_redacts_oversized_raw_segment_before_unescape() {
    let names = SafeFieldNames::default();
    // Larger than MAX_RAW_SEGMENT_CHARS so unescape never runs.
    let huge = format!("/{}", "z".repeat(MAX_RAW_SEGMENT_CHARS + 8));
    let rendered = safe_location(&huge, &names);
    assert_eq!(rendered, format!("/{REDACTED_SEGMENT}"));
    assert!(
        rendered.len() < 16,
        "oversized segment must stay bounded: {rendered}"
    );
    // Escaped spelling that would expand past the unescaped budget after a
    // would-be unescape is also rejected on the raw ceiling first.
    let escaped = format!("/{}", "~0".repeat(MAX_SEGMENT_CHARS + 1));
    assert!(escaped.len() > MAX_RAW_SEGMENT_CHARS);
    assert_eq!(
        safe_location(&escaped, &names),
        format!("/{REDACTED_SEGMENT}")
    );
}

#[test]
fn safe_keyword_accepts_only_allowlisted_vocabulary_tokens() {
    assert_eq!(safe_keyword("/properties/token/pattern"), "pattern");
    assert_eq!(
        safe_keyword("/additionalProperties"),
        "additionalProperties"
    );
    assert_eq!(safe_keyword(""), UNKNOWN_KEYWORD);
    // A fragment carrying payload-shaped text is not a keyword.
    assert_eq!(safe_keyword(&format!("/x/{CANARY} leak")), UNKNOWN_KEYWORD);
    // Short all-alphanumeric custom / canary tokens must not pass the
    // allowlist just because they look like vocabulary.
    assert_eq!(safe_keyword("/qzvxcanary9f3a"), UNKNOWN_KEYWORD);
    assert_eq!(safe_keyword(&format!("/{CANARY}")), UNKNOWN_KEYWORD);
    // `$defs` map keys are schema identifiers, not diagnostic keywords.
    assert_eq!(safe_keyword(&format!("/$defs/{CANARY}/type")), "type");
}

#[test]
fn safe_field_names_never_collect_instance_values_or_xml_names() {
    let names = SafeFieldNames::from_schema(&json!({
        "type": "object",
        "xml": {"name": CANARY},
        "properties": {
            "mode": {"enum": [CANARY], "const": CANARY, "xml": {"name": "wireModeCanary"}}
        },
        "required": ["mode"],
        "$defs": {CANARY: {"type": "string"}}
    }));
    assert!(names.allows("mode"));
    assert!(
        !names.allows(CANARY),
        "enum/const members and $defs keys are never declared JSON member names"
    );
    assert!(
        !names.allows("wireModeCanary"),
        "xml.name must not be inserted into SafeFieldNames"
    );
}

#[test]
fn bound_detail_caps_on_char_boundaries() {
    let long = "\u{4e2d}".repeat(MAX_DIAGNOSTIC_CHARS * 2);
    let bounded = bound_detail(&long);
    assert_eq!(bounded.chars().count(), MAX_DIAGNOSTIC_CHARS);
    assert_eq!(bound_detail("short"), "short");
}

// ───────────────────────── root-review canary coverage ──────────────────────

#[tokio::test]
async fn body_validator_missing_required_xml_hides_configured_name_on_request() {
    let plugin = body_validator_with(json!({
        "required_xml_elements": [CANARY],
        "content_types": ["application/xml"]
    }));
    let (status, detail) = bv_request_reject(&plugin, XML, b"<other/>").await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, "", CANARY);
    assert!(
        detail.contains("Missing required XML element"),
        "fixed category must survive: {detail}"
    );
}

#[tokio::test]
async fn body_validator_missing_required_xml_hides_configured_name_on_response() {
    let plugin = body_validator_with(json!({
        "response_required_xml_elements": [CANARY],
        "response_content_types": ["application/xml"]
    }));
    let (status, detail, metadata) = bv_response_reject(&plugin, XML, b"<other/>").await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        detail.contains("Missing required XML element"),
        "fixed category must survive: {detail}"
    );
}

#[tokio::test]
async fn openapi_request_content_encoding_hides_coding_token() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "object",
            "properties": {"ok": {"type": "boolean"}}
        }),
        JSON,
    );
    let coding = format!("qzvx{CANARY}");
    let mut headers = headers_with(JSON);
    headers.insert("content-encoding".into(), coding.clone());
    let mut ctx = post_ctx("/items");
    ctx.headers = headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, br#"{"ok":true}"#)
        .await;
    let (status, detail) = reject_parts(&result);
    let metadata = metadata_surfaces(&ctx);

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, &coding);
    assert!(
        detail.contains("Content-Encoding could not be decoded")
            || metadata.contains("Content-Encoding could not be decoded"),
        "fixed decode category must survive: detail={detail} metadata={metadata}"
    );
}

#[tokio::test]
async fn openapi_request_schema_path_defs_canary_is_not_disclosed() {
    let defs_name = format!("QzvxDefs{CANARY}");
    let mut schema = json!({
        "type": "object",
        "required": ["token"],
        "properties": {
            "token": {"$ref": format!("#/$defs/{defs_name}")}
        },
        "$defs": {}
    });
    schema["$defs"][defs_name.as_str()] = json!({"type": "string", "pattern": "^redacted$"});
    let plugin = openapi_request_plugin(schema, JSON);
    let body = format!(r#"{{"token":"{CANARY}"}}"#);
    let (status, detail, metadata) = oa_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, &defs_name);
    assert!(
        metadata.contains("request body does not satisfy the request schema"),
        "{metadata}"
    );
    assert!(
        metadata.contains("pattern") || metadata.contains(UNKNOWN_KEYWORD),
        "safe keyword category must survive: {metadata}"
    );
}

#[tokio::test]
async fn openapi_response_schema_path_defs_canary_is_not_disclosed() {
    let defs_name = format!("QzvxDefs{CANARY}");
    let mut schema = json!({
        "type": "object",
        "required": ["token"],
        "properties": {
            "token": {"$ref": format!("#/$defs/{defs_name}")}
        },
        "$defs": {}
    });
    schema["$defs"][defs_name.as_str()] = json!({"type": "string", "pattern": "^redacted$"});
    let plugin = openapi_response_plugin(schema, JSON);
    let body = format!(r#"{{"token":"{CANARY}"}}"#);
    let (status, detail, metadata) = oa_response_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 502);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, &defs_name);
    assert!(
        metadata.contains("response body does not satisfy the response schema"),
        "{metadata}"
    );
    assert!(
        !metadata.contains("/$defs/"),
        "raw schema paths must not appear: {metadata}"
    );
}

// ───────────────────────── validation_diagnostics depth ─────────────────────

#[test]
fn safe_location_without_json_pointer_prefix_returns_root() {
    let names = SafeFieldNames::default();
    assert_eq!(
        safe_location("payloadSegmentCanary", &names),
        ROOT_LOCATION,
        "non-pointer input must not echo payload text"
    );
}

#[test]
fn safe_location_malformed_escapes_never_echo_attacker_tokens() {
    let names = SafeFieldNames::from_schema(&json!({
        "type": "object",
        "properties": {"a~b": {"type": "string"}}
    }));
    assert_eq!(safe_location("/a~0b", &names), "/a~b");
    let hostile_escape = format!("/~2{CANARY}");
    let rendered = safe_location(&hostile_escape, &names);
    assert_no_disclosure(&rendered, "", CANARY);
    assert_eq!(rendered, format!("/{REDACTED_SEGMENT}"));
    assert_eq!(
        safe_location("/trailing~", &names),
        format!("/{REDACTED_SEGMENT}"),
        "a dangling escape must not leak raw pointer bytes"
    );
}

#[test]
fn safe_location_redacts_post_unescape_oversized_segments() {
    let names = SafeFieldNames::default();
    let oversized = "z".repeat(MAX_SEGMENT_CHARS + 1);
    assert_eq!(
        safe_location(&format!("/{oversized}"), &names),
        format!("/{REDACTED_SEGMENT}")
    );
}

#[test]
fn safe_location_truncates_on_total_character_budget() {
    let first = "a".repeat(MAX_SEGMENT_CHARS);
    let second = "b".repeat(MAX_SEGMENT_CHARS);
    let names = SafeFieldNames::from_schema(&json!({
        "type": "object",
        "properties": {
            (first.clone()): {"type": "string"},
            (second.clone()): {"type": "string"}
        }
    }));
    let rendered = safe_location(&format!("/{first}/{second}"), &names);
    assert!(
        rendered.ends_with(TRUNCATED_LOCATION_MARKER),
        "location must stay within the compiled-in character ceiling: {rendered}"
    );
    assert!(
        rendered.chars().count() <= 96 + TRUNCATED_LOCATION_MARKER.len(),
        "rendered location grew without bound: {rendered}"
    );
}

#[test]
fn safe_field_names_collects_dependent_and_composed_schema_names() {
    let names = SafeFieldNames::from_schema(&json!({
        "type": "object",
        "dependentRequired": {
            "whenPresent": ["alsoRequired", "peerRequired"]
        },
        "dependentSchemas": {
            "schemaTrigger": {
                "properties": {"schemaSibling": {"type": "string"}}
            }
        },
        "allOf": [{
            "properties": {"allOfField": {"type": "string"}}
        }],
        "properties": {
            "whenPresent": {"type": "string"},
            "alsoRequired": {"type": "string"},
            "peerRequired": {"type": "string"},
            "schemaTrigger": {"type": "string"}
        }
    }));
    for declared in [
        "whenPresent",
        "alsoRequired",
        "peerRequired",
        "schemaTrigger",
        "schemaSibling",
        "allOfField",
    ] {
        assert!(
            names.allows(declared),
            "schema-declared member {declared:?} must survive collection"
        );
    }
}

#[test]
fn safe_field_names_collects_draft7_tuple_item_properties() {
    let names = SafeFieldNames::from_schema(&json!({
        "type": "array",
        "items": [
            {"type": "string"},
            {
                "type": "object",
                "properties": {"tupleItemField": {"type": "integer"}}
            }
        ]
    }));
    assert!(names.allows("tupleItemField"));
}

#[test]
fn safe_field_names_skips_oversized_required_names_and_deep_leaves() {
    let oversized = "n".repeat(MAX_SEGMENT_CHARS + 1);
    let shallow = SafeFieldNames::from_schema(&json!({"required": [oversized.clone()]}));
    assert!(
        !shallow.allows(&oversized),
        "names longer than the segment ceiling must never be echoed"
    );

    fn nested(depth: usize) -> Value {
        if depth == 0 {
            return json!({
                "type": "object",
                "properties": {"deepLeaf": {"type": "string"}}
            });
        }
        json!({
            "type": "object",
            "properties": {"inner": nested(depth - 1)}
        })
    }
    let deep = SafeFieldNames::from_schema(&nested(30));
    assert!(
        !deep.allows("deepLeaf"),
        "names beyond the schema walk budget must not be collected"
    );
    assert!(
        deep.allows("inner"),
        "shallow declared names must still survive"
    );
}

#[test]
fn xml_error_category_maps_representative_variants_to_fixed_text() {
    use roxmltree::{Error as XmlError, TextPos};

    let pos = TextPos::new(1, 1);
    let cases: &[(&str, XmlError)] = &[
        (
            "entity references expand recursively",
            XmlError::EntityReferenceLoop(pos),
        ),
        ("document has no root element", XmlError::NoRootNode),
        (
            "document exceeds the parser node budget",
            XmlError::NodesLimitReached,
        ),
        (
            "element has too many attributes",
            XmlError::AttributesLimitReached,
        ),
        (
            "document declares too many namespaces",
            XmlError::NamespacesLimitReached,
        ),
        (
            "XML declaration is misplaced or duplicated",
            XmlError::UnexpectedDeclaration(pos),
        ),
        (
            "document type declaration is not permitted",
            XmlError::DtdDetected,
        ),
        (
            "element or attribute name is not a valid XML name",
            XmlError::InvalidName(pos),
        ),
        (
            "document contains a character XML does not allow",
            XmlError::NonXmlChar('\u{fffe}', pos),
        ),
        (
            "unexpected character in markup",
            XmlError::InvalidChar(b'<', b'>', pos),
        ),
        (
            "unexpected character in markup",
            XmlError::InvalidChar2("tag", b'!', pos),
        ),
        (
            "unexpected token in markup",
            XmlError::InvalidString("token", pos),
        ),
        (
            "document ended before markup was complete",
            XmlError::UnexpectedEndOfStream,
        ),
    ];
    for (expected, error) in cases {
        let category = xml_error_category(error);
        assert_eq!(category, *expected, "unexpected mapping for {error:?}");
        assert_no_disclosure(category, "", CANARY);
        assert!(
            !category.contains("TextPos"),
            "category must not echo parser coordinates: {category}"
        );
    }
}

#[tokio::test]
async fn openapi_request_dependent_required_keeps_declared_path_only() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "object",
            "properties": {
                "whenPresent": {"type": "string"},
                "alsoRequired": {"type": "string"}
            },
            "dependentRequired": {
                "whenPresent": ["alsoRequired"]
            }
        }),
        JSON,
    );
    let body = format!(r#"{{"whenPresent":"{CANARY}"}}"#);
    let (status, detail, metadata) = oa_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        metadata.contains("/alsoRequired"),
        "dependentRequired child name is schema-declared: {metadata}"
    );
    assert!(
        metadata.contains("dependentRequired") || metadata.contains(UNKNOWN_KEYWORD),
        "allowlisted keyword must survive: {metadata}"
    );
}

#[tokio::test]
async fn openapi_request_tuple_items_failure_uses_declared_path() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "array",
            "items": [
                {"type": "string"},
                {
                    "type": "object",
                    "properties": {"tupleItemField": {"type": "integer"}}
                }
            ]
        }),
        JSON,
    );
    let body = format!(r#"["ok", {{"tupleItemField":"{CANARY}"}}]"#);
    let (status, detail, metadata) = oa_request_reject(&plugin, JSON, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert!(
        metadata.contains(&format!("/{NUMERIC_SEGMENT}/tupleItemField")),
        "tuple item index must use the numeric marker: {metadata}"
    );
    assert!(
        metadata.contains("/tupleItemField"),
        "schema-declared tuple property must survive: {metadata}"
    );
}

#[tokio::test]
async fn body_validator_request_xml_category_withholds_markup_bytes() {
    let plugin = body_validator_with(json!({
        "validate_xml": true,
        "content_types": ["application/xml"]
    }));
    let body = format!("<root><id>{CANARY}</id></unclosed>");
    let (status, detail) = bv_request_reject(&plugin, XML, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, "", CANARY);
    assert!(
        detail.contains("element tags are not balanced")
            || detail.contains("document ended before markup was complete"),
        "malformed XML must surface only a fixed category: {detail}"
    );
}

#[tokio::test]
async fn openapi_request_xml_dtd_is_a_fixed_category_not_a_declaration() {
    let plugin = openapi_request_plugin(
        json!({
            "type": "object",
            "properties": {"id": {"type": "integer"}}
        }),
        XML,
    );
    let body = format!("<!DOCTYPE {HOSTILE_MEMBER}><root><id>{CANARY}</id></root>");
    let (status, detail, metadata) = oa_request_reject(&plugin, XML, body.as_bytes()).await;

    assert_eq!(status, 400);
    assert_no_disclosure(&detail, &metadata, CANARY);
    assert_no_disclosure(&detail, &metadata, HOSTILE_MEMBER);
    assert!(
        metadata.contains("document type declaration is not permitted"),
        "DTD rejection must stay value-free: {metadata}"
    );
}
