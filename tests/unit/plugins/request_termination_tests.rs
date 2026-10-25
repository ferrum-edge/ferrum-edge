//! Tests for request_termination plugin

use ferrum_edge::_test_support::{
    finalize_plugin_rejection_for_test, normalize_reject_response,
    set_request_http_flavor_for_test, set_request_wire_protocol_for_test,
};
use ferrum_edge::HttpFlavor;
use ferrum_edge::config::types::HttpWireTransport;
use ferrum_edge::plugins::request_termination::{
    REQUEST_TERMINATION_CONFIG_KEYS, REQUEST_TERMINATION_MAX_HEADER_VALUE_BYTES,
    REQUEST_TERMINATION_MAX_HEADERS, REQUEST_TERMINATION_TRIGGER_KEYS, RequestTermination,
};
use ferrum_edge::plugins::{HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use http::{HeaderMap, StatusCode};
use serde_json::json;

/// Dispatch the plugin and project its shared-`Bytes` result into the text
/// `Reject` shape most assertions in this file read. The plugin itself always
/// returns `RejectBinary` (pinned by
/// `test_canned_body_shares_one_allocation_across_requests_including_head`);
/// a text `Reject` coming back unchanged here fails that test, not this helper.
async fn run(plugin: &RequestTermination, ctx: &mut RequestContext) -> PluginResult {
    match plugin.on_request_received(ctx).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => PluginResult::Reject {
            status_code,
            body: String::from_utf8(body.to_vec()).expect("canned body is UTF-8"),
            headers,
        },
        other => other,
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

fn make_ctx_with_header(method: &str, path: &str, header: &str, value: &str) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    let mut raw = HeaderMap::new();
    raw.insert(
        http::HeaderName::from_bytes(header.as_bytes()).expect("header name"),
        http::HeaderValue::from_str(value).expect("header value"),
    );
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx
}

fn make_ctx_with_raw_headers(method: &str, path: &str, raw: HeaderMap) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    ctx
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = RequestTermination::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "request_termination");
    assert_eq!(plugin.priority(), priority::REQUEST_TERMINATION);
    assert_eq!(plugin.priority(), 125);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

// === Always trigger ===

#[tokio::test]
async fn test_always_trigger_rejects() {
    let plugin = RequestTermination::new(&json!({})).unwrap();
    let mut ctx = make_ctx("GET", "/anything");

    let result = run(&plugin, &mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503); // default
            assert!(body.contains("Service unavailable"));
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_custom_status_code() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 418
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 418);
            assert!(body.contains("418"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_invalid_status_code_rejects_creation() {
    let err = RequestTermination::new(&json!({
        "status_code": 999
    }))
    .err()
    .expect("invalid status code should be rejected");

    assert!(err.contains("status_code"), "got: {err}");
}

#[tokio::test]
async fn test_status_code_zero_rejects_creation() {
    let err = RequestTermination::new(&json!({
        "status_code": 0
    }))
    .err()
    .expect("zero status code should be rejected");

    assert!(err.contains("status_code"), "got: {err}");
}

#[test]
fn test_status_code_non_integer_rejects_creation() {
    let err = RequestTermination::new(&json!({
        "status_code": "503"
    }))
    .err()
    .expect("non-integer status code should be rejected");

    assert!(err.contains("status_code"), "got: {err}");
}

#[test]
fn test_integral_status_code_json_numbers_are_admitted() {
    let config =
        serde_json::from_str(r#"{"status_code":503.0}"#).expect("integral JSON number fixture");
    RequestTermination::new(&config).expect("503.0 must be admitted as 503");
    let fractional =
        serde_json::from_str(r#"{"status_code":503.1}"#).expect("fractional JSON number fixture");
    assert!(RequestTermination::new(&fractional).is_err());
}

#[test]
fn test_invalid_content_type_rejects_creation() {
    let err = RequestTermination::new(&json!({
        "content_type": "text/plain\r\nx-bad: yes"
    }))
    .err()
    .expect("invalid content-type header value should be rejected");

    assert!(err.contains("content_type"), "got: {err}");
}

#[test]
fn test_trigger_rejects_invalid_header_name() {
    let err = RequestTermination::new(&json!({
        "trigger": {
            "header": "bad header"
        }
    }))
    .err()
    .expect("invalid trigger header should be rejected");

    assert!(err.contains("trigger.header"), "got: {err}");
}

#[test]
fn test_trigger_rejects_ambiguous_fields() {
    for trigger in [
        json!({
            "path_prefix": "/admin",
            "header": "x-maintenance"
        }),
        json!({
            "path_prefix": "/admin",
            "header_value": "true"
        }),
    ] {
        let err = RequestTermination::new(&json!({"trigger": trigger}))
            .err()
            .expect("ambiguous trigger fields should be rejected");

        assert!(err.contains("only one"), "got: {err}");
    }

    let err = RequestTermination::new(&json!({
        "trigger": {"header_value": "true"}
    }))
    .err()
    .expect("header_value without header should be rejected");
    assert!(err.contains("requires `trigger.header`"), "got: {err}");
}

#[test]
fn test_trigger_rejects_path_prefix_without_leading_slash() {
    // Request paths come from `req.uri().path()`, which is origin-form (rooted
    // at '/') for ordinary requests. A prefix like "admin" can never match
    // `/admin/...`, so reject it at construction instead of silently never
    // firing. The lone asterisk-form exception ("*") is covered separately.
    let err = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "admin" }
    }))
    .err()
    .expect("path_prefix without a leading slash should be rejected");

    assert!(err.contains("path_prefix"), "got: {err}");
    assert!(err.contains("start with `/`"), "got: {err}");
}

#[test]
fn test_trigger_rejects_path_prefix_with_query_or_space() {
    for (prefix, needle) in [
        ("/a?b", "query delimiter"),
        ("/admin ", "literal space"),
        ("/api name", "literal space"),
        ("/a#frag", "fragment delimiter"),
    ] {
        let err = RequestTermination::new(&json!({
            "trigger": { "path_prefix": prefix }
        }))
        .err()
        .unwrap_or_else(|| panic!("unreachable path_prefix {prefix:?} must be rejected"));
        assert!(
            err.contains("path_prefix"),
            "prefix {prefix:?} error: {err}"
        );
        assert!(err.contains(needle), "prefix {prefix:?} error: {err}");
    }

    for prefix in ["/", "/admin", "/v1.0/users", "*"] {
        RequestTermination::new(&json!({
            "trigger": { "path_prefix": prefix }
        }))
        .unwrap_or_else(|error| {
            panic!("reachable path_prefix {prefix:?} must be admitted: {error}")
        });
    }
}

#[tokio::test]
async fn test_trigger_accepts_asterisk_form_path_prefix() {
    // `OPTIONS *` (server-wide options) has an asterisk-form request target,
    // which `req.uri().path()` exposes as "*". A `path_prefix` of "*" is the
    // only non-'/'-rooted value that can match a live request, so it must be
    // accepted and must fire on that request — and only that request.
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "*" }
    }))
    .expect("path_prefix \"*\" matches asterisk-form requests and must be accepted");

    // Matches the asterisk-form target carried by `OPTIONS *`.
    let mut asterisk_ctx = make_ctx("OPTIONS", "*");
    assert!(
        matches!(
            run(&plugin, &mut asterisk_ctx).await,
            PluginResult::Reject { .. }
        ),
        "path_prefix \"*\" should terminate an asterisk-form request"
    );

    // Does not match ordinary origin-form paths.
    let mut origin_ctx = make_ctx("GET", "/admin");
    assert!(
        matches!(run(&plugin, &mut origin_ctx).await, PluginResult::Continue),
        "path_prefix \"*\" must not terminate origin-form requests"
    );
}

#[test]
fn test_trigger_rejects_path_prefix_with_control_chars() {
    // CR/LF (and other control characters) never survive request-line parsing,
    // so a prefix containing them can never match a live request.
    let err = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/admin\r\nx-bad: yes" }
    }))
    .err()
    .expect("path_prefix with control characters should be rejected");

    assert!(err.contains("path_prefix"), "got: {err}");
    assert!(err.contains("control characters"), "got: {err}");
}

// === Custom body ===

#[tokio::test]
async fn test_custom_body() {
    let plugin = RequestTermination::new(&json!({
        "body": "Custom maintenance page",
        "content_type": "text/plain"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "Custom maintenance page");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_custom_message_in_json() {
    let plugin = RequestTermination::new(&json!({
        "message": "Under maintenance"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("Under maintenance"));
            assert!(body.contains("503"));
            // Verify it's valid JSON
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["message"], "Under maintenance");
            assert_eq!(parsed["status_code"], 503);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_json_escaping_in_message() {
    let plugin = RequestTermination::new(&json!({
        "message": "Error: \"invalid\" request\\path"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            // Body should be valid JSON with properly escaped characters
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
            assert!(parsed.is_ok(), "Body should be valid JSON: {}", body);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_xml_response_body() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/xml",
        "message": "Service down"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(headers.get("content-type").unwrap(), "application/xml");
            assert!(body.contains("<?xml version=\"1.0\"?>"));
            assert!(body.contains("<message>Service down</message>"));
            assert!(body.contains("<status_code>503</status_code>"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_xml_escaping() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "text/xml",
        "message": "Error <b>bad</b> & \"quoted\""
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("&lt;b&gt;bad&lt;/b&gt;"));
            assert!(body.contains("&amp;"));
            assert!(body.contains("&quot;quoted&quot;"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_plain_text_response() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "text/plain",
        "message": "Maintenance"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "Maintenance");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_json_object_message_is_emitted_as_body() {
    // Issue #3930: content_type JSON + a JSON object message must not wrap the
    // object inside the legacy {message,status_code} envelope.
    let plugin = RequestTermination::new(&json!({
        "status_code": 503,
        "content_type": "application/json",
        "message": r#"{"error":"scheduled-maintenance"}"#
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
            assert_eq!(body, r#"{"error":"scheduled-maintenance"}"#);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "scheduled-maintenance");
            assert!(parsed.get("message").is_none());
            assert!(parsed.get("status_code").is_none());
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_json_array_message_is_emitted_as_body() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/hal+json; charset=utf-8",
        "message": r#"[{"error":"scheduled-maintenance"}]"#
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(
                headers.get("content-type").unwrap(),
                "application/hal+json; charset=utf-8"
            );
            assert_eq!(body, r#"[{"error":"scheduled-maintenance"}]"#);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_malformed_json_message_fails_safe_to_envelope() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 503,
        "content_type": "application/json",
        "message": "{invalid"
    }))
    .expect("malformed JSON message must not panic or reject construction");
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("fail-safe body must be valid JSON");
            assert_eq!(parsed["message"], "{invalid");
            assert_eq!(parsed["status_code"], 503);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_duplicate_key_json_message_fails_safe_to_envelope() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/json",
        "message": r#"{"error":"first","error":"second"}"#
    }))
    .expect("duplicate-key JSON must not panic or reject construction");
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("fail-safe body must be valid JSON");
            assert_eq!(parsed["message"], r#"{"error":"first","error":"second"}"#);
            assert_eq!(parsed["status_code"], 503);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_pretty_printed_json_message_is_compacted() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/json",
        "message": "{\n  \"error\": \"scheduled-maintenance\"\n}"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, r#"{"error":"scheduled-maintenance"}"#);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_json_looking_plain_text_is_not_parsed() {
    // Non-JSON content types never parse `message` as JSON, even when the
    // text would be a valid JSON object.
    let plugin = RequestTermination::new(&json!({
        "content_type": "text/plain",
        "message": r#"{"error":"scheduled-maintenance"}"#
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(headers.get("content-type").unwrap(), "text/plain");
            assert_eq!(body, r#"{"error":"scheduled-maintenance"}"#);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_xml_json_looking_message_stays_in_xml_envelope() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/xml",
        "message": r#"{"error":"scheduled-maintenance"}"#
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(headers.get("content-type").unwrap(), "application/xml");
            assert!(body.contains("<?xml version=\"1.0\"?>"));
            assert!(body.contains(
                "<message>{&quot;error&quot;:&quot;scheduled-maintenance&quot;}</message>"
            ));
            assert!(body.contains("<status_code>503</status_code>"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

// === Path prefix trigger ===

#[tokio::test]
async fn test_path_prefix_trigger_matches() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/admin" }
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/admin/settings");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_path_prefix_trigger_no_match() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/admin" }
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_path_prefix_exact_match() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/maintenance" }
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/maintenance");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

// === Header match trigger ===

#[tokio::test]
async fn test_header_trigger_matches() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Debug",
            "header_value": "true"
        }
    }))
    .unwrap();

    let mut ctx = make_ctx_with_header("GET", "/", "x-debug", "true");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_header_trigger_value_mismatch() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Debug",
            "header_value": "true"
        }
    }))
    .unwrap();

    let mut ctx = make_ctx_with_header("GET", "/", "x-debug", "false");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_header_trigger_missing_header() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Debug",
            "header_value": "true"
        }
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_header_trigger_any_value() {
    // When header_value is empty, any value should match
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Maintenance"
        }
    }))
    .unwrap();

    let mut ctx = make_ctx_with_header("GET", "/", "x-maintenance", "anything");
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

// === Edge cases ===

#[tokio::test]
async fn test_boundary_status_codes() {
    // Minimum valid final status code
    let plugin = RequestTermination::new(&json!({ "status_code": 200 })).unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 200),
        _ => panic!("Expected Reject"),
    }

    // Maximum valid status code
    let plugin = RequestTermination::new(&json!({ "status_code": 599 })).unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 599),
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_empty_message_uses_default() {
    let plugin = RequestTermination::new(&json!({})).unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("Service unavailable"));
        }
        _ => panic!("Expected Reject"),
    }
}

// === Pre-rendered body / hot path correctness ===
//
// Bodies are rendered once at construction time. These tests verify that
// repeated dispatch returns identical, well-formed payloads — i.e. nothing
// in the hot path mutates shared state.

#[tokio::test]
async fn test_repeated_calls_return_identical_body() {
    let plugin = RequestTermination::new(&json!({
        "message": "Maintenance",
        "status_code": 503
    }))
    .unwrap();

    let mut bodies = Vec::with_capacity(3);
    for _ in 0..3 {
        let mut ctx = make_ctx("GET", "/");
        match run(&plugin, &mut ctx).await {
            PluginResult::Reject { body, .. } => bodies.push(body),
            other => panic!("Expected Reject, got {:?}", other),
        }
    }
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[1], bodies[2]);
}

#[tokio::test]
async fn test_pre_rendered_json_body_is_parseable() {
    let plugin = RequestTermination::new(&json!({
        "message": "Down for maintenance",
        "status_code": 503
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("body must be valid JSON");
            assert_eq!(parsed["message"], "Down for maintenance");
            assert_eq!(parsed["status_code"], 503);
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_pre_rendered_xml_body_well_formed_with_special_chars() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "text/xml",
        "message": "<crash> & burn"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            // Must escape '<', '>', and '&' so the XML stays well-formed.
            assert!(
                body.contains("&lt;crash&gt;"),
                "expected escaped angle brackets in {}",
                body
            );
            assert!(
                body.contains("&amp; burn"),
                "expected escaped ampersand in {}",
                body
            );
            // No raw control characters that would break parsers.
            assert!(!body.contains('\u{0}'));
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_content_type_structured_suffix_json() {
    // RFC 6838 structured suffix: application/hal+json must render as JSON.
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/hal+json; charset=utf-8",
        "message": "hi"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["message"], "hi");
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_content_type_bogus_substring_not_json() {
    // `application/notjson` must NOT be treated as JSON — falls through to
    // plain text so a JSON-structured body isn't sent with a non-JSON type.
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/notjson",
        "message": "hi"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "hi");
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_json_body_escapes_control_chars_and_unicode() {
    // serde_json::to_string handles newlines, tabs, quotes, backslashes, and
    // non-ASCII correctly so operator-supplied messages never produce invalid
    // JSON.
    let plugin = RequestTermination::new(&json!({
        "message": "line1\nline2\t\"quoted\"\\back — ünîcödé"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("body must be valid JSON");
            assert_eq!(
                parsed["message"],
                "line1\nline2\t\"quoted\"\\back — ünîcödé"
            );
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn test_explicit_body_takes_precedence_over_message() {
    let plugin = RequestTermination::new(&json!({
        "body": "literal payload",
        "message": "ignored"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => assert_eq!(body, "literal payload"),
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[test]
fn test_config_requires_object_and_rejects_unknown_keys() {
    for invalid in [
        json!(null),
        json!("enabled"),
        json!([]),
        json!({"triger": {"path_prefix": "/admin"}}),
        json!({"status_code": 503, "extra": true}),
        json!({"trigger": {"path_prefix": "/admin", "unknown": 1}}),
    ] {
        let err = RequestTermination::new(&invalid)
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {invalid}"));
        assert!(
            err.contains("request_termination"),
            "unexpected error for {invalid}: {err}"
        );
    }

    RequestTermination::new(&json!({}))
        .expect("empty object remains the intentional maintenance default");
    RequestTermination::new(&json!({
        "status_code": 451,
        "trigger": { "path_prefix": "/maintenance" }
    }))
    .expect("valid conditional config must be accepted");
}

#[test]
fn test_explicit_null_properties_are_rejected() {
    for (path, invalid) in [
        ("status_code", json!({"status_code": null})),
        ("content_type", json!({"content_type": null})),
        ("body", json!({"body": null})),
        ("message", json!({"message": null})),
        ("trigger", json!({"trigger": null})),
        (
            "trigger.path_prefix",
            json!({"trigger": {"path_prefix": null}}),
        ),
        ("trigger.header", json!({"trigger": {"header": null}})),
        (
            "trigger.header_value",
            json!({"trigger": {"header": "x-policy", "header_value": null}}),
        ),
    ] {
        let err = RequestTermination::new(&invalid)
            .err()
            .unwrap_or_else(|| panic!("expected explicit null at {path} to be rejected"));
        let leaf = path.rsplit('.').next().expect("path has a leaf");
        assert!(
            err.contains(leaf),
            "unexpected error for explicit null at {path}: {err}"
        );
    }
}

#[test]
fn test_informational_and_101_statuses_are_rejected() {
    for code in [100, 101, 199] {
        let err = RequestTermination::new(&json!({ "status_code": code }))
            .err()
            .expect("informational status must be rejected");
        assert!(err.contains("200 to 599"), "status {code}: {err}");
    }
}

#[tokio::test]
async fn test_no_body_statuses_force_empty_response() {
    for code in [204u16, 205, 304] {
        let plugin = RequestTermination::new(&json!({ "status_code": code }))
            .unwrap_or_else(|e| panic!("status {code} with generated body must force empty: {e}"));
        let mut ctx = make_ctx("GET", "/");
        match run(&plugin, &mut ctx).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, code);
                assert!(body.is_empty(), "status {code} must have empty body");
            }
            other => panic!("Expected Reject, got {other:?}"),
        }

        let err = RequestTermination::new(&json!({
            "status_code": code,
            "body": "not-empty"
        }))
        .err()
        .expect("explicit non-empty body on no-body status must fail");
        assert!(err.contains("cannot carry a response body"), "{err}");
    }
}

#[tokio::test]
async fn test_explicit_empty_body_suppresses_message() {
    let plugin = RequestTermination::new(&json!({
        "body": "",
        "message": "maintenance"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "");
            assert!(!body.contains("maintenance"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_omitted_body_uses_message() {
    let plugin = RequestTermination::new(&json!({
        "message": "maintenance"
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => assert!(body.contains("maintenance")),
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_connect_with_2xx_fails_closed() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 200,
        "body": "{}"
    }))
    .unwrap();
    let mut ctx = make_ctx("CONNECT", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("CONNECT"));
            assert!(!body.contains("{}") || body.contains("403"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_header_presence_matches_non_utf8_raw_value() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "header": "x-block" }
    }))
    .unwrap();
    let mut raw = HeaderMap::new();
    raw.insert(
        "x-block",
        http::HeaderValue::from_bytes(&[0x80]).expect("obs-text"),
    );
    let mut ctx = make_ctx_with_raw_headers("GET", "/", raw);
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_header_exact_matches_individual_field_line_not_folded() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "x-policy",
            "header_value": "true"
        }
    }))
    .unwrap();
    let mut raw = HeaderMap::new();
    raw.append("x-policy", "false".parse().unwrap());
    raw.append("x-policy", "true".parse().unwrap());
    let mut ctx = make_ctx_with_raw_headers("GET", "/", raw);
    assert!(
        matches!(run(&plugin, &mut ctx).await, PluginResult::Reject { .. }),
        "exact match must succeed against an individual appended field line"
    );

    let mut folded_only = make_ctx("GET", "/");
    folded_only
        .headers
        .insert("x-policy".to_string(), "false, true".to_string());
    // Without raw headers the harness falls back to the materialized map, which
    // does not equal "true" — documenting that raw evaluation is required.
    assert!(matches!(
        run(&plugin, &mut folded_only).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_xml_message_rejects_illegal_controls_and_keeps_whitespace() {
    for bad in ["\u{0000}null", "\u{0001}one", "\u{0008}bs"] {
        let err = RequestTermination::new(&json!({
            "content_type": "application/xml",
            "message": bad
        }))
        .err()
        .expect("illegal XML 1.0 control must be rejected");
        assert!(err.contains("XML 1.0"), "{err}");
    }

    let plugin = RequestTermination::new(&json!({
        "content_type": "application/vnd.api+xml",
        "message": "ok\tline\nwith\rbreaks & <markup>"
    }))
    .expect("tab/LF/CR and markup must be accepted for +xml");
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, .. } => {
            roxmltree::Document::parse(&body).expect("generated XML must parse");
            assert!(body.contains("&amp;"));
            assert!(body.contains("&lt;markup&gt;"));
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

#[test]
fn test_config_key_constants_match_documented_surface() {
    assert_eq!(
        REQUEST_TERMINATION_CONFIG_KEYS,
        [
            "status_code",
            "content_type",
            "body",
            "message",
            "headers",
            "trigger"
        ]
    );
    assert_eq!(
        REQUEST_TERMINATION_TRIGGER_KEYS,
        ["path_prefix", "header", "header_value"]
    );
}

#[tokio::test]
async fn test_native_grpc_maps_to_trailers_only_error() {
    let plugin = RequestTermination::new(&json!({})).unwrap();
    let mut ctx = make_ctx("POST", "/pkg.Service/Method");
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = run(&plugin, &mut ctx).await
    else {
        panic!("expected Reject");
    };
    let normalized = normalize_reject_response(
        StatusCode::from_u16(status_code).unwrap(),
        body.as_bytes(),
        &headers,
        true,
    );
    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(normalized.grpc_status, Some(14));
    assert_eq!(
        normalized.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        normalized.headers.get("grpc-message").map(String::as_str),
        Some("Service unavailable")
    );

    let plugin = RequestTermination::new(&json!({"status_code": 200})).unwrap();
    let mut ctx = make_ctx("POST", "/pkg.Service/Method");
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = run(&plugin, &mut ctx).await
    else {
        panic!("expected Reject");
    };
    let normalized = normalize_reject_response(
        StatusCode::from_u16(status_code).unwrap(),
        body.as_bytes(),
        &headers,
        true,
    );
    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(normalized.grpc_status, Some(13));
}

#[tokio::test]
async fn test_websocket_extended_connect_2xx_termination_is_forced_to_403() {
    let plugin = RequestTermination::new(&json!({ "status_code": 200 })).unwrap();
    let mut ctx = make_ctx("GET", "/ws");
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::WebSocket);
    set_request_wire_protocol_for_test(&mut ctx, HttpWireTransport::Http2, false);

    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("CONNECT termination requires a non-success status"));
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let token = "'\"`UNREGISTERED_TRAFFIC_TOKEN\\tail";
    for (config, field, reason) in [
        (
            json!({"trigger": {token: true}}),
            "`trigger`",
            "unknown config key",
        ),
        (
            json!({"status_code": 918273641}),
            "`status_code`",
            "final response from 200 to 599",
        ),
        (
            json!({"status_code": 205, "body": token}),
            "`status_code`",
            "cannot carry a response body",
        ),
        (
            json!({"trigger": {"path_prefix": true}}),
            "`trigger.path_prefix`",
            "must be a string",
        ),
        (
            json!({"trigger": {"path_prefix": "/UNREGISTERED_TRAFFIC_TOKEN?query"}}),
            "`trigger.path_prefix`",
            "query delimiter (`?`)",
        ),
        (
            json!({"trigger": {"path_prefix": "/UNREGISTERED_TRAFFIC_TOKEN#fragment"}}),
            "`trigger.path_prefix`",
            "fragment delimiter (`#`)",
        ),
        (
            json!({"headers": {token: "value"}}),
            "`headers`",
            "not a valid HTTP field name",
        ),
        (
            json!({"headers": {"set-cookie": token}}),
            "`headers`",
            "carries credentials",
        ),
        (
            json!({"headers": {"retry-after": "UNREGISTERED_TRAFFIC_TOKEN\n"}}),
            "`headers`",
            "visible ASCII",
        ),
        (
            json!({"trigger": {"header": "x-policy", "header_value": "UNREGISTERED_TRAFFIC_TOKEN\n"}}),
            "`trigger.header_value`",
            "not permitted in an HTTP field value",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("request_termination", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in [
            "UNREGISTERED_TRAFFIC_TOKEN",
            "918273641",
            "205",
            "true",
            "false",
        ] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// === Shared canned body (request_termination-SOL-1) ===

#[tokio::test]
async fn test_canned_body_shares_one_allocation_across_requests_including_head() {
    // 128 KiB: far past any small-buffer threshold, so a per-request copy is an
    // unmistakable pointer change rather than an allocator coincidence.
    let page = "m".repeat(128 * 1024);
    let plugin = RequestTermination::new(&json!({
        "status_code": 503,
        "content_type": "text/html",
        "body": page
    }))
    .unwrap();

    // Retain every result at once so a copy could not reuse a freed buffer.
    let mut results = Vec::new();
    for method in ["GET", "GET", "HEAD", "HEAD"] {
        let mut ctx = make_ctx(method, "/");
        results.push(plugin.on_request_received(&mut ctx).await);
    }

    let mut pointers = Vec::new();
    for result in &results {
        let PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } = result
        else {
            panic!("termination must return the shared-Bytes RejectBinary, got {result:?}");
        };
        assert_eq!(*status_code, 503);
        assert_eq!(body.len(), 128 * 1024);
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("text/html")
        );
        pointers.push(body.as_ptr() as usize);
    }
    assert!(
        pointers.windows(2).all(|pair| pair[0] == pair[1]),
        "every GET and HEAD result must share the pre-rendered allocation: {pointers:?}"
    );
}

#[tokio::test]
async fn test_finalized_get_keeps_shared_body_and_head_omits_bytes() {
    let page = "p".repeat(64 * 1024);
    let plugin = RequestTermination::new(&json!({
        "status_code": 503,
        "content_type": "text/plain",
        "body": page
    }))
    .unwrap();

    let mut get_ctx = make_ctx("GET", "/");
    let get = plugin.on_request_received(&mut get_ctx).await;
    let PluginResult::RejectBinary { body: raw_body, .. } = &get else {
        panic!("expected RejectBinary, got {get:?}");
    };
    let raw_ptr = raw_body.as_ptr() as usize;
    match finalize_plugin_rejection_for_test(&[], &mut get_ctx, get).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(body.len(), 64 * 1024);
            assert_eq!(
                body.as_ptr() as usize,
                raw_ptr,
                "the GET finalizer must carry the shared allocation, not a copy"
            );
        }
        other => panic!("expected finalized RejectBinary, got {other:?}"),
    }

    let mut head_ctx = make_ctx("HEAD", "/");
    let head = plugin.on_request_received(&mut head_ctx).await;
    match finalize_plugin_rejection_for_test(&[], &mut head_ctx, head).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503);
            assert!(body.is_empty(), "HEAD must not carry content bytes");
            let expected_len = (64 * 1024).to_string();
            assert_eq!(
                headers.get("content-length").map(String::as_str),
                Some(expected_len.as_str()),
                "HEAD keeps the representation length of the GET body"
            );
        }
        other => panic!("expected finalized RejectBinary, got {other:?}"),
    }
}

// === Header trigger OWS normalization (request_termination-CLAUDE-1) ===

#[tokio::test]
async fn test_header_exact_match_compares_the_rfc9110_field_value() {
    // HTTP/1.1 parsing strips surrounding OWS; HPACK/QPACK deliver it verbatim.
    // The same logical header must fire on every transport.
    let plugin = RequestTermination::new(&json!({
        "status_code": 403,
        "trigger": {"header": "x-kill-switch", "header_value": "true"}
    }))
    .unwrap();
    for wire in ["true", "true ", " true", "\ttrue\t", "  true \t"] {
        let mut ctx = make_ctx_with_header("GET", "/", "x-kill-switch", wire);
        assert!(
            matches!(run(&plugin, &mut ctx).await, PluginResult::Reject { .. }),
            "wire value {wire:?} is the field value \"true\" and must terminate"
        );
    }
    for wire in ["tr ue", "true,", "truex", "false"] {
        let mut ctx = make_ctx_with_header("GET", "/", "x-kill-switch", wire);
        assert!(
            matches!(run(&plugin, &mut ctx).await, PluginResult::Continue),
            "wire value {wire:?} must not match \"true\""
        );
    }

    // Each repeated field line is trimmed independently, never folded.
    let mut raw = HeaderMap::new();
    raw.append("x-kill-switch", "false".parse().unwrap());
    raw.append("x-kill-switch", http::HeaderValue::from_static("true "));
    let mut ctx = make_ctx_with_raw_headers("GET", "/", raw);
    assert!(matches!(
        run(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));

    // A padded configured value is normalized to its field value as well.
    let padded = RequestTermination::new(&json!({
        "trigger": {"header": "x-kill-switch", "header_value": " true\t"}
    }))
    .unwrap();
    let mut ctx = make_ctx_with_header("GET", "/", "x-kill-switch", "true");
    assert!(matches!(
        run(&padded, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[test]
fn test_header_value_config_must_be_a_reachable_field_value() {
    for bad in ["true\n", "a\r\nb", "x\u{0001}", "del\u{007F}"] {
        let err = RequestTermination::new(&json!({
            "trigger": {"header": "x-policy", "header_value": bad}
        }))
        .err()
        .unwrap_or_else(|| panic!("unreachable header_value {bad:?} must be rejected"));
        assert!(err.contains("trigger.header_value"), "{bad:?}: {err}");
        assert!(err.contains("never match"), "{bad:?}: {err}");
    }

    for whitespace_only in [" ", "\t", " \t "] {
        let err = RequestTermination::new(&json!({
            "trigger": {"header": "x-policy", "header_value": whitespace_only}
        }))
        .err()
        .unwrap_or_else(|| {
            panic!("whitespace-only header_value {whitespace_only:?} must not become presence")
        });
        assert!(
            err.contains("only whitespace"),
            "{whitespace_only:?}: {err}"
        );
    }

    // Empty stays presence; obs-text (UTF-8) is a legal, reachable field value.
    for ok in ["", "1", " padded ", "caf\u{e9}", "a\tb"] {
        RequestTermination::new(&json!({
            "trigger": {"header": "x-policy", "header_value": ok}
        }))
        .unwrap_or_else(|error| panic!("header_value {ok:?} must be admitted: {error}"));
    }
}

// === Residual unreachable path prefixes (request_termination-CLAUDE-2) ===

#[test]
fn test_trigger_rejects_path_prefix_bytes_the_request_target_parser_refuses() {
    for prefix in ["/a<b", "/a>b", "/a`b", "/<script>"] {
        let err = RequestTermination::new(&json!({
            "trigger": {"path_prefix": prefix}
        }))
        .err()
        .unwrap_or_else(|| panic!("unreachable path_prefix {prefix:?} must be rejected"));
        assert!(err.contains("path_prefix"), "{prefix:?}: {err}");
        assert!(err.contains("backtick"), "{prefix:?}: {err}");
    }

    // `http::uri::PathAndQuery` admits these literally (the H2/H3 parser admits
    // UTF-8 too), and the canonicalizer keeps them, so they are reachable and
    // must stay valid.
    for prefix in [
        "/users/{id}",
        "/caf\u{e9}",
        "/a\"b",
        "/a[0]",
        "/a^b",
        "/a|b",
    ] {
        RequestTermination::new(&json!({
            "trigger": {"path_prefix": prefix}
        }))
        .unwrap_or_else(|error| {
            panic!("reachable path_prefix {prefix:?} must be admitted: {error}")
        });
    }
}

// === Runtime / schema alphabet parity (request_termination-CLAUDE-3) ===

#[test]
fn test_content_type_alphabet_matches_published_schema() {
    for bad in ["text/pl\u{e4}in", "\ntext/plain", "text/plain\u{00A0}"] {
        let err = RequestTermination::new(&json!({"content_type": bad}))
            .err()
            .unwrap_or_else(|| panic!("content_type {bad:?} must be rejected"));
        assert!(err.contains("content_type"), "{bad:?}: {err}");
    }
    for ok in [
        "text/plain",
        " text/plain\t",
        "application/json; charset=utf-8",
    ] {
        RequestTermination::new(&json!({"content_type": ok}))
            .unwrap_or_else(|error| panic!("content_type {ok:?} must be admitted: {error}"));
    }
}

#[test]
fn test_path_prefix_c1_controls_are_rejected() {
    let err = RequestTermination::new(&json!({
        "trigger": {"path_prefix": "/a\u{0085}b"}
    }))
    .err()
    .expect("C1 control in path_prefix must be rejected");
    assert!(err.contains("control characters"), "{err}");
}

// === Configured response headers (request_termination-CLAUDE-5) ===

#[tokio::test]
async fn test_configured_response_headers_are_emitted() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 503,
        "content_type": "text/plain",
        "message": "maintenance",
        "headers": {
            "Retry-After": "120",
            "cache-control": "no-store",
            "X-Maintenance-Window": "02:00-03:00 UTC"
        }
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(body, "maintenance");
            assert_eq!(headers.len(), 4);
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("text/plain")
            );
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("120"));
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(
                headers.get("x-maintenance-window").map(String::as_str),
                Some("02:00-03:00 UTC")
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }

    // No-body statuses may still carry headers.
    let plugin = RequestTermination::new(&json!({
        "status_code": 204,
        "headers": {"cache-control": "no-store"}
    }))
    .unwrap();
    let mut ctx = make_ctx("GET", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert!(body.is_empty());
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_connect_refusal_does_not_carry_configured_headers() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 200,
        "headers": {"cache-control": "public, max-age=3600"}
    }))
    .unwrap();
    let mut ctx = make_ctx("CONNECT", "/");
    match run(&plugin, &mut ctx).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 403);
            assert!(!headers.contains_key("cache-control"), "{headers:?}");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_native_grpc_keeps_trailers_only_contract_with_configured_headers() {
    let plugin = RequestTermination::new(&json!({
        "headers": {"retry-after": "30"}
    }))
    .unwrap();
    let mut ctx = make_ctx("POST", "/pkg.Service/Method");
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = run(&plugin, &mut ctx).await
    else {
        panic!("expected Reject");
    };
    let normalized = normalize_reject_response(
        StatusCode::from_u16(status_code).unwrap(),
        body.as_bytes(),
        &headers,
        true,
    );
    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(normalized.grpc_status, Some(14));
    assert_eq!(
        normalized.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
}

#[test]
fn test_response_headers_refuse_reserved_names() {
    for (name, needle) in [
        ("Content-Length", "protocol-managed"),
        ("transfer-encoding", "protocol-managed"),
        ("Connection", "protocol-managed"),
        ("upgrade", "protocol-managed"),
        ("trailer", "protocol-managed"),
        ("Content-Type", "`content_type`"),
        ("Set-Cookie", "carries credentials"),
        ("set-cookie2", "carries credentials"),
        ("WWW-Authenticate", "carries credentials"),
        ("authorization", "carries credentials"),
        ("proxy-authorization", "carries credentials"),
        ("authentication-info", "carries credentials"),
        ("x-ferrum-diagnostic-ref", "gateway-owned"),
        ("X-Ferrum-Grpc-Web-Accept-Rejected", "gateway-owned"),
        ("grpc-status", "gateway-owned"),
        ("Grpc-Message", "gateway-owned"),
        ("x-gateway-error", "gateway-owned"),
        ("x-gateway-upstream-status", "gateway-owned"),
    ] {
        let err = RequestTermination::new(&json!({"headers": {name: "x"}}))
            .err()
            .unwrap_or_else(|| panic!("reserved response header {name:?} must be rejected"));
        assert!(err.contains("`headers` key"), "{name:?}: {err}");
        assert!(err.contains(needle), "{name:?}: {err}");
    }
}

#[test]
fn test_response_headers_validate_shape_values_and_bounds() {
    for (config, needle) in [
        (json!({"headers": []}), "must be an object"),
        (json!({"headers": "retry-after: 1"}), "must be an object"),
        (json!({"headers": null}), "must be an object"),
        (
            json!({"headers": {"bad name": "1"}}),
            "not a valid HTTP field name",
        ),
        (json!({"headers": {"": "1"}}), "not a valid HTTP field name"),
        (json!({"headers": {"retry-after": 120}}), "must be a string"),
        (
            json!({"headers": {"retry-after": null}}),
            "must be a string",
        ),
        (json!({"headers": {"x-a": "a\r\nx-b: b"}}), "visible ASCII"),
        (json!({"headers": {"x-a": "caf\u{e9}"}}), "visible ASCII"),
        (
            json!({"headers": {"x-a": " 1"}}),
            "leading or trailing whitespace",
        ),
        (
            json!({"headers": {"x-a": "1\t"}}),
            "leading or trailing whitespace",
        ),
        (
            json!({"headers": {"Retry-After": "1", "retry-after": "2"}}),
            "more than once",
        ),
    ] {
        let err = RequestTermination::new(&config)
            .err()
            .unwrap_or_else(|| panic!("invalid headers config must be rejected: {config}"));
        assert!(err.contains("`headers`"), "{config}: {err}");
        assert!(err.contains(needle), "{config}: {err}");
    }

    let at_limit = "v".repeat(REQUEST_TERMINATION_MAX_HEADER_VALUE_BYTES);
    RequestTermination::new(&json!({"headers": {"x-a": at_limit}}))
        .unwrap_or_else(|error| panic!("value at the byte limit must be admitted: {error}"));
    let over_limit = "v".repeat(REQUEST_TERMINATION_MAX_HEADER_VALUE_BYTES + 1);
    let err = RequestTermination::new(&json!({"headers": {"x-a": over_limit}}))
        .err()
        .expect("value over the byte limit must be rejected");
    assert!(err.contains("4096-byte limit"), "{err}");

    let headers_at = |count: usize| {
        let map: serde_json::Map<String, serde_json::Value> = (0..count)
            .map(|i| (format!("x-h{i}"), json!("1")))
            .collect();
        json!({"headers": map})
    };
    RequestTermination::new(&headers_at(REQUEST_TERMINATION_MAX_HEADERS))
        .unwrap_or_else(|error| panic!("headers at the entry limit must be admitted: {error}"));
    let err = RequestTermination::new(&headers_at(REQUEST_TERMINATION_MAX_HEADERS + 1))
        .err()
        .expect("headers over the entry limit must be rejected");
    assert!(err.contains("at most"), "{err}");

    // Empty values and interior whitespace are legal field values.
    RequestTermination::new(&json!({"headers": {"x-empty": "", "x-inner": "a  b\tc"}}))
        .unwrap_or_else(|error| panic!("legal values must be admitted: {error}"));
}
