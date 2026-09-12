//! Tests for request_termination plugin

use ferrum_edge::_test_support::{normalize_reject_response, set_request_http_flavor_for_test};
use ferrum_edge::HttpFlavor;
use ferrum_edge::plugins::request_termination::{
    REQUEST_TERMINATION_CONFIG_KEYS, REQUEST_TERMINATION_TRIGGER_KEYS, RequestTermination,
};
use ferrum_edge::plugins::{HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use http::{HeaderMap, StatusCode};
use serde_json::json;

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

    let result = plugin.on_request_received(&mut ctx).await;
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

    match plugin.on_request_received(&mut ctx).await {
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
    assert!(err.contains("requires 'trigger.header'"), "got: {err}");
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
    assert!(err.contains("start with '/'"), "got: {err}");
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
            plugin.on_request_received(&mut asterisk_ctx).await,
            PluginResult::Reject { .. }
        ),
        "path_prefix \"*\" should terminate an asterisk-form request"
    );

    // Does not match ordinary origin-form paths.
    let mut origin_ctx = make_ctx("GET", "/admin");
    assert!(
        matches!(
            plugin.on_request_received(&mut origin_ctx).await,
            PluginResult::Continue
        ),
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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
        plugin.on_request_received(&mut ctx).await,
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
        plugin.on_request_received(&mut ctx).await,
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
        plugin.on_request_received(&mut ctx).await,
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
        plugin.on_request_received(&mut ctx).await,
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
        plugin.on_request_received(&mut ctx).await,
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
        plugin.on_request_received(&mut ctx).await,
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
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

// === Edge cases ===

#[tokio::test]
async fn test_boundary_status_codes() {
    // Minimum valid final status code
    let plugin = RequestTermination::new(&json!({ "status_code": 200 })).unwrap();
    let mut ctx = make_ctx("GET", "/");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 200),
        _ => panic!("Expected Reject"),
    }

    // Maximum valid status code
    let plugin = RequestTermination::new(&json!({ "status_code": 599 })).unwrap();
    let mut ctx = make_ctx("GET", "/");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 599),
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_empty_message_uses_default() {
    let plugin = RequestTermination::new(&json!({})).unwrap();
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
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
        match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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
    match plugin.on_request_received(&mut ctx).await {
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
    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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

    match plugin.on_request_received(&mut ctx).await {
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
        match plugin.on_request_received(&mut ctx).await {
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
    match plugin.on_request_received(&mut ctx).await {
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
    match plugin.on_request_received(&mut ctx).await {
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
    match plugin.on_request_received(&mut ctx).await {
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
        plugin.on_request_received(&mut ctx).await,
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
        matches!(
            plugin.on_request_received(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "exact match must succeed against an individual appended field line"
    );

    let mut folded_only = make_ctx("GET", "/");
    folded_only
        .headers
        .insert("x-policy".to_string(), "false, true".to_string());
    // Without raw headers the harness falls back to the materialized map, which
    // does not equal "true" — documenting that raw evaluation is required.
    assert!(matches!(
        plugin.on_request_received(&mut folded_only).await,
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
    match plugin.on_request_received(&mut ctx).await {
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
        ["status_code", "content_type", "body", "message", "trigger"]
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
    } = plugin.on_request_received(&mut ctx).await
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
    } = plugin.on_request_received(&mut ctx).await
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
