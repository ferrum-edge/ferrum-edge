//! WAF production-launch review hardening.
//!
//! * gRPC / gRPC-Web bodies are inspected message by message, so a JSON-path
//!   rule sees each `+json` message and a `grpc-encoding`-compressed message
//!   cannot carry a payload past an enforcing body policy (waf-SOL-1).
//! * A bounded response relabeled `text/event-stream` by a later hook is still
//!   judged by the final response-body phase (waf-SOL-2).
//! * JSON-path-only policies do not normalize the whole raw body (waf-SOL-3).
//! * Request bodies are governed on every method that carries one (M1).
//! * Hits record the matched field NAMES, never values (M3).
//! * `global_exemptions.header_present` also suppresses the strict `block`
//!   dispositions (M8).
//! * `global_exemptions.paths` literals must be canonical (M11).

use base64::Engine;
use ferrum_edge::_test_support::stamp_original_response_metadata_for_test;
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};
use std::collections::HashMap;

const BYPASS_HEADER: &str = "x-trusted-hop";
const BYPASS_SECRET: &str = "trusted-hop-shared-secret";

fn waf(mut config: Value) -> Result<Waf, String> {
    if let Some(object) = config.as_object_mut()
        && !object.contains_key("scan_budget_ms")
    {
        object.insert("scan_budget_ms".to_string(), json!(0));
    }
    Waf::new(&config)
}

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new("203.0.113.10".into(), method.into(), path.into())
}

fn meta<'a>(ctx: &'a RequestContext, key: &str) -> Option<&'a str> {
    ctx.metadata.get(key).map(String::as_str)
}

fn is_reject(result: &PluginResult) -> bool {
    matches!(result, PluginResult::Reject { .. })
}

async fn final_request_body(
    plugin: &Waf,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (PluginResult, RequestContext) {
    let mut request = ctx(method, "/rpc");
    for (name, value) in headers {
        request
            .headers
            .insert((*name).to_string(), (*value).to_string());
    }
    let headers = request.headers.clone();
    let result = plugin
        .on_final_request_body_with_context(&mut request, &headers, body)
        .await;
    (result, request)
}

fn grpc_frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("test payload fits a gRPC frame");
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(flag);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn json_path_bio_rule() -> Value {
    json!({
        "mode": "enforce",
        "include_default_rules": false,
        "custom_rules": [{
            "id": "BIO",
            "name": "forbidden bio",
            "category": "custom",
            "severity": "high",
            "target": { "type": "body_json_path", "path": "user.bio" },
            "match_kind": "contains",
            "pattern": "forbidden-canary",
            "action": "enforce"
        }]
    })
}

fn enforcing_body_text_rule(mode: &str) -> Value {
    json!({
        "mode": mode,
        "include_default_rules": false,
        "custom_rules": [{
            "id": "BODY-NEEDLE",
            "name": "body needle",
            "category": "custom",
            "severity": "high",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "needle",
            "action": "enforce"
        }]
    })
}

fn enforcing_response_rule() -> Value {
    json!({
        "mode": "enforce",
        "include_default_rules": false,
        "response_inspection": true,
        "response_body_inspection": true,
        "custom_rules": [{
            "id": "RESP-SECRET",
            "name": "response secret",
            "category": "custom",
            "severity": "high",
            "target": "response_body",
            "match_kind": "contains",
            "pattern": "secret",
            "action": "enforce"
        }]
    })
}

// ── waf-SOL-1: gRPC message inspection ─────────────────────────────────────

#[tokio::test]
async fn grpc_json_messages_reach_json_path_rules() {
    let plugin = waf(json_path_bio_rule()).unwrap();
    let forbidden = grpc_frame(0, br#"{"user":{"bio":"forbidden-canary"}}"#);
    let clean = grpc_frame(0, br#"{"user":{"bio":"hello"}}"#);
    for content_type in ["application/grpc+json", "application/grpc-web+json"] {
        let (result, request) = final_request_body(
            &plugin,
            "POST",
            &[("content-type", content_type)],
            &forbidden,
        )
        .await;
        assert!(
            is_reject(&result),
            "{content_type}: a framed JSON message must be parsed as a document"
        );
        assert_eq!(
            meta(&request, "waf.rule_hits"),
            Some("BIO"),
            "{content_type}"
        );

        let (result, _) =
            final_request_body(&plugin, "POST", &[("content-type", content_type)], &clean).await;
        assert!(matches!(result, PluginResult::Continue), "{content_type}");
    }
}

#[tokio::test]
async fn every_grpc_message_of_a_stream_is_inspected() {
    let plugin = waf(json_path_bio_rule()).unwrap();
    let mut body = grpc_frame(0, br#"{"user":{"bio":"first"}}"#);
    body.extend(grpc_frame(0, br#"{"user":{"bio":"forbidden-canary"}}"#));

    let (result, _) = final_request_body(
        &plugin,
        "POST",
        &[("content-type", "application/grpc+json")],
        &body,
    )
    .await;

    assert!(
        is_reject(&result),
        "a later message must not escape the scan"
    );
}

#[tokio::test]
async fn grpc_web_text_bodies_are_decoded_before_message_inspection() {
    let plugin = waf(json_path_bio_rule()).unwrap();
    let frames = grpc_frame(0, br#"{"user":{"bio":"forbidden-canary"}}"#);
    let body = base64::engine::general_purpose::STANDARD.encode(frames);

    let (result, _) = final_request_body(
        &plugin,
        "POST",
        &[("content-type", "application/grpc-web-text+json")],
        body.as_bytes(),
    )
    .await;

    assert!(is_reject(&result));
}

#[tokio::test]
async fn a_compressed_grpc_message_fails_closed_under_an_enforcing_body_policy() {
    let plugin = waf(enforcing_body_text_rule("enforce")).unwrap();
    // The payload bytes are opaque to the WAF; it never decodes grpc-encoding.
    let body = grpc_frame(1, b"\x1f\x8b\x08\x00compressed-needle");

    let (result, request) = final_request_body(
        &plugin,
        "POST",
        &[
            ("content-type", "application/grpc+json"),
            ("grpc-encoding", "gzip"),
        ],
        &body,
    )
    .await;

    assert!(is_reject(&result));
    assert_eq!(
        meta(&request, "waf.block_reason"),
        Some("grpc_message_uninspectable")
    );
    assert_eq!(
        meta(&request, "waf.body_uninspected"),
        Some("grpc_compressed")
    );
    assert_eq!(
        meta(&request, "waf.body_uninspected_target"),
        Some("request_body")
    );
}

#[tokio::test]
async fn a_compressed_grpc_message_is_only_recorded_without_an_enforcing_policy() {
    let plugin = waf(enforcing_body_text_rule("monitor")).unwrap();
    let mut body = grpc_frame(1, b"opaque");
    body.extend(grpc_frame(0, b"needle in an uncompressed message"));

    let (result, request) = final_request_body(
        &plugin,
        "POST",
        &[
            ("content-type", "application/grpc+json"),
            ("grpc-encoding", "gzip"),
        ],
        &body,
    )
    .await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        meta(&request, "waf.body_uninspected"),
        Some("grpc_compressed")
    );
    assert_eq!(meta(&request, "waf.block_reason"), None);
    assert_eq!(
        meta(&request, "waf.rule_hits"),
        Some("BODY-NEEDLE"),
        "the uncompressed messages are still scanned"
    );
}

#[tokio::test]
async fn a_grpc_body_over_the_message_cap_fails_closed_when_enforcing() {
    let plugin = waf(enforcing_body_text_rule("enforce")).unwrap();
    let mut body = Vec::new();
    for _ in 0..1025 {
        body.extend(grpc_frame(0, b"{}"));
    }

    let (result, request) = final_request_body(
        &plugin,
        "POST",
        &[("content-type", "application/grpc+json")],
        &body,
    )
    .await;

    assert!(is_reject(&result));
    assert_eq!(
        meta(&request, "waf.body_uninspected"),
        Some("grpc_message_count")
    );
}

#[tokio::test]
async fn grpc_response_messages_are_inspected_and_compression_fails_closed() {
    let plugin = waf(enforcing_response_rule()).unwrap();
    let headers = HashMap::from([(
        "content-type".to_string(),
        "application/grpc+json".to_string(),
    )]);

    let mut leaking = ctx("POST", "/rpc");
    let result = plugin
        .finalize_client_visible_response_body(
            &mut leaking,
            200,
            &headers,
            &grpc_frame(0, br#"{"token":"secret"}"#),
        )
        .await;
    assert!(is_reject(&result));

    let mut compressed = ctx("POST", "/rpc");
    let result = plugin
        .finalize_client_visible_response_body(
            &mut compressed,
            200,
            &headers,
            &grpc_frame(1, b"opaque"),
        )
        .await;
    assert!(is_reject(&result));
    assert_eq!(
        meta(&compressed, "waf.body_uninspected_target"),
        Some("response_body")
    );

    let mut clean = ctx("POST", "/rpc");
    let result = plugin
        .finalize_client_visible_response_body(
            &mut clean,
            200,
            &headers,
            &grpc_frame(0, br#"{"ok":true}"#),
        )
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── waf-SOL-2: bounded bodies relabeled as SSE ─────────────────────────────

async fn finalize_relabeled_event_stream(
    plugin: &Waf,
    origin_content_type: &str,
    body: &[u8],
) -> (PluginResult, RequestContext) {
    let mut request = ctx("GET", "/events");
    request
        .headers
        .insert("accept".into(), "text/event-stream".into());
    let origin = HashMap::from([("content-type".to_string(), origin_content_type.to_string())]);
    stamp_original_response_metadata_for_test(&mut request, 200, &origin);
    // A later hook (the `sse` wrapper, a response transformer) relabeled it.
    let live = HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let result = plugin
        .finalize_client_visible_response_body(&mut request, 200, &live, body)
        .await;
    (result, request)
}

#[tokio::test]
async fn a_bounded_body_wrapped_as_sse_is_still_scanned() {
    let plugin = waf(enforcing_response_rule()).unwrap();

    let (result, request) =
        finalize_relabeled_event_stream(&plugin, "text/plain", b"data: secret\n\n").await;
    assert!(
        is_reject(&result),
        "a finite body relabeled as SSE must not skip the response-body scan"
    );
    assert_eq!(meta(&request, "waf.rule_hits"), Some("RESP-SECRET"));

    let (result, _) =
        finalize_relabeled_event_stream(&plugin, "text/plain", b"data: hello\n\n").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn a_relabeled_unlisted_origin_type_gets_the_unlisted_disposition() {
    let plugin = waf(enforcing_response_rule()).unwrap();

    let (result, request) =
        finalize_relabeled_event_stream(&plugin, "application/octet-stream", b"data: x\n\n").await;

    assert!(is_reject(&result));
    assert_eq!(meta(&request, "waf.block_reason"), Some("content_type"));
}

#[tokio::test]
async fn a_genuine_origin_event_stream_is_not_judged_by_the_final_body_phase() {
    let plugin = waf(enforcing_response_rule()).unwrap();

    let (result, _) =
        finalize_relabeled_event_stream(&plugin, "text/event-stream", b"data: secret\n\n").await;

    assert!(
        matches!(result, PluginResult::Continue),
        "a pristine event stream is decided in after_proxy, not here"
    );
}

// ── waf-SOL-3: JSON-path-only policies skip whole-body normalization ──────

/// The whole-body text views (layered decode, every normalization variant,
/// Luhn, CIDR) have no consumer unless a body text rule or a body-scoped
/// encoding special is active. The scanner must bail out before building them;
/// this pins that structurally because the saved work has no observable
/// verdict difference.
#[test]
fn json_path_only_policies_return_before_whole_body_text_views() {
    const SCAN_RS: &str = include_str!("../../../src/plugins/waf/scan.rs");
    let body = SCAN_RS
        .split("fn scan_body_rules(")
        .nth(1)
        .expect("scan_body_rules exists");
    let body = body
        .split("\n    pub(super) fn ")
        .next()
        .expect("scan_body_rules body");
    let guard = body
        .find("if !text_views_active {\n            return outcome;\n        }")
        .expect("the text-view guard returns before any whole-body view");
    let first_lossy = body
        .find("String::from_utf8_lossy(body)")
        .expect("the raw text view is still built for text rules");
    let first_text_view = body
        .find("self.scan_body_text_view(")
        .expect("text views are still scanned for text rules");
    assert!(
        guard < first_lossy && guard < first_text_view,
        "whole-body normalization must sit behind `text_views_active`"
    );
}

#[tokio::test]
async fn json_path_only_policy_still_decides_its_selected_scalar() {
    let plugin = waf(json_path_bio_rule()).unwrap();
    let padding = "%61".repeat(10_000);
    let forbidden = format!(r#"{{"user":{{"bio":"forbidden-canary"}},"padding":"{padding}"}}"#);
    let clean = format!(r#"{{"user":{{"bio":"ok"}},"padding":"{padding}"}}"#);

    let (result, _) = final_request_body(
        &plugin,
        "POST",
        &[("content-type", "application/json")],
        forbidden.as_bytes(),
    )
    .await;
    assert!(is_reject(&result));

    let (result, request) = final_request_body(
        &plugin,
        "POST",
        &[("content-type", "application/json")],
        clean.as_bytes(),
    )
    .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(meta(&request, "waf.rule_hits"), None);
}

// ── M1: bodies on every method ─────────────────────────────────────────────

#[tokio::test]
async fn a_body_on_a_method_outside_body_methods_is_scanned() {
    let plugin = waf(enforcing_body_text_rule("enforce")).unwrap();

    for method in ["GET", "SEARCH", "PROPFIND"] {
        let mut labelled = ctx(method, "/search");
        labelled
            .headers
            .insert("content-type".into(), "application/json".into());
        assert!(
            plugin.should_buffer_request_body(&labelled),
            "{method}: a labelled body is buffered"
        );
        let mut sized = ctx(method, "/search");
        sized.headers.insert("content-length".into(), "16".into());
        assert!(
            plugin.should_buffer_request_body(&sized),
            "{method}: a declared length is buffered"
        );

        let (result, request) = final_request_body(
            &plugin,
            method,
            &[("content-type", "application/json")],
            br#"{"q":"needle"}"#,
        )
        .await;
        assert!(is_reject(&result), "{method}");
        assert_eq!(meta(&request, "waf.block_reason"), Some("rule"), "{method}");
    }

    // A request that declares no body keeps the streaming path, and an empty
    // finalized body on such a method is not scanned.
    let bare = ctx("GET", "/search");
    assert!(!plugin.should_buffer_request_body(&bare));
    let (result, _) = final_request_body(&plugin, "GET", &[], b"").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn an_empty_body_methods_list_still_governs_declared_bodies() {
    let mut config = enforcing_body_text_rule("enforce");
    config["body_methods"] = json!([]);
    let plugin = waf(config).unwrap();

    let (result, _) = final_request_body(
        &plugin,
        "POST",
        &[("content-type", "text/plain")],
        b"needle",
    )
    .await;

    assert!(is_reject(&result));
}

// ── M3: matched field names ────────────────────────────────────────────────

fn field_rules_waf() -> Waf {
    let rule = |id: &str, target: &str| {
        json!({
            "id": id,
            "name": id,
            "category": "custom",
            "target": target,
            "match_kind": "contains",
            "pattern": "needle"
        })
    };
    waf(json!({
        "mode": "monitor",
        "include_default_rules": false,
        "custom_rules": [
            rule("Q-NEEDLE", "query_values"),
            rule("H-NEEDLE", "header_values"),
            rule("C-NEEDLE", "cookies")
        ]
    }))
    .unwrap()
}

fn matched_fields(ctx: &RequestContext) -> Vec<String> {
    meta(ctx, "waf.matched_fields")
        .unwrap_or_default()
        .split(',')
        .filter(|field| !field.is_empty())
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn hits_record_matched_field_names_and_never_values() {
    let plugin = field_rules_waf();
    let mut request = ctx("GET", "/search");
    request.set_raw_query_string("q=needle&safe=ok".into());
    request.headers.insert("x-note".into(), "needle".into());
    request
        .headers
        .insert("cookie".into(), "sid=abc; pref=needle".into());

    let result = plugin.authorize(&mut request).await;

    assert!(matches!(result, PluginResult::Continue));
    let fields = matched_fields(&request);
    for expected in ["query:q", "header:x-note", "cookie:pref"] {
        assert!(
            fields.iter().any(|field| field == expected),
            "{expected} missing from {fields:?}"
        );
    }
    for absent in ["query:safe", "cookie:sid"] {
        assert!(
            !fields.iter().any(|field| field == absent),
            "{absent} did not match"
        );
    }
    let raw = meta(&request, "waf.matched_fields").unwrap_or_default();
    assert!(!raw.contains("needle"), "a field value leaked: {raw}");
}

#[tokio::test]
async fn matched_field_names_are_encoded_and_bounded() {
    let plugin = field_rules_waf();
    let long_name = "k".repeat(200);
    let mut request = ctx("GET", "/search");
    request.set_raw_query_string(format!("a%2Cb=needle&{long_name}=needle"));
    request.headers.insert("x,evil".into(), "needle".into());

    let _ = plugin.authorize(&mut request).await;

    let fields = matched_fields(&request);
    assert!(
        fields.iter().any(|field| field == "query:a%2Cb"),
        "a decoded `,` must be encoded, not split: {fields:?}"
    );
    assert!(
        fields.iter().any(|field| field == "header:x%2Cevil"),
        "{fields:?}"
    );
    let truncated = format!("query:{}*", "k".repeat(128));
    assert!(
        fields.iter().any(|field| *field == truncated),
        "an over-long name is cut and marked: {fields:?}"
    );
}

// ── M8: header_present suppresses the strict `block` dispositions ─────────

fn exempt(mut request: RequestContext) -> RequestContext {
    request
        .headers
        .insert(BYPASS_HEADER.into(), BYPASS_SECRET.into());
    request
}

fn with_bypass_secret(mut config: Value) -> Value {
    let mut header_present = serde_json::Map::new();
    header_present.insert(BYPASS_HEADER.to_string(), json!(BYPASS_SECRET));
    config["global_exemptions"] = json!({ "header_present": Value::Object(header_present) });
    config
}

#[tokio::test]
async fn header_present_suppresses_the_strict_oversize_block() {
    let plugin = waf(with_bypass_secret(json!({
        "mode": "enforce",
        "include_default_rules": false,
        "max_scan_bytes": 16,
        "on_body_too_large": "block",
        "custom_rules": [{
            "id": "BODY-MONITOR",
            "name": "monitored",
            "category": "custom",
            "target": "body_text",
            "match_kind": "contains",
            "pattern": "needle",
            "action": "monitor"
        }]
    })))
    .unwrap();
    let body = "a".repeat(64);

    for (trusted, expect_reject) in [(true, false), (false, true)] {
        let mut request = ctx("POST", "/upload");
        if trusted {
            request = exempt(request);
        }
        request
            .headers
            .insert("content-type".into(), "text/plain".into());
        let headers = request.headers.clone();
        let result = plugin
            .on_final_request_body_with_context(&mut request, &headers, body.as_bytes())
            .await;
        assert_eq!(is_reject(&result), expect_reject, "trusted={trusted}");
    }
}

#[tokio::test]
async fn header_present_suppresses_the_strict_unlisted_content_type_block() {
    let plugin = waf(with_bypass_secret(json!({
        "mode": "enforce",
        "on_unlisted_content_type": "block"
    })))
    .unwrap();

    for (trusted, expect_reject) in [(true, false), (false, true)] {
        let mut request = ctx("POST", "/upload");
        if trusted {
            request = exempt(request);
        }
        request
            .headers
            .insert("content-type".into(), "application/octet-stream".into());
        assert_eq!(
            plugin.should_buffer_request_body(&request),
            expect_reject,
            "trusted={trusted}: only a refusable body is buffered"
        );
        let headers = request.headers.clone();
        let result = plugin
            .on_final_request_body_with_context(&mut request, &headers, b"payload")
            .await;
        assert_eq!(is_reject(&result), expect_reject, "trusted={trusted}");
    }
}

#[tokio::test]
async fn header_present_suppresses_the_strict_unlisted_response_block() {
    let plugin = waf(with_bypass_secret(json!({
        "mode": "enforce",
        "response_inspection": true,
        "response_body_inspection": true,
        "on_unlisted_content_type": "block",
        "on_unlisted_response_content_type": "block"
    })))
    .unwrap();
    let headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);

    for (trusted, expect_reject) in [(true, false), (false, true)] {
        let mut request = ctx("GET", "/download");
        if trusted {
            request = exempt(request);
        }
        let result = plugin
            .finalize_client_visible_response_body(&mut request, 200, &headers, b"opaque")
            .await;
        assert_eq!(is_reject(&result), expect_reject, "trusted={trusted}");
    }
}

// ── M11: canonical global_exemptions.paths ─────────────────────────────────

#[test]
fn non_canonical_exemption_paths_are_rejected_at_admission() {
    for path in [
        "/internal/%2ehealth",
        "/api//webhook*",
        "/a/../b",
        "/a/./b*",
    ] {
        let error = waf(json!({
            "mode": "monitor",
            "global_exemptions": { "paths": ["/health", path] }
        }))
        .unwrap_err();
        assert!(
            error.contains("`global_exemptions.paths[1]`")
                && error.contains("not a canonical path"),
            "{path}: {error}"
        );
    }

    // Canonical literals and regex text are admitted unchanged.
    waf(json!({
        "mode": "monitor",
        "global_exemptions": { "paths": ["/health", "/internal/*", "~^/v1\\.0/.*%"] }
    }))
    .unwrap();
}
