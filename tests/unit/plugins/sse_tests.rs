use super::plugin_utils::create_test_proxy;
use bytes::Bytes;
use ferrum_edge::_test_support::{
    finalize_plugin_rejection_parts_for_test, finalize_synthetic_response_for_test,
    install_pending_buffered_response_capacity_refusal_for_test,
    refine_stream_response_for_content_type_for_test, retry_response_decision_context_for_test,
    stamp_original_response_metadata_for_test,
    take_buffered_response_capacity_refusal_pending_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::sse::{
    LAST_EVENT_ID_METADATA_KEY, MAX_LAST_EVENT_ID_BYTES, SsePlugin, redact_sse_log_metadata,
};
use ferrum_edge::plugins::utils::metadata_redaction::{
    REDACTED_PLACEHOLDER, is_sensitive_metadata_key_with_extras, serialize_redacted_metadata,
};
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, priority,
};
use ferrum_edge::proxy::headers::{
    apply_response_headers, strip_client_response_hop_by_hop_headers,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_plugin(config: serde_json::Value) -> SsePlugin {
    SsePlugin::new(&config).unwrap()
}

fn make_sse_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/events".to_string(),
    );
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    ctx
}

fn sse_response_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "text/event-stream".to_string());
    h.insert("content-length".to_string(), "0".to_string());
    h
}

fn json_response_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h.insert("content-length".to_string(), "42".to_string());
    h
}

fn assert_continue(result: &PluginResult) {
    assert!(
        matches!(result, PluginResult::Continue),
        "expected Continue, got {result:?}"
    );
}

fn assert_reject(result: &PluginResult, expected_status: u16) {
    match result {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(*status_code, expected_status, "unexpected reject status");
        }
        other => panic!("expected Reject({expected_status}), got {other:?}"),
    }
}

// ── Metadata & hints ──────────────────────────────────────────────────────────

#[test]
fn test_name_and_priority() {
    let plugin = make_plugin(json!({}));
    assert_eq!(plugin.name(), "sse");
    assert_eq!(plugin.priority(), priority::SSE);
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_supported_protocols_http_only() {
    let plugin = make_plugin(json!({}));
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, HTTP_ONLY_PROTOCOLS);
}

#[test]
fn test_requires_response_body_buffering_defaults_false() {
    let plugin = make_plugin(json!({}));
    assert!(!plugin.requires_response_body_buffering());
}

#[test]
fn test_requires_response_body_buffering_when_wrap_enabled() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_wrap_releases_genuine_sse_after_backend_content_type_is_known() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let ctx = make_sse_ctx();
    let headers = HashMap::new();

    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers,
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &headers,
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("Text/Event-Stream; charset=utf-8"),
        200,
        &headers,
    ));
}

#[test]
fn test_modifies_request_headers_default_true() {
    let plugin = make_plugin(json!({}));
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_modifies_request_headers_true_when_strip_disabled() {
    let plugin = make_plugin(json!({"strip_accept_encoding": false}));
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_applies_after_proxy_on_reject_is_false() {
    let plugin = make_plugin(json!({}));
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_invalid_bool_config_rejected() {
    let err = SsePlugin::new(&json!({"strip_accept_encoding": "yes"}))
        .err()
        .expect("invalid bool must be rejected");
    assert!(err.contains("`strip_accept_encoding` must be a boolean"));
}

#[test]
fn test_invalid_retry_ms_rejected() {
    let err = SsePlugin::new(&json!({"retry_ms": "3000"}))
        .err()
        .expect("invalid retry_ms must be rejected");
    assert!(err.contains("`retry_ms` must be an unsigned integer"));
}

#[test]
fn test_zero_retry_ms_rejected() {
    let err = SsePlugin::new(&json!({"retry_ms": 0}))
        .err()
        .expect("zero retry_ms must be rejected");
    assert!(err.contains("`retry_ms` must be greater than zero"));
}

#[test]
fn test_non_object_config_rejected() {
    for config in [
        json!("disabled"),
        json!(["require_get_method", false]),
        json!(null),
        json!(42),
    ] {
        let err = SsePlugin::new(&config)
            .err()
            .unwrap_or_else(|| panic!("non-object must be rejected: {config}"));
        assert!(
            err.contains("config must be an object"),
            "unexpected error for {config}: {err}"
        );
    }
}

#[test]
fn test_unknown_config_keys_rejected() {
    let err = SsePlugin::new(&json!({
        "require_accept_headr": false,
        "strip_content_lenght": false
    }))
    .err()
    .expect("unknown keys must be rejected");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(err.contains("require_accept_headr"), "{err}");
    assert!(err.contains("strip_content_lenght"), "{err}");
}

#[test]
fn test_explicit_null_members_rejected() {
    let err = SsePlugin::new(&json!({"require_get_method": null}))
        .err()
        .expect("null member must be rejected");
    assert!(
        err.contains("`require_get_method` must be a boolean"),
        "{err}"
    );
}

#[test]
fn test_null_retry_ms_rejected() {
    let err = SsePlugin::new(&json!({"retry_ms": null}))
        .err()
        .expect("null retry_ms must be rejected");
    assert!(
        err.contains("`retry_ms` must be an unsigned integer"),
        "{err}"
    );
}

// ── on_request_received: method validation ────────────────────────────────────

#[tokio::test]
async fn test_get_request_passes() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_post_request_rejected_405() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.method = "POST".to_string();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 405);

    // Should include Allow: GET header.
    if let PluginResult::Reject { headers, .. } = &result {
        assert_eq!(headers.get("allow").unwrap(), "GET");
    }
}

#[tokio::test]
async fn test_put_request_rejected_405() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.method = "PUT".to_string();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 405);
}

#[tokio::test]
async fn test_method_validation_disabled() {
    let plugin = make_plugin(json!({"require_get_method": false}));
    let mut ctx = make_sse_ctx();
    ctx.method = "POST".to_string();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

// ── on_request_received: Accept header validation ─────────────────────────────

#[tokio::test]
async fn test_accept_text_event_stream_passes() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_accept_with_multiple_types_passes() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers.insert(
        "accept".to_string(),
        "application/json, text/event-stream, text/html".to_string(),
    );
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_accept_with_charset_passes() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers.insert(
        "accept".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    );
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_accept_positive_quality_passes() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream; q=1.0".to_string());
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_accept_zero_quality_rejected_406() {
    // RFC 9110 §12.4.2: q=0 means the client explicitly does not accept the
    // representation, so enabled SSE Accept validation must reject it.
    for value in [
        "text/event-stream; q=0",
        "text/event-stream; q=0.0",
        "text/event-stream; q=0.000",
        "text/event-stream; Q=0",
    ] {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_sse_ctx();
        ctx.headers.insert("accept".to_string(), value.to_string());
        let result = plugin.on_request_received(&mut ctx).await;
        assert_reject(&result, 406);
    }
}

#[tokio::test]
async fn test_accept_invalid_or_duplicate_quality_rejected_406() {
    for value in [
        "text/event-stream; q=",
        "text/event-stream; q=2",
        "text/event-stream; q=0.0001",
        "text/event-stream; q=1.1",
        "text/event-stream; q=1; q=0",
        "text/event-stream; q",
        "text/event-stream; Q ",
    ] {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_sse_ctx();
        ctx.headers.insert("accept".to_string(), value.to_string());
        let result = plugin.on_request_received(&mut ctx).await;
        assert_reject(&result, 406);
    }
}

#[tokio::test]
async fn test_accept_mixed_list_with_affirmative_entry_passes() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers.insert(
        "accept".to_string(),
        "text/event-stream; q=0, application/json, text/event-stream; q=1".to_string(),
    );
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_accept_zero_quality_opt_out_allows_request() {
    let plugin = make_plugin(json!({"require_accept_header": false}));
    let mut ctx = make_sse_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream; q=0".to_string());
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_missing_accept_header_rejected_406() {
    let plugin = make_plugin(json!({}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/events".to_string(),
    );
    // No Accept header at all.
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 406);
}

#[tokio::test]
async fn test_wrong_accept_header_rejected_406() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 406);
}

#[tokio::test]
async fn test_accept_substring_media_type_rejected_406() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers.insert(
        "accept".to_string(),
        "application/json, text/event-stream-like".to_string(),
    );

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 406);
}

#[tokio::test]
async fn test_accept_validation_disabled() {
    let plugin = make_plugin(json!({"require_accept_header": false}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/events".to_string(),
    );
    // No Accept header, but validation is disabled.
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

// ── on_request_received: Last-Event-ID stashing ──────────────────────────────

#[tokio::test]
async fn test_last_event_id_stashed_in_metadata() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.headers
        .insert("last-event-id".to_string(), "evt-42".to_string());

    plugin.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.metadata.get(LAST_EVENT_ID_METADATA_KEY).unwrap(),
        "evt-42"
    );
}

#[tokio::test]
async fn test_oversized_last_event_id_rejected() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let oversized = "x".repeat(MAX_LAST_EVENT_ID_BYTES + 1);
    ctx.headers.insert("last-event-id".to_string(), oversized);
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 400);
    assert!(!ctx.metadata.contains_key(LAST_EVENT_ID_METADATA_KEY));
}

#[tokio::test]
async fn test_last_event_id_redacted_from_log_metadata() {
    let mut metadata = HashMap::new();
    metadata.insert(
        LAST_EVENT_ID_METADATA_KEY.to_string(),
        "opaque-resume-cursor".to_string(),
    );
    metadata.insert("sse:wrap_non_sse".to_string(), "1".to_string());
    metadata.insert("sse:relabeled_non_sse".to_string(), "1".to_string());
    metadata.insert("safe".to_string(), "ok".to_string());

    redact_sse_log_metadata(&mut metadata);

    assert!(!metadata.contains_key(LAST_EVENT_ID_METADATA_KEY));
    assert!(!metadata.contains_key("sse:wrap_non_sse"));
    assert!(!metadata.contains_key("sse:relabeled_non_sse"));
    assert_eq!(
        metadata.get("sse:leid_present").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        metadata.get("sse:leid_bytes").map(String::as_str),
        Some("20")
    );
    assert_eq!(metadata.get("safe").map(String::as_str), Some("ok"));

    let extras: Vec<String> = Vec::new();
    assert!(is_sensitive_metadata_key_with_extras(
        LAST_EVENT_ID_METADATA_KEY,
        &extras
    ));
    assert!(is_sensitive_metadata_key_with_extras(
        "SSE:Last_Event_ID",
        &extras
    ));

    // Defense in depth: if a sink still sees the raw key, serialization redacts it.
    let mut residual = HashMap::new();
    residual.insert(
        LAST_EVENT_ID_METADATA_KEY.to_string(),
        "still-sensitive".to_string(),
    );
    #[derive(Serialize)]
    struct Wrapper {
        #[serde(serialize_with = "serialize_redacted_metadata")]
        metadata: HashMap<String, String>,
    }
    let encoded = serde_json::to_value(Wrapper { metadata: residual }).unwrap();
    assert_eq!(
        encoded["metadata"][LAST_EVENT_ID_METADATA_KEY],
        REDACTED_PLACEHOLDER
    );
}

#[tokio::test]
async fn test_no_last_event_id_no_metadata() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    plugin.on_request_received(&mut ctx).await;
    assert!(!ctx.metadata.contains_key(LAST_EVENT_ID_METADATA_KEY));
}

// ── on_request_received: method checked before accept ─────────────────────────

#[tokio::test]
async fn test_post_without_accept_gets_405_not_406() {
    let plugin = make_plugin(json!({}));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/events".to_string(),
    );
    // No Accept header AND wrong method — method should be checked first.
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(&result, 405);
}

// ── before_proxy: Accept-Encoding stripping ───────────────────────────────────

#[tokio::test]
async fn test_strips_accept_encoding_by_default() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!headers.contains_key("accept-encoding"));
}

#[tokio::test]
async fn test_preserves_accept_encoding_when_disabled() {
    let plugin = make_plugin(json!({"strip_accept_encoding": false}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("accept-encoding").unwrap(), "gzip");
}

// ── before_proxy: Last-Event-ID forwarding ────────────────────────────────────

#[tokio::test]
async fn test_last_event_id_forwarded_to_backend() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.metadata
        .insert(LAST_EVENT_ID_METADATA_KEY.to_string(), "evt-99".to_string());
    let mut headers = HashMap::new();

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("last-event-id").unwrap(), "evt-99");
}

#[tokio::test]
async fn test_last_event_id_does_not_overwrite_existing_header() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.metadata.insert(
        LAST_EVENT_ID_METADATA_KEY.to_string(),
        "from-metadata".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("last-event-id".to_string(), "from-header".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    // Existing header takes precedence.
    assert_eq!(headers.get("last-event-id").unwrap(), "from-header");
}

// ── after_proxy: SSE response header decoration ───────────────────────────────

#[tokio::test]
async fn test_sse_response_gets_streaming_headers() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_continue(&result);

    assert_eq!(headers.get("cache-control").unwrap(), "no-cache");
    // Connection keep-alive is HTTP/1-only and forbidden on H2/H3 — never emit it.
    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("keep-alive"));
    assert_eq!(headers.get("x-accel-buffering").unwrap(), "no");
    assert!(!headers.contains_key("content-length"));
}

#[tokio::test]
async fn test_cache_control_merges_without_weakening_origin() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();
    headers.insert(
        "cache-control".to_string(),
        "private, no-store, no-cache, no-transform, ext=1".to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    let cc = headers.get("cache-control").unwrap();
    assert!(cc.contains("private"), "{cc}");
    assert!(cc.contains("no-store"), "{cc}");
    assert!(cc.contains("no-cache"), "{cc}");
    assert!(cc.contains("no-transform"), "{cc}");
    assert!(cc.contains("ext=1"), "{cc}");
}

#[tokio::test]
async fn test_cache_control_appends_no_cache_when_absent() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();
    headers.insert(
        "cache-control".to_string(),
        "private, no-store, no-transform".to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(
        headers.get("cache-control").unwrap(),
        "private, no-store, no-transform, no-cache"
    );
}

#[tokio::test]
async fn test_cache_control_merges_into_mixed_case_key_without_duplicate() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();
    headers.insert("Cache-Control".to_string(), "private, no-store".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(
        headers.get("Cache-Control").map(String::as_str),
        Some("private, no-store, no-cache")
    );
    assert_eq!(
        headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("cache-control"))
            .count(),
        1,
        "SSE cache policy must not create case-variant duplicates: {headers:?}"
    );
}

#[tokio::test]
async fn test_cache_control_preserves_quoted_and_malformed() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();
    // Quoted value contains the substring no-cache but must not count as the
    // directive; malformed trailing quote is preserved rather than replaced.
    headers.insert(
        "cache-control".to_string(),
        "private, community=\"no-cache,x\", weird=\"".to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    let cc = headers.get("cache-control").unwrap();
    assert!(
        cc.starts_with("private, community=\"no-cache,x\", weird=\""),
        "{cc}"
    );
    assert!(cc.ends_with("no-cache"), "{cc}");
    assert!(cc.contains("private"), "{cc}");
}

#[tokio::test]
async fn test_cache_control_quoted_even_backslash_does_not_hide_missing_directive() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();
    // The first quoted value ends with an escaped backslash (two raw
    // backslashes before its closing quote). A parser that only checks the
    // immediately preceding byte can lose quote state and mistake the
    // comma-delimited text inside the second quoted value for a directive.
    headers.insert(
        "cache-control".to_string(),
        r#"private, ext="slash\\", note="x,no-cache,y""#.to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    let cc = headers.get("cache-control").unwrap();
    assert!(cc.ends_with(", no-cache"), "{cc}");
    assert!(cc.starts_with("private, ext="), "{cc}");
}

#[tokio::test]
async fn test_h3_final_strip_removes_plugin_reintroduced_connection() {
    // Defense in depth: even if a plugin reintroduces hop-by-hop fields after
    // backend sanitation, the H3 final-field strip removes static and
    // Connection-nominated fields regardless of plugin-supplied casing.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();
    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    // Model a later generic response-header plugin reintroducing fields after
    // the SSE hook. The final H3 boundary must sanitize the resulting union.
    headers.insert(
        "ConNection".to_string(),
        "X-Plugin-Hop, Keep-Alive".to_string(),
    );
    headers.insert("Keep-Alive".to_string(), "timeout=5".to_string());
    headers.insert(
        "X-Plugin-Hop".to_string(),
        "secret-routing-state".to_string(),
    );
    headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
    headers.insert("x-accel-buffering".to_string(), "no".to_string());

    strip_client_response_hop_by_hop_headers(&mut headers);

    for stripped in [
        "connection",
        "keep-alive",
        "x-plugin-hop",
        "transfer-encoding",
    ] {
        assert!(
            !headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case(stripped)),
            "{stripped} survived final H3 sanitation: {headers:?}"
        );
    }
    assert_eq!(headers.get("x-accel-buffering").unwrap(), "no");
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");

    let response = apply_response_headers(hyper::Response::builder().status(200), &headers)
        .body(())
        .expect("sanitized H3 response headers must build");
    assert!(response.headers().get("connection").is_none());
    assert!(response.headers().get("keep-alive").is_none());
    assert!(response.headers().get("x-plugin-hop").is_none());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
}

#[tokio::test]
async fn test_non_sse_response_untouched_by_default() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(headers.get("content-length").unwrap(), "42");
    assert!(!headers.contains_key("cache-control"));
    assert!(!headers.contains_key("x-accel-buffering"));
}

#[tokio::test]
async fn test_detects_sse_with_charset() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(headers.get("cache-control").unwrap(), "no-cache");
}

#[tokio::test]
async fn test_detects_sse_case_insensitive() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "Text/Event-Stream".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(headers.get("cache-control").unwrap(), "no-cache");
}

#[tokio::test]
async fn test_sse_like_content_type_is_not_decorated() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "text/event-stream-like".to_string(),
    );
    headers.insert("content-length".to_string(), "42".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/event-stream-like"
    );
    assert_eq!(headers.get("content-length").unwrap(), "42");
    assert!(!headers.contains_key("cache-control"));
    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("x-accel-buffering"));
}

// ── after_proxy: configuration options ────────────────────────────────────────

#[tokio::test]
async fn test_no_buffering_header_disabled() {
    let plugin = make_plugin(json!({"add_no_buffering_header": false}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(!headers.contains_key("x-accel-buffering"));
    assert_eq!(headers.get("cache-control").unwrap(), "no-cache");
}

#[tokio::test]
async fn test_strip_content_length_disabled() {
    let plugin = make_plugin(json!({"strip_content_length": false}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(headers.contains_key("content-length"));
}

#[tokio::test]
async fn test_retry_ms_stored_in_metadata() {
    let plugin = make_plugin(json!({"retry_ms": 5000}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(ctx.metadata.get("sse:retry_ms").unwrap(), "5000");
}

#[tokio::test]
async fn test_retry_ms_not_set_without_config() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(!ctx.metadata.contains_key("sse:retry_ms"));
}

// ── after_proxy: force_sse_content_type ───────────────────────────────────────

#[test]
fn may_modify_response_content_type_reflects_force_sse_content_type() {
    let ctx = make_sse_ctx();

    let forcing = make_plugin(json!({"force_sse_content_type": true}));
    // A non-SSE backend type WILL be relabeled to text/event-stream in
    // after_proxy, so keep the body buffered for final-response inspection.
    assert!(forcing.may_modify_response_content_type(&ctx, Some("application/json")));
    // A missing backend Content-Type is also the relabel path (after_proxy
    // treats a missing/non-SSE type as "force it"), so keep buffering.
    assert!(forcing.may_modify_response_content_type(&ctx, None));
    // A genuine text/event-stream response is NOT relabeled by after_proxy, so
    // it must NOT be pinned to the buffered path — an unbounded stream would
    // otherwise be collected until the max-response-body 502. Allow the
    // SSE→stream downgrade (including with a charset parameter).
    assert!(!forcing.may_modify_response_content_type(&ctx, Some("text/event-stream")));
    assert!(
        !forcing.may_modify_response_content_type(&ctx, Some("text/event-stream; charset=utf-8"))
    );

    // Wrapping also relabels non-SSE responses to text/event-stream.
    let wrapping = make_plugin(json!({"wrap_non_sse_responses": true}));
    assert!(wrapping.may_modify_response_content_type(&ctx, Some("application/json")));
    assert!(!wrapping.may_modify_response_content_type(&ctx, Some("text/event-stream")));

    // Without forcing or wrapping, the plugin never changes the response
    // content-type (it only adds SSE responses' cache/streaming headers).
    let passive = make_plugin(json!({}));
    assert!(!passive.may_modify_response_content_type(&ctx, Some("application/json")));
    assert!(!passive.may_modify_response_content_type(&ctx, Some("text/event-stream")));
}

#[tokio::test]
async fn test_force_sse_content_type_on_json_response() {
    let plugin = make_plugin(json!({"force_sse_content_type": true}));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert_eq!(headers.get("cache-control").unwrap(), "no-cache");
    assert!(!headers.contains_key("connection"));
}

#[tokio::test]
async fn test_wrap_alone_relabels_content_type() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert_eq!(ctx.metadata.get("sse:wrap_non_sse").unwrap(), "1");
    assert!(!headers.contains_key("connection"));
}

#[tokio::test]
async fn test_wrap_and_force_compose_through_body_transform() {
    // Lifecycle: after_proxy relabels to text/event-stream, then
    // transform_response_body_with_context still wraps using the wrap flag.
    let plugin = make_plugin(json!({
        "wrap_non_sse_responses": true,
        "force_sse_content_type": true
    }));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");

    let body = br#"{"message":"hello"}"#;
    let transformed = plugin
        .transform_response_body_with_context(&mut ctx, body, Some("text/event-stream"), &headers)
        .await
        .expect("wrap+force must still frame the body");
    assert_eq!(
        String::from_utf8(transformed).unwrap(),
        "data: {\"message\":\"hello\"}\n\n"
    );
}

#[tokio::test]
async fn test_multiple_sse_instances_wrap_once_and_merge_cache_control_idempotently() {
    let first = make_plugin(json!({
        "wrap_non_sse_responses": true,
        "force_sse_content_type": true
    }));
    let second = make_plugin(json!({
        "wrap_non_sse_responses": true,
        "force_sse_content_type": true
    }));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();
    headers.insert("cache-control".to_string(), "private, no-store".to_string());

    first.after_proxy(&mut ctx, 200, &mut headers).await;
    second.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(
        headers.get("cache-control").map(String::as_str),
        Some("private, no-store, no-cache")
    );
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");

    let body = br#"{"message":"hello"}"#;
    let transformed = first
        .transform_response_body_with_context(&mut ctx, body, Some("text/event-stream"), &headers)
        .await
        .expect("the first wrapper must consume the original response decision");
    assert!(
        !ctx.metadata.contains_key("sse:wrap_non_sse"),
        "the shared wrap decision must be consumed exactly once"
    );

    let repeated = second
        .transform_response_body_with_context(
            &mut ctx,
            &transformed,
            Some("text/event-stream"),
            &headers,
        )
        .await;
    assert!(
        repeated.is_none(),
        "a later SSE instance must not double-wrap"
    );
    assert_eq!(
        String::from_utf8(transformed).unwrap(),
        "data: {\"message\":\"hello\"}\n\n"
    );
}

#[tokio::test]
async fn test_force_only_instance_before_wrapper_preserves_original_non_sse_provenance() {
    let forcing = make_plugin(json!({"force_sse_content_type": true}));
    let wrapping = make_plugin(json!({"wrap_non_sse_responses": true}));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();

    forcing.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    wrapping.after_proxy(&mut ctx, 200, &mut headers).await;

    let body = br#"{"message":"hello"}"#;
    assert!(
        forcing
            .transform_response_body_with_context(
                &mut ctx,
                body,
                Some("text/event-stream"),
                &headers,
            )
            .await
            .is_none()
    );
    let transformed = wrapping
        .transform_response_body_with_context(&mut ctx, body, Some("text/event-stream"), &headers)
        .await
        .expect("a later wrapper must honor the original non-SSE provenance");

    assert_eq!(
        String::from_utf8(transformed).unwrap(),
        "data: {\"message\":\"hello\"}\n\n"
    );
    assert!(!ctx.metadata.contains_key("sse:wrap_non_sse"));
    assert!(!ctx.metadata.contains_key("sse:relabeled_non_sse"));
}

#[tokio::test]
async fn test_genuine_sse_is_not_double_wrapped_after_lifecycle() {
    let plugin = make_plugin(json!({
        "wrap_non_sse_responses": true,
        "force_sse_content_type": true
    }));
    let mut ctx = make_sse_ctx();
    let mut headers = sse_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(!ctx.metadata.contains_key("sse:wrap_non_sse"));

    let body = b"data: already sse\n\n";
    let result = plugin
        .transform_response_body_with_context(&mut ctx, body, Some("text/event-stream"), &headers)
        .await;
    assert!(result.is_none(), "genuine SSE must not be double-wrapped");
}

#[tokio::test]
async fn test_preserved_non_sse_response_is_not_relabelled_without_body_wrap() {
    let plugin = make_plugin(json!({
        "force_sse_content_type": true,
        "wrap_non_sse_responses": true
    }));

    for status in [206, 226] {
        let mut ctx = make_sse_ctx();
        let mut headers = json_response_headers();
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            status,
            &headers
        ));
        assert!(
            plugin.should_release_response_body_before_content_type_rewrite(&ctx, status, &headers)
        );
        plugin.after_proxy(&mut ctx, status, &mut headers).await;

        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some("42")
        );
        assert!(!headers.contains_key("cache-control"));
        assert!(!headers.contains_key("connection"));
    }
}

#[tokio::test]
async fn test_force_does_not_overwrite_existing_sse() {
    let plugin = make_plugin(json!({"force_sse_content_type": true}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    // Should keep the original (with charset), not overwrite.
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/event-stream; charset=utf-8"
    );
}

// ── transform_response_body: SSE wrapping ─────────────────────────────────────

#[tokio::test]
async fn test_wrap_json_body_as_sse_event() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let body = br#"{"message":"hello"}"#;
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("application/json"), &headers)
        .await;

    let transformed = result.expect("should wrap body");
    let output = String::from_utf8(transformed).unwrap();
    assert_eq!(output, "data: {\"message\":\"hello\"}\n\n");
}

#[tokio::test]
async fn test_wrap_multiline_body_as_sse_event() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let body = b"line one\nline two\nline three";
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("text/plain"), &headers)
        .await;

    let transformed = result.expect("should wrap body");
    let output = String::from_utf8(transformed).unwrap();
    assert_eq!(
        output,
        "data: line one\ndata: line two\ndata: line three\n\n"
    );
}

#[tokio::test]
async fn test_wrap_includes_retry_field() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true, "retry_ms": 3000}));
    let body = b"hello";
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("text/plain"), &headers)
        .await;

    let transformed = result.expect("should wrap body");
    let output = String::from_utf8(transformed).unwrap();
    assert_eq!(output, "retry: 3000\ndata: hello\n\n");
}

#[tokio::test]
async fn test_does_not_wrap_already_sse_body() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let body = b"data: already sse\n\n";
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("text/event-stream"), &headers)
        .await;

    assert!(result.is_none(), "should not double-wrap SSE body");
}

#[tokio::test]
async fn test_wraps_sse_like_content_type_body() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let body = b"not an sse stream";
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("text/event-stream-like"), &headers)
        .await;

    let transformed = result.expect("sse-like content type should not suppress wrapping");
    assert_eq!(
        String::from_utf8(transformed).unwrap(),
        "data: not an sse stream\n\n"
    );
}

#[tokio::test]
async fn test_does_not_wrap_when_disabled() {
    let plugin = make_plugin(json!({}));
    let body = br#"{"message":"hello"}"#;
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("application/json"), &headers)
        .await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_does_not_wrap_empty_body() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(b"", Some("application/json"), &headers)
        .await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_wrap_lone_cr_does_not_inject_sse_fields() {
    // Security regression for finding #20 (SSE event/field injection): a lone
    // CR (`\r`) in an untrusted upstream body must NOT survive into the wrapped
    // output, where the client EventSource parser would re-split on it and let
    // the upstream inject extra `data:`/`event:`/`id:`/`retry:` fields and a
    // forged event boundary (blank line from `\r\r`).
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    // `\r\r` would forge an event boundary; embedded field names would be
    // parsed as real fields if the CR reached the wire.
    let body = b"foo\rdata: injected\r\rid: spoofed";
    let headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, Some("application/json"), &headers)
        .await;

    let transformed = result.expect("should wrap body");
    let output = String::from_utf8(transformed).unwrap();

    // No bare CR may reach the wire — that is the injection vector.
    assert!(
        !output.contains('\r'),
        "wrapped output must not contain a bare CR: {output:?}"
    );

    // Every upstream logical line (split on CR/LF/CRLF) becomes exactly one
    // escaped `data:` field, so the injected `data:`/`id:` text is inert
    // content, not new SSE fields, and `\r\r` yields an empty `data:` line
    // (which does NOT terminate the event) rather than a blank-line boundary.
    assert_eq!(
        output,
        "data: foo\ndata: data: injected\ndata: \ndata: id: spoofed\n\n"
    );

    // The only event-terminating blank line is the trailing one this code
    // appends; the upstream `\r\r` must not have introduced an earlier one.
    let body_section = output
        .strip_suffix("\n\n")
        .expect("event must end with a blank line");
    assert!(
        !body_section.contains("\n\n"),
        "upstream content must not forge an interior event boundary: {output:?}"
    );
}

#[tokio::test]
async fn test_wrap_crlf_and_lf_produce_identical_framing() {
    // CRLF and lone-CR normalization must not regress the existing LF/CRLF
    // framing: one `data:` field per line, no spurious empty lines, no bare CR.
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let headers = HashMap::new();

    let crlf = plugin
        .transform_response_body(b"a\r\nb\r\nc", Some("text/plain"), &headers)
        .await
        .expect("should wrap body");
    let lf = plugin
        .transform_response_body(b"a\nb\nc", Some("text/plain"), &headers)
        .await
        .expect("should wrap body");

    assert_eq!(crlf, lf, "CRLF and LF bodies must frame identically");
    let output = String::from_utf8(lf).unwrap();
    assert_eq!(output, "data: a\ndata: b\ndata: c\n\n");
    assert!(!output.contains('\r'));
}

#[tokio::test]
async fn test_wrap_preserves_terminal_line_breaks() {
    // EventSource appends LF per data field then strips one trailing LF.
    // Preserving a payload that ends in a newline requires an empty final
    // `data:` field. Assert decoded MessageEvent.data, not only wire bytes.
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let headers = HashMap::new();

    let cases: &[(&[u8], &str)] = &[
        (b"alpha", "alpha"),
        (b"alpha\n", "alpha\n"),
        (b"alpha\r", "alpha\n"),
        (b"alpha\r\n", "alpha\n"),
        (b"alpha\n\n", "alpha\n\n"),
        (b"alpha\nbeta\n", "alpha\nbeta\n"),
        (b"\n", "\n"),
        (b"line\n\nmiddle", "line\n\nmiddle"),
    ];

    for (body, expected_data) in cases {
        let framed = plugin
            .transform_response_body(body, Some("text/plain"), &headers)
            .await
            .unwrap_or_else(|| panic!("should wrap {:?}", std::str::from_utf8(body)));
        let wire = String::from_utf8(framed).unwrap();
        assert!(
            !wire.contains('\r'),
            "no bare CR for {:?}: {wire:?}",
            std::str::from_utf8(body)
        );
        assert_eq!(
            decode_eventsource_data(&wire),
            *expected_data,
            "wire={wire:?} body={:?}",
            std::str::from_utf8(body)
        );
    }
}

/// Minimal WHATWG EventSource data-buffer decode for a single event.
fn decode_eventsource_data(wire: &str) -> String {
    let mut data = String::new();
    for line in wire.lines() {
        if let Some(value) = line.strip_prefix("data:") {
            let value = value.strip_prefix(' ').unwrap_or(value);
            data.push_str(value);
            data.push('\n');
        } else if line.is_empty() {
            break;
        }
    }
    if data.ends_with('\n') {
        data.pop();
    }
    data
}

// ── Full lifecycle: on_request_received → before_proxy → after_proxy ──────────

#[tokio::test]
async fn test_full_sse_lifecycle() {
    let plugin = make_plugin(json!({"retry_ms": 2000}));
    let mut ctx = make_sse_ctx();
    ctx.headers
        .insert("last-event-id".to_string(), "42".to_string());
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip, br".to_string());

    // Phase 1: validate request.
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
    assert_eq!(ctx.metadata.get(LAST_EVENT_ID_METADATA_KEY).unwrap(), "42");

    // Phase 2: shape request for backend.
    let mut backend_headers = HashMap::new();
    backend_headers.insert("accept".to_string(), "text/event-stream".to_string());
    backend_headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut backend_headers).await;
    assert_continue(&result);
    assert!(!backend_headers.contains_key("accept-encoding"));
    assert_eq!(backend_headers.get("last-event-id").unwrap(), "42");

    // Phase 3: decorate response.
    let mut response_headers = sse_response_headers();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_continue(&result);
    assert_eq!(response_headers.get("cache-control").unwrap(), "no-cache");
    assert!(!response_headers.contains_key("connection"));
    assert_eq!(response_headers.get("x-accel-buffering").unwrap(), "no");
    assert!(!response_headers.contains_key("content-length"));
    assert_eq!(ctx.metadata.get("sse:retry_ms").unwrap(), "2000");
}

// ── Edge cases ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_no_content_type_in_response_skips_decoration() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(!headers.contains_key("cache-control"));
}

#[tokio::test]
async fn test_all_validation_disabled() {
    let plugin = make_plugin(json!({
        "require_get_method": false,
        "require_accept_header": false,
        "strip_accept_encoding": false,
    }));
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/events".to_string(),
    );
    // No Accept header, DELETE method — should still pass with all validation disabled.
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(&result);
}

#[tokio::test]
async fn test_empty_config_defaults() {
    let plugin = make_plugin(json!({}));
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(plugin.modifies_request_headers());
}

// ---------------------------------------------------------------------------
// Incremental SSE event framing (GHSA-pwcm-6rh8-f2gh).
//
// The wrapped event used to be framed from two WHOLE-BODY `String` copies — a
// lossy UTF-8 decode and a CR/CRLF normalization — before the ceiling-bounded
// sink saw a byte, so a full attacker-chosen replacement was resident outside
// the reserved window. It is now written incrementally over the input; these
// tests pin the observable framing that rewrite must preserve.
// ---------------------------------------------------------------------------

async fn wrap_body_once(config: serde_json::Value, body: &[u8]) -> Option<Vec<u8>> {
    let plugin = make_plugin(config);
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();
    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    plugin
        .transform_response_body_with_context(&mut ctx, body, Some("text/event-stream"), &headers)
        .await
}

#[tokio::test]
async fn test_wrap_preserves_crlf_and_lone_cr_normalization() {
    let config = json!({"wrap_non_sse_responses": true});
    for (body, expected) in [
        (&b"plain"[..], "data: plain\n\n"),
        (&b"a\r\nb"[..], "data: a\ndata: b\n\n"),
        (&b"a\rb"[..], "data: a\ndata: b\n\n"),
        (&b"a\r\r\nb"[..], "data: a\ndata: \ndata: b\n\n"),
        (&b"a\n\nb"[..], "data: a\ndata: \ndata: b\n\n"),
        // A payload that itself ends in LF needs the empty final `data:` field
        // the WHATWG dispatch algorithm's trailing-LF removal consumes.
        (&b"a\n"[..], "data: a\ndata: \n\n"),
        (&b"a\r\n"[..], "data: a\ndata: \n\n"),
        (&b"\n"[..], "data: \ndata: \n\n"),
    ] {
        let wrapped = wrap_body_once(config.clone(), body)
            .await
            .expect("wrapping must frame the body");
        assert_eq!(
            String::from_utf8(wrapped).expect("framed event is UTF-8"),
            expected,
            "framing changed for body {body:?}"
        );
        assert!(
            !expected.contains('\r'),
            "no bare CR may reach the wire: it would reintroduce a field \
             injection boundary"
        );
    }
}

#[tokio::test]
async fn test_wrap_decodes_invalid_utf8_exactly_like_from_utf8_lossy() {
    // Asserted against the reference implementation itself, so the incremental
    // decoder cannot drift from `String::from_utf8_lossy` substitution.
    for raw in [
        &b"a\xffb"[..],
        &b"\xf0\x9f"[..],
        &b"\xe2\x82"[..],
        &b"lead\xc3(trail"[..],
    ] {
        let wrapped = wrap_body_once(json!({"wrap_non_sse_responses": true}), raw)
            .await
            .expect("wrapping must frame the body");
        let expected = format!("data: {}\n\n", String::from_utf8_lossy(raw));
        assert_eq!(
            String::from_utf8(wrapped).expect("framed event is UTF-8"),
            expected,
            "lossy decoding drifted for {raw:?}"
        );
    }
}

#[tokio::test]
async fn test_wrap_keeps_the_retry_field_ahead_of_the_data_fields() {
    let wrapped = wrap_body_once(
        json!({"wrap_non_sse_responses": true, "retry_ms": 2500}),
        b"hi\nthere",
    )
    .await
    .expect("wrapping must frame the body");
    assert_eq!(
        String::from_utf8(wrapped).expect("framed event is UTF-8"),
        "retry: 2500\ndata: hi\ndata: there\n\n"
    );
}

#[tokio::test]
async fn test_wrap_is_refused_while_it_is_written_when_it_exceeds_the_ceiling() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let mut ctx = make_sse_ctx();
    // A tiny route-effective ceiling: the framed event cannot fit, and the
    // refusal must happen during construction rather than after a larger buffer
    // exists (GHSA-pwcm-6rh8-f2gh).
    ctx.max_response_body_size_bytes = 4;
    let mut headers = json_response_headers();
    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    let wrapped = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"a body that cannot fit in four bytes of framing",
            Some("text/event-stream"),
            &headers,
        )
        .await;
    assert!(
        wrapped.is_none(),
        "an over-ceiling framed event must be refused rather than allocated"
    );
    assert!(
        take_buffered_response_capacity_refusal_pending_for_test(&mut ctx),
        "the refusal is a CLAIMED rewrite that failed, so it must mark the shared \
         pending capacity signal instead of publishing the unconverted body"
    );
}

// ── #5103 — SseConfig.retry_ms schema/runtime admission parity ────────────────

/// `SseConfig.retry_ms` is published as JSON Schema `type: integer`, which
/// draft 2020-12 defines over the VALUE: `1.0` is an integer there exactly as
/// `1` is, and no keyword can express the lexical difference. Admission here
/// therefore accepts an exact integer-valued number, so a document that
/// validates against the published schema also passes `ferrum-edge validate`.
#[test]
fn test_retry_ms_accepts_exact_integer_valued_numbers() {
    for config in [
        json!({"retry_ms": 1.0}),
        json!({"retry_ms": 2500.0}),
        json!({"retry_ms": 1}),
        json!({"retry_ms": u64::MAX}),
    ] {
        let admitted = SsePlugin::new(&config);
        assert!(admitted.is_ok(), "must admit {config}");
    }
}

#[tokio::test]
async fn test_integer_valued_retry_ms_frames_the_same_retry_field() {
    let config = json!({"wrap_non_sse_responses": true, "retry_ms": 2500.0});
    let wrapped = wrap_body_once(config, b"hi").await.expect("wrapped");
    let framed = String::from_utf8(wrapped).expect("framed event is UTF-8");
    assert_eq!(framed, "retry: 2500\ndata: hi\n\n");
}

/// The other half of the parity: everything the schema's `type` / `minimum` /
/// `maximum` triple rejects is rejected here too. `18446744073709551616` is the
/// case the missing `maximum` used to let the schema admit while the
/// constructor refused it.
#[test]
fn test_retry_ms_rejects_values_outside_the_published_schema_range() {
    for (config, expected) in [
        (json!({"retry_ms": 1.5}), "must be an unsigned integer"),
        (json!({"retry_ms": -1}), "must be an unsigned integer"),
        (json!({"retry_ms": -1.0}), "must be an unsigned integer"),
        (json!({"retry_ms": 0.0}), "must be greater than zero"),
    ] {
        let err = SsePlugin::new(&config).err().unwrap_or_default();
        assert!(err.contains(expected), "for {config}: {err}");
    }

    let over_u64_text = r#"{"retry_ms": 18446744073709551616}"#;
    let over_u64: serde_json::Value =
        serde_json::from_str(over_u64_text).expect("over-u64 literals parse");
    let err = SsePlugin::new(&over_u64).err().unwrap_or_default();
    assert!(err.contains("must be an unsigned integer"), "{err}");
}

// ── #5100 / #5101 / #5102 — representations wrapping declines ─────────────────

/// A backend response header map plus the pristine stamp every dispatch path
/// records before running `after_proxy`.
fn stamped_origin(content_type: &str) -> (RequestContext, HashMap<String, String>) {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), content_type.to_string());
    let mut ctx = make_sse_ctx();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    (ctx, headers)
}

/// Same, with one extra origin header recorded in the stamp.
fn stamped_origin_with(
    content_type: &str,
    name: &str,
    value: &str,
) -> (RequestContext, HashMap<String, String>) {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), content_type.to_string());
    headers.insert(name.to_string(), value.to_string());
    let mut ctx = make_sse_ctx();
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);
    (ctx, headers)
}

fn content_type_of(headers: &HashMap<String, String>) -> Option<&str> {
    headers.get("content-type").map(String::as_str)
}

/// Drive the wrapping transform exactly as the buffered response-body phase
/// does, over the response headers the client would see.
async fn wrap_now(
    plugin: &SsePlugin,
    ctx: &mut RequestContext,
    body: &[u8],
    content_type: &str,
    headers: &HashMap<String, String>,
) -> Option<Vec<u8>> {
    let content_type = Some(content_type);
    plugin
        .transform_response_body_with_context(ctx, body, content_type, headers)
        .await
}

/// RFC 9110 §7.7: an origin `Cache-Control: no-transform` forbids an
/// intermediary from converting the content. Wrapping used to reframe the body
/// and relabel the media type while faithfully preserving the very directive
/// that forbade both.
#[tokio::test]
async fn test_origin_no_transform_blocks_wrapping_and_relabeling() {
    let config = json!({"wrap_non_sse_responses": true, "retry_ms": 2500});
    let plugin = make_plugin(config);
    for directive in ["no-transform", "NO-TRANSFORM", "private, no-transform"] {
        let stamped = stamped_origin_with("text/plain", "cache-control", directive);
        let (mut ctx, mut headers) = stamped;

        let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
        assert_continue(&result);
        let label = content_type_of(&headers);
        assert_eq!(label, Some("text/plain"), "kept for {directive}");
        let cache_control = headers.get("cache-control").map(String::as_str);
        assert_eq!(cache_control, Some(directive), "verbatim {directive}");

        let wrapped = wrap_now(&plugin, &mut ctx, b"hello", "text/plain", &headers).await;
        assert!(wrapped.is_none(), "must not reframe: {directive}");
    }
}

/// `force_sse_content_type` is blocked by the same directive: RFC 9110 §7.7
/// names `Content-Type` among the fields a no-transform response forbids
/// changing.
#[tokio::test]
async fn test_origin_no_transform_also_blocks_content_type_forcing() {
    let plugin = make_plugin(json!({"force_sse_content_type": true}));
    let stamped = stamped_origin_with("application/json", "cache-control", "no-transform");
    let (mut ctx, mut headers) = stamped;

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_continue(&result);
    assert_eq!(content_type_of(&headers), Some("application/json"));
}

/// A later header rule cannot unlock wrapping by deleting the directive: the
/// decision reads the pristine pre-`after_proxy` snapshot.
#[tokio::test]
async fn test_erasing_the_origin_no_transform_directive_does_not_unlock_wrapping() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let stamped = stamped_origin_with("text/plain", "cache-control", "no-transform");
    let (mut ctx, mut headers) = stamped;
    headers.remove("cache-control");

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_continue(&result);
    assert_eq!(content_type_of(&headers), Some("text/plain"));

    let wrapped = wrap_now(&plugin, &mut ctx, b"hello", "text/plain", &headers).await;
    assert!(wrapped.is_none(), "the pristine directive still forbids it");
}

/// `no-transform` inside a quoted extension value is not the directive. The
/// shared Cache-Control parser skips quoted-string interiors, so an ordinary
/// response carrying one is still wrapped.
#[tokio::test]
async fn test_quoted_no_transform_extension_is_not_the_directive() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let quoted = r#"ext="no-transform""#;
    let stamped = stamped_origin_with("text/plain", "cache-control", quoted);
    let (mut ctx, mut headers) = stamped;

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_continue(&result);
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));

    let sse = "text/event-stream";
    let wrapped = wrap_now(&plugin, &mut ctx, b"hello", sse, &headers).await;
    let framed = wrapped.expect("an ordinary response is still wrapped");
    assert_eq!(String::from_utf8(framed).unwrap(), "data: hello\n\n");
}

/// A content-coded origin body is a compressed bitstream, not the UTF-8 text
/// `data:` framing describes. Wrapping it produced a body that was neither
/// valid gzip nor the intended event, still labelled `Content-Encoding: gzip`.
#[tokio::test]
async fn test_content_coded_origin_body_is_not_framed_as_text() {
    let config = json!({
        "wrap_non_sse_responses": true,
        "force_sse_content_type": true
    });
    let plugin = make_plugin(config);
    // Deliberately not UTF-8: framing these would emit lossy replacement
    // characters in place of the compressed octets.
    let coded: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x00, 0x03];
    for coding in ["gzip", "br", "gzip, br"] {
        let stamped = stamped_origin_with("text/plain", "content-encoding", coding);
        let (mut ctx, mut headers) = stamped;

        let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
        assert_continue(&result);
        let label = content_type_of(&headers);
        assert_eq!(label, Some("text/plain"), "not relabelled: {coding}");

        let wrapped = wrap_now(&plugin, &mut ctx, coded, "text/plain", &headers).await;
        assert!(wrapped.is_none(), "coded octets are not text: {coding}");
    }
}

/// `identity` is not a transforming coding, so it changes nothing.
#[tokio::test]
async fn test_identity_content_encoding_still_wraps() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let stamped = stamped_origin_with("text/plain", "content-encoding", "identity");
    let (mut ctx, mut headers) = stamped;

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_continue(&result);
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));

    let sse = "text/event-stream";
    let wrapped = wrap_now(&plugin, &mut ctx, b"hello", sse, &headers).await;
    let framed = wrapped.expect("identity bytes are what the wrapper frames");
    assert_eq!(String::from_utf8(framed).unwrap(), "data: hello\n\n");
}

/// A refused representation is also released from the buffered path: nothing
/// this instance does with the body can run, so pinning it there only costs the
/// retained-response budget.
#[test]
fn test_refused_representations_are_released_from_the_buffered_path() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let no_transform = stamped_origin_with("text/plain", "cache-control", "no-transform");
    let coded = stamped_origin_with("text/plain", "content-encoding", "gzip");
    for (ctx, headers) in [no_transform, coded] {
        let plain = Some("text/plain");
        let buffers =
            plugin.should_buffer_response_body_for_content_type(&ctx, plain, 200, &headers);
        assert!(!buffers, "a refused representation must not be buffered");
        let released =
            plugin.should_release_response_body_before_content_type_rewrite(&ctx, 200, &headers);
        assert!(released, "it must release before the relabel guard");
    }
}

/// A framed event that cannot fit this response's retained ceiling is a CLAIMED
/// rewrite that failed, not a no-op: `after_proxy` already published
/// `text/event-stream`, so publishing the unconverted body would serve plain
/// text as a successful event stream. The shared pending capacity signal is
/// what hands the response to the gateway terminal instead.
#[tokio::test]
async fn test_over_ceiling_framing_selects_the_shared_capacity_terminal() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true}));
    let mut ctx = make_sse_ctx();
    ctx.max_response_body_size_bytes = 8;
    let mut headers = json_response_headers();
    // The original body fits the ceiling; only its framing does not. That is
    // the real-wire case an "original already over the limit" fixture misses.
    let original: &[u8] = b"abcd";
    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));

    let sse = "text/event-stream";
    let wrapped = wrap_now(&plugin, &mut ctx, original, sse, &headers).await;
    assert!(wrapped.is_none(), "an over-ceiling event is refused");

    let mut status = 200u16;
    let mut body = Bytes::from_static(b"abcd");
    let installed = install_pending_buffered_response_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );
    assert!(installed, "the refusal must mark the pending signal");
    assert_ne!(status, 200, "the refused response is not successful");
    assert_ne!(&body[..], original, "raw bytes are not published");
    assert_ne!(content_type_of(&headers), Some("text/event-stream"));
}

// ── #5097 / #5098 — streaming decisions for wrapped and genuine event streams ─

fn refinement_streams(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
    with_retries: bool,
) -> bool {
    let proxy = create_test_proxy();
    let decision_ctx = if with_retries {
        retry_response_decision_context_for_test(ctx)
    } else {
        ctx.clone()
    };
    refine_stream_response_for_content_type_for_test(&proxy, plugins, &decision_ctx, 200, headers)
}

/// A configured wrapper never frames a genuine backend event stream, so it must
/// open the retry-time release gate and then release that representation.
/// Without the opt-in, `wrap_non_sse_responses` plus `retry` collected an
/// unbounded origin stream to EOF before the client saw its first event.
#[test]
fn test_genuine_event_streams_release_under_retries() {
    let config = json!({"wrap_non_sse_responses": true});
    let plugin: Arc<SsePlugin> = Arc::new(make_plugin(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];

    let (sse_ctx, sse_headers) = stamped_origin("text/event-stream");
    assert!(plugin.may_release_response_body_under_retries(&sse_ctx));
    let released = plugin.should_release_response_body_under_retries(&sse_ctx, 200, &sse_headers);
    assert!(released, "a genuine event stream is never framed");
    assert!(
        refinement_streams(&plugins, &sse_ctx, &sse_headers, true),
        "a genuine event stream must stream even with retries configured"
    );

    let (json_ctx, json_headers) = stamped_origin("application/json");
    let held = plugin.should_release_response_body_under_retries(&json_ctx, 200, &json_headers);
    assert!(!held, "a response this wrapper frames keeps its body");
    assert!(
        !refinement_streams(&plugins, &json_ctx, &json_headers, true),
        "a response this wrapper will frame stays buffered under retries"
    );
}

/// A plugin that is not wrapping has no body need at all, so it neither opens
/// the retry gate nor votes.
#[test]
fn test_a_non_wrapping_instance_does_not_open_the_retry_gate() {
    let plugin = make_plugin(json!({}));
    let (ctx, headers) = stamped_origin("text/event-stream");
    assert!(!plugin.may_release_response_body_under_retries(&ctx));
    let released = plugin.should_release_response_body_under_retries(&ctx, 200, &headers);
    assert!(!released);
}

/// The ordering invariant every dispatch path has to honor: the buffer/stream
/// refinement is only correct over the PRISTINE backend headers. Asked about
/// the map `after_proxy` has already relabelled, this same chain answers
/// "stream" — nothing left to wrap in a response that is already
/// `text/event-stream` — and the body goes out unframed under the very label
/// the wrap was supposed to fill. That was the H3 bridge's ordering bug.
#[tokio::test]
async fn test_the_refinement_answer_depends_on_pristine_backend_headers() {
    let config = json!({"wrap_non_sse_responses": true});
    let plugin: Arc<SsePlugin> = Arc::new(make_plugin(config));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let (mut ctx, mut headers) = stamped_origin("text/plain");
    let pristine = headers.clone();

    assert!(
        !refinement_streams(&plugins, &ctx, &pristine, false),
        "over the backend's own headers the wrapper must keep the body"
    );

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));
    assert!(
        refinement_streams(&plugins, &ctx, &headers, false),
        "the relabelled map releases the body — which is exactly why every \
         dispatch path must refine before `after_proxy` runs"
    );
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [
        (
            json!({"require_get_method": "'UNREGISTERED_TRAFFIC_TOKEN"}),
            "`require_get_method`",
            "must be a boolean",
        ),
        (
            json!({"retry_ms": -918273641}),
            "`retry_ms`",
            "must be an unsigned integer",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("sse", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// ── Plugin review fixes: admission fence, synthetic wrap, force consistency ───

/// sse-SOL-2: the GET-only and Accept checks are route admission policy. The
/// client selects the native-gRPC or WebSocket view by its own headers and
/// those views omit this HTTP-only instance, so the instance must declare the
/// bit the gateway's flavor fence refuses on.
#[test]
fn test_request_checks_gate_route_admission() {
    for config in [
        json!({}),
        json!({"require_get_method": true, "require_accept_header": false}),
        json!({"require_get_method": false, "require_accept_header": true}),
    ] {
        let plugin = make_plugin(config.clone());
        assert!(plugin.gates_request_admission(), "{config}");
    }
    let permissive = make_plugin(json!({
        "require_get_method": false,
        "require_accept_header": false
    }));
    assert!(
        !permissive.gates_request_admission(),
        "an instance that refuses nothing is not admission policy"
    );
}

/// sse-SOL-1: without `after_proxy`'s decision nothing published the
/// `text/event-stream` label, so the context-aware transform must not frame
/// the body under the producer's own media type.
#[tokio::test]
async fn test_context_transform_does_not_wrap_without_after_proxy_decision() {
    let plugin = make_plugin(json!({"wrap_non_sse_responses": true, "retry_ms": 2500}));
    let mut ctx = make_sse_ctx();
    let headers = json_response_headers();
    let body = br#"{"message":"hello"}"#;

    let wrapped = plugin
        .transform_response_body_with_context(&mut ctx, body, Some("application/json"), &headers)
        .await;
    assert!(
        wrapped.is_none(),
        "no header phase selected wrapping, so the body must stay unframed"
    );
}

/// sse-SOL-1: a synthetic 200 (a `response_mock` reply, a serverless terminate
/// reply) runs body transforms through the shared finalizer but skips this
/// plugin's `after_proxy`. The client must never receive SSE-framed bytes
/// under the producer's `application/json` label, with one wrapper or two.
#[tokio::test]
async fn test_synthetic_response_is_not_framed_under_its_own_media_type() {
    let config = json!({"wrap_non_sse_responses": true, "retry_ms": 2500});
    let one: Vec<Arc<dyn Plugin>> = vec![Arc::new(make_plugin(config.clone()))];
    let two: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(config.clone())),
        Arc::new(make_plugin(config)),
    ];
    for plugins in [one, two] {
        let original: &[u8] = br#"{"message":"hello"}"#;
        let mut ctx = make_sse_ctx();
        let mut status = 200u16;
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), original.len().to_string()),
        ]);
        let mut body = Bytes::from_static(br#"{"message":"hello"}"#);

        finalize_synthetic_response_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
        )
        .await;

        assert_eq!(status, 200, "instances={}", plugins.len());
        assert_eq!(
            content_type_of(&headers),
            Some("application/json"),
            "instances={}",
            plugins.len()
        );
        assert_eq!(&body[..], original, "instances={}", plugins.len());
    }
}

/// sse-claude-2: forcing declines the same partial-content and content-coded
/// representations whether or not wrapping is configured, so toggling the
/// wrapper never changes what forcing does.
#[tokio::test]
async fn test_force_only_does_not_relabel_partial_content() {
    for config in [
        json!({"force_sse_content_type": true}),
        json!({"force_sse_content_type": true, "wrap_non_sse_responses": true}),
    ] {
        let plugin = make_plugin(config.clone());
        for status in [206, 226] {
            let mut ctx = make_sse_ctx();
            let mut headers = json_response_headers();
            headers.insert("content-range".to_string(), "bytes 0-41/100".to_string());

            let result = plugin.after_proxy(&mut ctx, status, &mut headers).await;
            assert_continue(&result);
            assert_eq!(
                content_type_of(&headers),
                Some("application/json"),
                "{config} status={status}"
            );
            assert_eq!(
                headers.get("content-length").map(String::as_str),
                Some("42"),
                "{config} status={status}"
            );
            assert!(!headers.contains_key("cache-control"), "{config} {status}");
            assert!(!ctx.metadata.contains_key("sse:relabeled_non_sse"));
        }
    }
}

#[tokio::test]
async fn test_force_only_does_not_relabel_content_coded_body() {
    for config in [
        json!({"force_sse_content_type": true}),
        json!({"force_sse_content_type": true, "wrap_non_sse_responses": true}),
    ] {
        let plugin = make_plugin(config.clone());
        for coding in ["gzip", "br"] {
            let (mut ctx, mut headers) =
                stamped_origin_with("application/json", "content-encoding", coding);

            let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
            assert_continue(&result);
            assert_eq!(
                content_type_of(&headers),
                Some("application/json"),
                "{config} coding={coding}"
            );
            assert!(!ctx.metadata.contains_key("sse:relabeled_non_sse"));
        }
    }
}

/// Forcing a complete identity-coded 200 is unchanged by the decline above.
#[tokio::test]
async fn test_force_only_still_relabels_identity_coded_full_response() {
    let plugin = make_plugin(json!({"force_sse_content_type": true}));
    let (mut ctx, mut headers) =
        stamped_origin_with("application/json", "content-encoding", "identity");

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert_continue(&result);
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));
}

/// sse-claude-3: only the `Last-Event-ID` request header is honored. A cursor
/// a polyfill sends as a query parameter stays in the query string and is not
/// promoted to a backend header.
#[tokio::test]
async fn test_query_parameter_cursor_is_not_promoted_to_header() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.query_params
        .insert("lastEventId".to_string(), "42".to_string());
    ctx.query_params
        .insert("last-event-id".to_string(), "42".to_string());

    assert_continue(&plugin.on_request_received(&mut ctx).await);
    assert!(!ctx.metadata.contains_key(LAST_EVENT_ID_METADATA_KEY));

    let mut headers = HashMap::new();
    assert_continue(&plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!headers.contains_key("last-event-id"));
}

// ── Fix round 1: stale wrap decisions and genuine-stream retry ────────────────

const GUARD_REJECTION_BODY: &[u8] = br#"{"error":"response rejected by policy"}"#;

/// Run the normal header phase over a complete JSON 200, then replace the
/// response with a gateway JSON rejection exactly as an `on_response_body`
/// rejection does. Returns the rejection the client would receive.
async fn wrap_selected_then_rejected(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
) -> (u16, Bytes, HashMap<String, String>) {
    let mut headers = json_response_headers();
    stamp_original_response_metadata_for_test(ctx, 200, &headers);
    for plugin in plugins {
        assert_continue(&plugin.after_proxy(ctx, 200, &mut headers).await);
    }
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));
    assert_eq!(
        ctx.metadata.get("sse:wrap_non_sse").map(String::as_str),
        Some("1")
    );

    let (status, body, headers) = finalize_plugin_rejection_parts_for_test(
        plugins,
        ctx,
        502,
        Bytes::from_static(GUARD_REJECTION_BODY),
        HashMap::new(),
    )
    .await;
    assert_eq!(content_type_of(&headers), Some("application/json"));
    (status, body, headers)
}

/// PR6831-SOL-1: a wrap decision belongs to the response `after_proxy` saw.
/// Once gateway policy replaced that response, the transform must not frame
/// the replacement's JSON error.
#[tokio::test]
async fn test_wrap_decision_is_dropped_when_the_response_is_replaced() {
    let plugin: Arc<dyn Plugin> = Arc::new(make_plugin(json!({"wrap_non_sse_responses": true})));
    let plugins = vec![Arc::clone(&plugin)];
    let mut ctx = make_sse_ctx();
    let (_, body, headers) = wrap_selected_then_rejected(&plugins, &mut ctx).await;

    let wrapped = plugin
        .transform_response_body_with_context(&mut ctx, &body, Some("application/json"), &headers)
        .await;
    assert!(wrapped.is_none(), "the replacement must not be framed");
    assert!(
        !ctx.metadata.contains_key("sse:wrap_non_sse"),
        "the stale decision is consumed so no later instance can use it"
    );
}

/// PR6831-SOL-1 through the shared buffered transform phase, with one and two
/// wrapping instances: the client receives the rejection as valid JSON.
#[tokio::test]
async fn test_replaced_response_stays_valid_json_through_the_transform_phase() {
    let config = json!({"wrap_non_sse_responses": true, "retry_ms": 2500});
    for instances in [1usize, 2] {
        let plugins: Vec<Arc<dyn Plugin>> = (0..instances)
            .map(|_| Arc::new(make_plugin(config.clone())) as Arc<dyn Plugin>)
            .collect();
        let mut ctx = make_sse_ctx();
        let (mut status, mut body, mut headers) =
            wrap_selected_then_rejected(&plugins, &mut ctx).await;

        transform_buffered_response_body_with_deadline_full_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
            true,
        )
        .await;

        assert_eq!(status, 502, "instances={instances}");
        assert_eq!(
            content_type_of(&headers),
            Some("application/json"),
            "instances={instances}"
        );
        assert_eq!(&body[..], GUARD_REJECTION_BODY, "instances={instances}");
        serde_json::from_slice::<serde_json::Value>(&body)
            .unwrap_or_else(|error| panic!("instances={instances}: invalid JSON: {error}"));
    }
}

fn forwarded(action: ResponseStreamAction) -> Vec<u8> {
    match action {
        ResponseStreamAction::Forward(bytes) => bytes.to_vec(),
        other => panic!("expected Forward, got {other:?}"),
    }
}

/// A genuine origin event stream after the normal header phase, plus the
/// inspector this plugin attaches to it.
async fn genuine_stream_inspector(
    config: serde_json::Value,
) -> Option<Box<dyn ResponseStreamInspector>> {
    let plugin = make_plugin(config);
    let (mut ctx, mut headers) = stamped_origin("text/event-stream");
    assert_continue(&plugin.after_proxy(&mut ctx, 200, &mut headers).await);
    plugin.response_stream_inspector(&ctx, 200, content_type_of(&headers))
}

#[test]
fn test_only_retry_configured_instances_request_stream_hooks() {
    assert!(make_plugin(json!({"retry_ms": 2500})).requires_response_stream_hooks());
    assert!(!make_plugin(json!({})).requires_response_stream_hooks());
    assert!(!make_plugin(json!({"wrap_non_sse_responses": true})).requires_response_stream_hooks());
}

/// PR6831-SOL-2: `retry:` is written once, ahead of the first backend bytes,
/// as its own line (no blank line, so no event dispatch), and every later
/// chunk passes through unchanged.
#[tokio::test]
async fn test_retry_field_is_written_once_at_the_start_of_a_genuine_stream() {
    let mut inspector = genuine_stream_inspector(json!({"retry_ms": 2500}))
        .await
        .expect("a genuine event stream gets the retry inspector");

    let first = forwarded(inspector.on_chunk(b"id: 7\ndata: a\n\n").await);
    assert_eq!(first, b"retry: 2500\nid: 7\ndata: a\n\n");
    let second = forwarded(inspector.on_chunk(b"data: b\n\n").await);
    assert_eq!(second, b"data: b\n\n");
    let end = forwarded(inspector.on_end().await);
    assert!(end.is_empty(), "nothing is held at the end");
}

/// A backend BOM split across chunks is held, then dropped, so the decoded
/// stream still starts with the field rather than a BOM-prefixed field name.
#[tokio::test]
async fn test_retry_field_is_written_ahead_of_a_split_backend_bom() {
    let mut inspector = genuine_stream_inspector(json!({"retry_ms": 2500}))
        .await
        .expect("inspector");

    let held = forwarded(inspector.on_chunk(&[0xEF]).await);
    assert!(held.is_empty(), "a possible BOM prefix is held");
    let released = forwarded(inspector.on_chunk(b"\xBB\xBFdata: a\n\n").await);
    assert_eq!(released, b"retry: 2500\ndata: a\n\n");
}

/// Bytes that only looked like a BOM start are released unchanged after the
/// field, and a stream that ends before any byte still carries the field.
#[tokio::test]
async fn test_retry_field_releases_non_bom_bytes_and_empty_streams() {
    let mut inspector = genuine_stream_inspector(json!({"retry_ms": 2500}))
        .await
        .expect("inspector");
    assert!(forwarded(inspector.on_chunk(&[0xEF]).await).is_empty());
    let released = forwarded(inspector.on_chunk(b"x").await);
    assert_eq!(released, b"retry: 2500\n\xEFx");

    let mut empty = genuine_stream_inspector(json!({"retry_ms": 2500}))
        .await
        .expect("inspector");
    assert_eq!(forwarded(empty.on_end().await), b"retry: 2500\n");
}

/// The inspector attaches only to a 2xx genuine origin event stream on an
/// instance that configured `retry_ms`.
#[tokio::test]
async fn test_retry_inspector_declines_non_genuine_streams() {
    assert!(genuine_stream_inspector(json!({})).await.is_none());

    let plugin = make_plugin(json!({"retry_ms": 2500, "force_sse_content_type": true}));
    let (mut ctx, mut headers) = stamped_origin("application/json");
    assert_continue(&plugin.after_proxy(&mut ctx, 200, &mut headers).await);
    assert_eq!(content_type_of(&headers), Some("text/event-stream"));
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, content_type_of(&headers))
            .is_none(),
        "a relabelled non-SSE response is not the origin's event stream"
    );

    let plugin = make_plugin(json!({"retry_ms": 2500}));
    let unstamped = make_sse_ctx();
    assert!(
        plugin
            .response_stream_inspector(&unstamped, 200, Some("text/event-stream"))
            .is_none(),
        "a gateway-authored stream has no origin stamp"
    );

    let (ctx, _) = stamped_origin("text/event-stream");
    assert!(
        plugin
            .response_stream_inspector(&ctx, 503, Some("text/event-stream"))
            .is_none()
    );
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/plain"))
            .is_none()
    );
}

// ── Fix round 2: retry injection never touches coded or protected streams ─────

/// PR6831-SOL-3: a genuine event stream the backend sent under gzip/br is a
/// compressed bitstream. Plaintext `retry:` written ahead of it would break the
/// client's decoder, so no inspector attaches (directly or through the shared
/// resolver every transport uses) and the bytes are forwarded unchanged.
#[tokio::test]
async fn test_retry_inspector_never_attaches_to_content_coded_streams() {
    let plugin = Arc::new(make_plugin(json!({
        "retry_ms": 2500,
        "strip_accept_encoding": false
    })));
    let plugins: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    for coding in ["gzip", "br", "gzip, br"] {
        let (mut ctx, mut headers) =
            stamped_origin_with("text/event-stream", "content-encoding", coding);
        assert_continue(&plugin.after_proxy(&mut ctx, 200, &mut headers).await);
        assert_eq!(
            headers.get("content-encoding").map(String::as_str),
            Some(coding),
            "the coding is preserved: {coding}"
        );
        let content_type = content_type_of(&headers);
        assert!(
            plugin
                .response_stream_inspector(&ctx, 200, content_type)
                .is_none(),
            "no direct inspector for {coding}"
        );
        assert!(
            ferrum_edge::plugins::create_response_stream_inspector(
                &plugins,
                &mut ctx,
                200,
                content_type,
            )
            .is_none(),
            "the shared resolver must not attach one either: {coding}"
        );
    }
}

/// An explicit `identity` coding is not a transformation, so the field is
/// still written.
#[tokio::test]
async fn test_retry_inspector_still_attaches_to_identity_coded_streams() {
    let plugin = make_plugin(json!({"retry_ms": 2500}));
    let (mut ctx, mut headers) =
        stamped_origin_with("text/event-stream", "content-encoding", "identity");
    assert_continue(&plugin.after_proxy(&mut ctx, 200, &mut headers).await);
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, content_type_of(&headers))
        .expect("identity bytes are the text an EventSource parses");
    let first = forwarded(inspector.on_chunk(b"data: a\n\n").await);
    assert_eq!(first, b"retry: 2500\ndata: a\n\n");
}

/// The other representation boundaries the wrapper honors apply to the
/// stream field too: `no-transform` forbids adding content, and a `206`/`226`
/// body is not the start of an event stream.
#[tokio::test]
async fn test_retry_inspector_respects_no_transform_and_partial_content() {
    let plugin = make_plugin(json!({"retry_ms": 2500}));
    let (mut ctx, mut headers) =
        stamped_origin_with("text/event-stream", "cache-control", "no-transform");
    assert_continue(&plugin.after_proxy(&mut ctx, 200, &mut headers).await);
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, content_type_of(&headers))
            .is_none(),
        "no-transform forbids the added field"
    );

    for status in [206, 226] {
        let (ctx, _) = stamped_origin("text/event-stream");
        assert!(
            plugin
                .response_stream_inspector(&ctx, status, Some("text/event-stream"))
                .is_none(),
            "status {status}"
        );
    }
}
