use ferrum_edge::plugins::sse::{
    LAST_EVENT_ID_METADATA_KEY, MAX_LAST_EVENT_ID_BYTES, SsePlugin, redact_sse_log_metadata,
};
use ferrum_edge::plugins::utils::metadata_redaction::{
    REDACTED_PLACEHOLDER, is_sensitive_metadata_key_with_extras, serialize_redacted_metadata,
};
use ferrum_edge::plugins::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use ferrum_edge::proxy::headers::{
    apply_response_headers, strip_client_response_hop_by_hop_headers,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;

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
    assert!(err.contains("'strip_accept_encoding' must be a boolean"));
}

#[test]
fn test_invalid_retry_ms_rejected() {
    let err = SsePlugin::new(&json!({"retry_ms": "3000"}))
        .err()
        .expect("invalid retry_ms must be rejected");
    assert!(err.contains("'retry_ms' must be an unsigned integer"));
}

#[test]
fn test_zero_retry_ms_rejected() {
    let err = SsePlugin::new(&json!({"retry_ms": 0}))
        .err()
        .expect("zero retry_ms must be rejected");
    assert!(err.contains("'retry_ms' must be greater than zero"));
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
        err.contains("'require_get_method' must be a boolean"),
        "{err}"
    );
}

#[test]
fn test_null_retry_ms_rejected() {
    let err = SsePlugin::new(&json!({"retry_ms": null}))
        .err()
        .expect("null retry_ms must be rejected");
    assert!(
        err.contains("'retry_ms' must be an unsigned integer"),
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
        "an over-ceiling framed event must be refused, leaving the original \
         body in place"
    );
}
