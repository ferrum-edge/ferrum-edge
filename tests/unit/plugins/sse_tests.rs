use ferrum_edge::plugins::sse::SsePlugin;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
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
    assert_eq!(plugin.priority(), 250);
}

#[test]
fn test_supported_protocols_http_only() {
    let plugin = make_plugin(json!({}));
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0], ferrum_edge::plugins::ProxyProtocol::Http);
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
fn test_modifies_request_headers_default_true() {
    let plugin = make_plugin(json!({}));
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_modifies_request_headers_false_when_strip_disabled() {
    let plugin = make_plugin(json!({"strip_accept_encoding": false}));
    assert!(!plugin.modifies_request_headers());
}

#[test]
fn test_applies_after_proxy_on_reject_is_false() {
    let plugin = make_plugin(json!({}));
    assert!(!plugin.applies_after_proxy_on_reject());
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
    assert_eq!(ctx.metadata.get("sse:last_event_id").unwrap(), "evt-42");
}

#[tokio::test]
async fn test_no_last_event_id_no_metadata() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    plugin.on_request_received(&mut ctx).await;
    assert!(!ctx.metadata.contains_key("sse:last_event_id"));
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

// ── before_proxy: original Accept saved in metadata ───────────────────────────

#[tokio::test]
async fn test_original_accept_saved_in_metadata() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    let mut headers = HashMap::new();

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata.get("sse:original_accept").unwrap(),
        "text/event-stream"
    );
}

// ── before_proxy: Last-Event-ID forwarding ────────────────────────────────────

#[tokio::test]
async fn test_last_event_id_forwarded_to_backend() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.metadata
        .insert("sse:last_event_id".to_string(), "evt-99".to_string());
    let mut headers = HashMap::new();

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("last-event-id").unwrap(), "evt-99");
}

#[tokio::test]
async fn test_last_event_id_does_not_overwrite_existing_header() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_sse_ctx();
    ctx.metadata
        .insert("sse:last_event_id".to_string(), "from-metadata".to_string());
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
    assert_eq!(headers.get("connection").unwrap(), "keep-alive");
    assert_eq!(headers.get("x-accel-buffering").unwrap(), "no");
    assert!(!headers.contains_key("content-length"));
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

#[tokio::test]
async fn test_force_sse_content_type_on_json_response() {
    let plugin = make_plugin(json!({"force_sse_content_type": true}));
    let mut ctx = make_sse_ctx();
    let mut headers = json_response_headers();

    plugin.after_proxy(&mut ctx, 200, &mut headers).await;

    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert_eq!(headers.get("cache-control").unwrap(), "no-cache");
    assert_eq!(headers.get("connection").unwrap(), "keep-alive");
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
    assert_eq!(ctx.metadata.get("sse:last_event_id").unwrap(), "42");

    // Phase 2: shape request for backend.
    let mut backend_headers = HashMap::new();
    backend_headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut backend_headers).await;
    assert_continue(&result);
    assert!(!backend_headers.contains_key("accept-encoding"));
    assert_eq!(backend_headers.get("last-event-id").unwrap(), "42");
    assert_eq!(
        ctx.metadata.get("sse:original_accept").unwrap(),
        "text/event-stream"
    );

    // Phase 3: decorate response.
    let mut response_headers = sse_response_headers();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_continue(&result);
    assert_eq!(response_headers.get("cache-control").unwrap(), "no-cache");
    assert_eq!(response_headers.get("connection").unwrap(), "keep-alive");
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
