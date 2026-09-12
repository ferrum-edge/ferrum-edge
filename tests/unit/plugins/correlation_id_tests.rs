//! Tests for the Correlation ID plugin

use ferrum_edge::_test_support::{
    clone_log_metadata, is_gateway_generated_correlation_header_for_test,
};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, REQUEST_ID_METADATA_KEY, RequestContext, correlation_id::CorrelationId,
    priority,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

// ── Constructor validation ──────────────────────────────────────────

#[test]
fn test_constructor_rejects_every_non_object_config_class() {
    for config in [
        json!(null),
        json!([]),
        json!("not-an-object"),
        json!(42),
        json!(true),
    ] {
        let err = CorrelationId::new(&config)
            .err()
            .expect("non-object config must be rejected");
        assert_eq!(err, "correlation_id: config must be a JSON object");
    }
}

#[test]
fn test_constructor_rejects_one_and_multiple_unknown_fields_deterministically() {
    let one = CorrelationId::new(&json!({"echo_downsteam": false}))
        .err()
        .expect("unknown field must be rejected");
    assert_eq!(
        one,
        "correlation_id: unknown config field(s): echo_downsteam"
    );

    let multiple = CorrelationId::new(&json!({
        "z_unknown": true,
        "header_name": "x-request-id",
        "a_unknown": false
    }))
    .err()
    .expect("multiple unknown fields must be rejected");
    assert_eq!(
        multiple,
        "correlation_id: unknown config field(s): a_unknown, z_unknown"
    );
}

#[test]
fn test_constructor_rejects_non_string_header_name() {
    let err = CorrelationId::new(&json!({ "header_name": 42 }))
        .err()
        .expect("integer header_name must be rejected");
    assert!(err.contains("must be a string"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_header_name() {
    let err = CorrelationId::new(&json!({ "header_name": "" }))
        .err()
        .expect("empty header_name must be rejected");
    assert!(err.contains("non-empty string"), "got: {err}");
}

#[test]
fn test_constructor_rejects_invalid_header_name_chars() {
    // Colon is not a valid HTTP token character per RFC 7230 §3.2.6
    let err = CorrelationId::new(&json!({ "header_name": "x:request-id" }))
        .err()
        .expect("colon in header name must be rejected");
    assert!(err.contains("not permitted"), "got: {err}");
}

#[test]
fn test_constructor_trims_rust_unicode_whitespace_but_not_bom() {
    let nel = "\u{0085}X-Audit\u{0085}".to_string();
    let plugin = CorrelationId::new(&json!({ "header_name": nel }))
        .expect("U+0085 is Rust White_Space and must be trimmed");
    assert_eq!(plugin.correlation_id_header_name(), Some("x-audit"));

    let bom = "\u{feff}x-audit\u{feff}".to_string();
    let err = CorrelationId::new(&json!({ "header_name": bom }))
        .err()
        .expect("U+FEFF is not Rust White_Space and must not be trimmed");
    assert!(err.contains("not permitted"), "got: {err}");
}

#[test]
fn test_constructor_admits_http_builder_limit_and_rejects_overlong_names() {
    let maximum = "a".repeat(65_535);
    let plugin = CorrelationId::new(&json!({ "header_name": maximum.clone() }))
        .expect("65,535-byte HTTP field name is the accepted builder limit");
    assert_eq!(plugin.correlation_id_header_name(), Some(maximum.as_str()));
    assert!(
        http::header::HeaderName::from_bytes(maximum.as_bytes()).is_ok(),
        "admitted name must be representable as HeaderName"
    );

    let padded = format!(" \t{maximum}\n");
    let trimmed = CorrelationId::new(&json!({ "header_name": padded }))
        .expect("surrounding whitespace is trimmed before the length check");
    assert_eq!(trimmed.correlation_id_header_name(), Some(maximum.as_str()));

    let overlong = "a".repeat(65_536);
    let err = CorrelationId::new(&json!({ "header_name": overlong }))
        .err()
        .expect("65,536-byte header name must be rejected at admission");
    assert!(err.contains("65,535"), "got: {err}");
    assert!(
        err.len() < 200,
        "overlong-name diagnostic must stay bounded, got {} bytes",
        err.len()
    );
}

#[tokio::test]
async fn test_max_length_header_name_forwards_and_echoes() {
    let maximum = "a".repeat(65_535);
    let plugin = CorrelationId::new(&json!({ "header_name": maximum.clone() }))
        .expect("65,535-byte HTTP field name is the accepted builder limit");
    let mut ctx = make_ctx();
    plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);
    let generated = ctx
        .headers
        .get(&maximum)
        .expect("request hook must install the configured header")
        .clone();
    assert!(uuid::Uuid::parse_str(&generated).is_ok());

    let mut outgoing = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut outgoing).await);
    assert_eq!(
        outgoing.get(&maximum).map(String::as_str),
        Some(generated.as_str())
    );

    let mut response = HashMap::new();
    plugin_utils::assert_continue(plugin.after_proxy(&mut ctx, 200, &mut response).await);
    assert_eq!(
        response.get(&maximum).map(String::as_str),
        Some(generated.as_str())
    );
}

#[test]
fn test_constructor_rejects_protocol_managed_and_security_sensitive_header_names() {
    for header_name in [
        "API-Key",
        "Authentication-Info",
        "Authorization",
        "Connection",
        "Content-Encoding",
        "Content-Length",
        "Cookie",
        "Early-Data",
        "Expect",
        "Forwarded",
        "Grpc-Message",
        "Grpc-Status",
        "Grpc-Status-Details-Bin",
        "Host",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authentication-Info",
        "Proxy-Authorization",
        "Proxy-Connection",
        "Sec-WebSocket-Accept",
        "Sec-WebSocket-Extensions",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Protocol",
        "Sec-WebSocket-Version",
        "Set-Cookie",
        "TE",
        "Traceparent",
        "Tracestate",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Via",
        "WWW-Authenticate",
        "X-API-Key",
        "X-Auth-Token",
        "X-CSRF-Token",
        "X-Ferrum-Original-Content-Encoding",
        "X-Forwarded-Authorization",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Goog-API-Key",
        "X-Grpc-Web-Mode",
        "X-XSRF-Token",
    ] {
        let err = CorrelationId::new(&json!({"header_name": header_name}))
            .err()
            .expect("reserved header must be rejected");
        assert!(err.contains("protocol-managed"), "{header_name}: {err}");
    }
}

#[test]
fn test_constructor_rejects_effective_real_ip_header_case_insensitively() {
    let error = ferrum_edge::_test_support::correlation_id_with_real_ip_header_for_test(
        &json!({"header_name": " CF-Connecting-IP "}),
        Some("cf-connecting-ip"),
    )
    .err()
    .expect("configured real-IP header collision must fail closed");
    assert!(error.contains("FERRUM_REAL_IP_HEADER"), "got: {error}");
    assert!(error.contains("cf-connecting-ip"), "got: {error}");
}

#[test]
fn test_constructor_rejects_default_header_when_used_for_real_ip() {
    let error = ferrum_edge::_test_support::correlation_id_with_real_ip_header_for_test(
        &json!({}),
        Some("X-Request-ID"),
    )
    .err()
    .expect("the default correlation header must not replace the real-IP header");
    assert!(error.contains("FERRUM_REAL_IP_HEADER"), "got: {error}");
    assert!(error.contains("x-request-id"), "got: {error}");
}

#[test]
fn test_constructor_accepts_header_distinct_from_effective_real_ip_header() {
    let plugin = ferrum_edge::_test_support::correlation_id_with_real_ip_header_for_test(
        &json!({"header_name": "X-Request-ID"}),
        Some("cloudfront-viewer-address"),
    )
    .expect("distinct correlation and real-IP headers must remain valid");
    assert_eq!(plugin.correlation_id_header_name(), Some("x-request-id"));
}

#[test]
fn test_constructor_rejects_non_bool_echo_downstream() {
    let err = CorrelationId::new(&json!({ "echo_downstream": "yes" }))
        .err()
        .expect("string echo_downstream must be rejected");
    assert!(err.contains("must be a boolean"), "got: {err}");
}

#[test]
fn test_constructor_accepts_null_fields_as_defaults() {
    // Explicit null is treated the same as omitted — falls back to defaults.
    let plugin = CorrelationId::new(&json!({
        "header_name": null,
        "echo_downstream": null
    }))
    .expect("null fields should fall back to defaults");
    assert_eq!(plugin.name(), "correlation_id");
}

// ── Plugin identity ─────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "correlation_id");
}

#[test]
fn test_plugin_priority() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    assert_eq!(plugin.priority(), priority::CORRELATION_ID);
    assert_eq!(plugin.priority(), 50);
}

#[test]
fn test_modifies_request_headers() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_phase_and_protocol_flags() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(plugin.modifies_request_headers());
    assert!(plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_applies_after_proxy_on_reject_follows_echo_downstream() {
    let echo_enabled = CorrelationId::new(&json!({
        "echo_downstream": true
    }))
    .unwrap();
    assert!(echo_enabled.applies_after_proxy_on_reject());

    let echo_disabled = CorrelationId::new(&json!({
        "echo_downstream": false
    }))
    .unwrap();
    assert!(!echo_disabled.applies_after_proxy_on_reject());
}

// ── Default configuration ───────────────────────────────────────────

#[tokio::test]
async fn test_default_config_uses_x_request_id_header() {
    // Default header_name should be "x-request-id" — verify by running the plugin
    // and checking that it inserts the correlation ID into the correct header
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // The default header is "x-request-id" — verify it was inserted
    assert!(
        ctx.headers.contains_key("x-request-id"),
        "Default config should insert x-request-id header"
    );
    // The value should be a valid UUID
    let id = ctx.headers.get("x-request-id").unwrap();
    assert!(
        uuid::Uuid::parse_str(id).is_ok(),
        "Correlation ID should be a valid UUID, got: {}",
        id
    );
}

#[tokio::test]
async fn test_default_config_echo_downstream_enabled() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    // Generate correlation ID
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // after_proxy should echo the header in response since echo_downstream defaults to true
    let mut response_headers = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin_utils::assert_continue(result);

    assert!(
        response_headers.contains_key("x-request-id"),
        "Default config should echo correlation ID downstream"
    );
}

// ── Generates UUID when none present ────────────────────────────────

#[tokio::test]
async fn test_generates_uuid_when_no_correlation_id_present() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // Should have inserted a header
    let header_value = ctx
        .headers
        .get("x-request-id")
        .expect("header should be set");
    // Validate it's a UUID v4 format
    assert!(
        uuid::Uuid::parse_str(header_value).is_ok(),
        "Generated ID should be a valid UUID, got: {}",
        header_value
    );
}

#[tokio::test]
async fn test_generated_uuid_stored_in_metadata() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let metadata_id = ctx
        .metadata
        .get("request_id")
        .expect("request_id should be in metadata");
    let header_id = ctx
        .headers
        .get("x-request-id")
        .expect("header should be set");
    assert_eq!(metadata_id, header_id, "Metadata and header should match");
}

// ── Preserves existing correlation ID ───────────────────────────────

#[tokio::test]
async fn test_preserves_existing_correlation_id() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-request-id".to_string(), "my-custom-id-123".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    assert_eq!(
        ctx.headers.get("x-request-id").unwrap(),
        "my-custom-id-123",
        "Existing correlation ID should be preserved"
    );
    assert_eq!(
        ctx.metadata.get("request_id").unwrap(),
        "my-custom-id-123",
        "Metadata should contain the preserved ID"
    );
}

#[tokio::test]
async fn test_preserves_existing_id_at_max_length() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    let id_256_chars: String = "a".repeat(256);
    ctx.headers
        .insert("x-request-id".to_string(), id_256_chars.clone());

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    assert_eq!(
        ctx.headers.get("x-request-id").unwrap(),
        &id_256_chars,
        "ID at exactly 256 chars should be preserved"
    );
}

// ── Truncates oversized correlation IDs ─────────────────────────────

#[tokio::test]
async fn test_replaces_oversized_correlation_id() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    let oversized_id: String = "x".repeat(257);
    ctx.headers
        .insert("x-request-id".to_string(), oversized_id.clone());

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    let new_id = ctx.headers.get("x-request-id").unwrap();
    assert_ne!(new_id, &oversized_id, "Oversized ID should be replaced");
    assert!(
        uuid::Uuid::parse_str(new_id).is_ok(),
        "Replacement should be a valid UUID, got: {}",
        new_id
    );
}

#[tokio::test]
async fn test_oversized_id_metadata_matches_replaced_header() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    let oversized_id: String = "z".repeat(500);
    ctx.headers.insert("x-request-id".to_string(), oversized_id);

    plugin.on_request_received(&mut ctx).await;

    let header_id = ctx.headers.get("x-request-id").unwrap();
    let metadata_id = ctx.metadata.get("request_id").unwrap();
    assert_eq!(
        header_id, metadata_id,
        "Metadata and header should match after replacement"
    );
}

// ── Rejects ids with unsafe characters (finding #69) ────────────────

#[tokio::test]
async fn test_replaces_inbound_id_with_control_chars() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    // HTAB and DEL are permitted by http::HeaderValue but are not safe
    // correlation-id characters; the value must be regenerated, not reflected.
    let unsafe_id = "abc\u{09}def\u{7f}".to_string();
    ctx.headers
        .insert("x-request-id".to_string(), unsafe_id.clone());

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    let new_id = ctx.headers.get("x-request-id").unwrap();
    assert_ne!(
        new_id, &unsafe_id,
        "ID with control characters should be replaced"
    );
    assert!(
        uuid::Uuid::parse_str(new_id).is_ok(),
        "Replacement should be a valid UUID, got: {new_id:?}"
    );
    // Metadata must carry the sanitized (regenerated) value, not the raw input.
    let metadata_id = ctx.metadata.get("request_id").unwrap();
    assert_eq!(metadata_id, new_id);
    assert_ne!(metadata_id, &unsafe_id);
}

#[tokio::test]
async fn test_replaces_inbound_id_with_obs_text_byte() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    // obs-text (0x80-0xFF) is legal in a header value but not a token char.
    let unsafe_id = "trace-\u{00e9}".to_string();
    ctx.headers
        .insert("x-request-id".to_string(), unsafe_id.clone());

    plugin.on_request_received(&mut ctx).await;

    let new_id = ctx.headers.get("x-request-id").unwrap();
    assert_ne!(new_id, &unsafe_id, "ID with obs-text should be replaced");
    assert!(uuid::Uuid::parse_str(new_id).is_ok());
}

#[tokio::test]
async fn test_replaces_inbound_id_with_printable_punctuation() {
    for unsafe_id in [
        "order:12345",
        "Root=1-abc;Parent=def",
        "trace/value+suffix",
        "contains space",
    ] {
        let plugin = CorrelationId::new(&json!({})).unwrap();
        let mut ctx = make_ctx();
        ctx.headers
            .insert("x-request-id".to_string(), unsafe_id.to_string());

        plugin.on_request_received(&mut ctx).await;

        let replacement = ctx.headers.get("x-request-id").unwrap();
        assert_ne!(replacement, unsafe_id);
        assert!(uuid::Uuid::parse_str(replacement).is_ok());
    }
}

#[tokio::test]
async fn test_preserves_well_formed_uuid_inbound_id() {
    // No-over-restriction guard: a well-formed token id (UUID with hyphens)
    // must still be preserved verbatim.
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    let good_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
    ctx.headers
        .insert("x-request-id".to_string(), good_id.clone());

    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.headers.get("x-request-id").unwrap(),
        &good_id,
        "Well-formed UUID id should be preserved"
    );
    assert_eq!(ctx.metadata.get("request_id").unwrap(), &good_id);
}

// ── Custom header name ──────────────────────────────────────────────

#[tokio::test]
async fn test_custom_header_name() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "X-Correlation-ID"
    }))
    .unwrap();
    let mut ctx = make_ctx();

    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // Header name is lowercased
    assert!(
        ctx.headers.contains_key("x-correlation-id"),
        "Custom header name should be used (lowercased)"
    );
    assert!(
        !ctx.headers.contains_key("x-request-id"),
        "Default header name should not be used"
    );
}

#[tokio::test]
async fn test_custom_header_preserves_existing_value() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "X-Trace-ID"
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-trace-id".to_string(), "trace-abc-456".to_string());

    plugin.on_request_received(&mut ctx).await;

    assert_eq!(
        ctx.headers.get("x-trace-id").unwrap(),
        "trace-abc-456",
        "Custom header should preserve existing value"
    );
}

#[tokio::test]
async fn test_custom_header_echo_downstream() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "X-My-Trace"
    }))
    .unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert!(
        response_headers.contains_key("x-my-trace"),
        "Custom header name should be echoed downstream"
    );
    assert!(
        !response_headers.contains_key("x-request-id"),
        "Default header should not appear"
    );
}

// ── Echo downstream enabled ─────────────────────────────────────────

#[tokio::test]
async fn test_echo_downstream_enabled_adds_header_to_response() {
    let plugin = CorrelationId::new(&json!({
        "echo_downstream": true
    }))
    .unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let request_id = ctx.metadata.get("request_id").unwrap().clone();

    let mut response_headers = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin_utils::assert_continue(result);

    assert_eq!(
        response_headers.get("x-request-id").unwrap(),
        &request_id,
        "Response should contain the same correlation ID"
    );
}

#[tokio::test]
async fn test_echo_downstream_preserves_original_id() {
    let plugin = CorrelationId::new(&json!({
        "echo_downstream": true
    }))
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-request-id".to_string(), "original-id-789".to_string());

    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert_eq!(
        response_headers.get("x-request-id").unwrap(),
        "original-id-789",
        "Echoed ID should match the original request ID"
    );
}

// ── Echo downstream disabled ────────────────────────────────────────

#[tokio::test]
async fn test_echo_downstream_disabled_no_header_in_response() {
    let plugin = CorrelationId::new(&json!({
        "echo_downstream": false
    }))
    .unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin_utils::assert_continue(result);

    assert!(
        !response_headers.contains_key("x-request-id"),
        "Response should NOT contain correlation ID when echo_downstream is false"
    );
}

#[tokio::test]
async fn test_echo_downstream_disabled_still_stores_metadata() {
    let plugin = CorrelationId::new(&json!({
        "echo_downstream": false
    }))
    .unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    assert!(
        ctx.metadata.contains_key("request_id"),
        "Metadata should still have request_id even with echo disabled"
    );
}

// ── Stores correlation ID in metadata ───────────────────────────────

#[tokio::test]
async fn test_metadata_request_id_set_for_downstream_plugins() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let request_id = ctx.metadata.get("request_id");
    assert!(request_id.is_some(), "request_id must be in metadata");
    assert!(
        !request_id.unwrap().is_empty(),
        "request_id must not be empty"
    );
}

// ── before_proxy propagates to outgoing headers ─────────────────────

#[tokio::test]
async fn test_before_proxy_propagates_correlation_id_to_outgoing_headers() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;
    let expected_id = ctx.metadata.get("request_id").unwrap().clone();

    let mut outgoing_headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut outgoing_headers).await;
    plugin_utils::assert_continue(result);

    assert_eq!(
        outgoing_headers.get("x-request-id").unwrap(),
        &expected_id,
        "Outgoing request headers should contain the correlation ID"
    );
}

#[tokio::test]
async fn test_before_proxy_uses_custom_header_name() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "X-Req-Trace"
    }))
    .unwrap();
    let mut ctx = make_ctx();

    plugin.on_request_received(&mut ctx).await;

    let mut outgoing_headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut outgoing_headers).await;

    assert!(
        outgoing_headers.contains_key("x-req-trace"),
        "Custom header should be used in outgoing headers"
    );
}

// ── Each request gets a unique ID ───────────────────────────────────

#[tokio::test]
async fn test_each_request_generates_unique_id() {
    let plugin = CorrelationId::new(&json!({})).unwrap();

    let mut ctx1 = make_ctx();
    let mut ctx2 = make_ctx();

    plugin.on_request_received(&mut ctx1).await;
    plugin.on_request_received(&mut ctx2).await;

    let id1 = ctx1.metadata.get("request_id").unwrap();
    let id2 = ctx2.metadata.get("request_id").unwrap();

    assert_ne!(id1, id2, "Each request should get a unique ID");
}

// ── Full lifecycle test ─────────────────────────────────────────────

#[tokio::test]
async fn test_full_lifecycle_generate_propagate_echo() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "X-Req-ID",
        "echo_downstream": true
    }))
    .unwrap();
    let mut ctx = make_ctx();

    // Step 1: on_request_received generates ID
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    let generated_id = ctx.metadata.get("request_id").unwrap().clone();
    assert!(uuid::Uuid::parse_str(&generated_id).is_ok());

    // Step 2: before_proxy propagates to backend request
    let mut outgoing = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut outgoing).await;
    plugin_utils::assert_continue(result);
    assert_eq!(outgoing.get("x-req-id").unwrap(), &generated_id);

    // Step 3: after_proxy echoes to client response
    let mut response = HashMap::new();
    let result = plugin.after_proxy(&mut ctx, 200, &mut response).await;
    plugin_utils::assert_continue(result);
    assert_eq!(response.get("x-req-id").unwrap(), &generated_id);
}

// ── Multi-instance trust isolation ──────────────────────────────────

async fn assert_isolated_instances(external_first: bool) {
    let internal = CorrelationId::new(&json!({
        "header_name": "x-internal-request-id",
        "echo_downstream": true
    }))
    .unwrap();
    let external = CorrelationId::new(&json!({
        "header_name": "x-external-correlation-id",
        "echo_downstream": true
    }))
    .unwrap();
    let ordered: [&CorrelationId; 2] = if external_first {
        [&external, &internal]
    } else {
        [&internal, &external]
    };

    let mut ctx = make_ctx();
    // An earlier custom plugin may use the generic consumer-facing key. That
    // occupancy must not prevent the first correlation instance from claiming
    // canonical ownership, while the second instance must still preserve it.
    ctx.metadata.insert(
        REQUEST_ID_METADATA_KEY.to_string(),
        "pre-correlation-custom-value".to_string(),
    );
    ctx.metadata.insert(
        "correlation_id.instance.spoofed-custom-value".to_string(),
        "attacker-metadata".to_string(),
    );
    ctx.headers.insert(
        "x-external-correlation-id".to_string(),
        "attacker-preserved-id".to_string(),
    );
    for plugin in ordered {
        plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);
    }

    let internal_id = ctx
        .headers
        .get("x-internal-request-id")
        .expect("internal instance must generate an ID")
        .clone();
    assert!(uuid::Uuid::parse_str(&internal_id).is_ok());
    assert_eq!(
        ctx.headers
            .get("x-external-correlation-id")
            .map(String::as_str),
        Some("attacker-preserved-id")
    );
    assert_ne!(internal_id, "attacker-preserved-id");

    let expected_canonical = if external_first {
        "attacker-preserved-id"
    } else {
        internal_id.as_str()
    };
    assert_eq!(
        ctx.metadata
            .get(REQUEST_ID_METADATA_KEY)
            .map(String::as_str),
        Some(expected_canonical),
        "the first configured instance owns the canonical consumer metadata"
    );
    assert_eq!(
        ctx.metadata
            .get("correlation_id.instance.x-internal-request-id"),
        Some(&internal_id)
    );
    assert_eq!(
        ctx.metadata
            .get("correlation_id.instance.x-external-correlation-id")
            .map(String::as_str),
        Some("attacker-preserved-id")
    );
    assert!(
        !ctx.metadata.contains_key("correlation_id.canonical_owner"),
        "correlation ownership bookkeeping must not enter public metadata"
    );

    // A later plugin can write arbitrary public metadata names. Those writes
    // must not replace the authoritative canonical or instance values used for
    // backend propagation, response echo, or transaction summaries.
    ctx.metadata.insert(
        REQUEST_ID_METADATA_KEY.to_string(),
        "poisoned-canonical-id".to_string(),
    );
    ctx.metadata.insert(
        "correlation_id.instance.x-internal-request-id".to_string(),
        "poisoned-internal-id".to_string(),
    );
    ctx.metadata.insert(
        "correlation_id.instance.x-external-correlation-id".to_string(),
        "poisoned-external-id".to_string(),
    );

    let mut backend_headers = HashMap::new();
    for plugin in ordered {
        plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut backend_headers).await);
    }
    assert_eq!(
        backend_headers.get("x-internal-request-id"),
        Some(&internal_id)
    );
    assert_eq!(
        backend_headers
            .get("x-external-correlation-id")
            .map(String::as_str),
        Some("attacker-preserved-id")
    );

    let logged = clone_log_metadata(&ctx);
    assert_eq!(
        logged.get(REQUEST_ID_METADATA_KEY).map(String::as_str),
        Some(expected_canonical)
    );
    assert_eq!(
        logged
            .get("correlation_id.instance.x-internal-request-id")
            .map(String::as_str),
        Some(internal_id.as_str())
    );
    assert_eq!(
        logged
            .get("correlation_id.instance.x-external-correlation-id")
            .map(String::as_str),
        Some("attacker-preserved-id")
    );

    for status in [200, 403] {
        let mut response_headers = HashMap::new();
        for plugin in ordered {
            plugin_utils::assert_continue(
                plugin
                    .after_proxy(&mut ctx, status, &mut response_headers)
                    .await,
            );
        }
        assert_eq!(
            response_headers.get("x-internal-request-id"),
            Some(&internal_id)
        );
        assert_eq!(
            response_headers
                .get("x-external-correlation-id")
                .map(String::as_str),
            Some("attacker-preserved-id")
        );
    }
}

#[tokio::test]
async fn test_multiple_instances_isolate_trust_domains_in_both_orders() {
    assert_isolated_instances(false).await;
    assert_isolated_instances(true).await;
}

// ── Successful WebSocket response propagation ──────────────────────

#[tokio::test]
async fn test_websocket_handshake_response_echoes_generated_and_preserved_ids() {
    for status in [101, 200] {
        for inbound in [None, Some("preserved-websocket-id")] {
            let plugin = CorrelationId::new(&json!({})).unwrap();
            let mut ctx = make_ctx();
            if let Some(inbound) = inbound {
                ctx.headers
                    .insert("x-request-id".to_string(), inbound.to_string());
            }
            plugin.on_request_received(&mut ctx).await;

            let expected = ctx
                .metadata
                .get(REQUEST_ID_METADATA_KEY)
                .expect("canonical request ID")
                .clone();
            let mut response_headers = HashMap::new();
            plugin.apply_websocket_handshake_response_headers(&ctx, status, &mut response_headers);
            assert_eq!(response_headers.get("x-request-id"), Some(&expected));
            if let Some(inbound) = inbound {
                assert_eq!(expected, inbound);
            } else {
                assert!(uuid::Uuid::parse_str(&expected).is_ok());
            }
        }
    }
}

// ── Generated vs client-supplied provenance for response_caching (#3929) ─

#[tokio::test]
async fn omitted_header_records_private_generated_provenance_and_still_forwards() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);

    let generated = ctx
        .headers
        .get("x-request-id")
        .expect("generated header")
        .clone();
    assert!(uuid::Uuid::parse_str(&generated).is_ok());
    assert!(is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-request-id",
        &generated
    ));
    assert!(!is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-request-id",
        "some-other-value"
    ));

    let mut outbound = HashMap::new();
    plugin_utils::assert_continue(plugin.before_proxy(&mut ctx, &mut outbound).await);
    assert_eq!(outbound.get("x-request-id"), Some(&generated));

    let mut response_headers = HashMap::new();
    plugin_utils::assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    assert_eq!(response_headers.get("x-request-id"), Some(&generated));

    let logged = clone_log_metadata(&ctx);
    assert_eq!(logged.get("request_id"), Some(&generated));
    assert!(
        !logged
            .keys()
            .any(|key| key.contains("generated") && key.contains("correlation"))
    );
}

#[tokio::test]
async fn client_supplied_header_is_not_recorded_as_generated() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-request-id".to_string(), "client-fixed-1".to_string());
    plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);

    assert!(!is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-request-id",
        "client-fixed-1"
    ));
    assert_eq!(
        ctx.headers.get("x-request-id").map(String::as_str),
        Some("client-fixed-1")
    );
}

#[tokio::test]
async fn rejected_inbound_value_is_recorded_as_generated() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-request-id".to_string(), "not a token".to_string());
    plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);

    let replacement = ctx
        .headers
        .get("x-request-id")
        .expect("replacement header")
        .clone();
    assert_ne!(replacement, "not a token");
    assert!(is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-request-id",
        &replacement
    ));
}

#[tokio::test]
async fn custom_header_generation_is_instance_scoped() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "x-correlation-id"
    }))
    .unwrap();
    let mut ctx = make_ctx();
    plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);

    let generated = ctx
        .headers
        .get("x-correlation-id")
        .expect("custom generated header")
        .clone();
    assert!(is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-correlation-id",
        &generated
    ));
    assert!(!is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-request-id",
        &generated
    ));
}

#[tokio::test]
async fn public_metadata_cannot_mark_a_client_value_as_generated() {
    let plugin = CorrelationId::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-request-id".to_string(), "client-fixed-1".to_string());
    ctx.metadata
        .insert("correlation_id.generated".to_string(), "true".to_string());
    ctx.metadata.insert(
        "correlation_id.generated.x-request-id".to_string(),
        "true".to_string(),
    );
    plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);

    assert!(!is_gateway_generated_correlation_header_for_test(
        &ctx,
        "x-request-id",
        "client-fixed-1"
    ));
}
