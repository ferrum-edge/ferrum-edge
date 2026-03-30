//! Tests for the Correlation ID plugin

use ferrum_edge::plugins::correlation_id::{CORRELATION_ID_PRIORITY, CorrelationId};
use ferrum_edge::plugins::{Plugin, RequestContext};
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

// ── Plugin identity ─────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = CorrelationId::new(&json!({}));
    assert_eq!(plugin.name(), "correlation_id");
}

#[test]
fn test_plugin_priority() {
    let plugin = CorrelationId::new(&json!({}));
    assert_eq!(plugin.priority(), CORRELATION_ID_PRIORITY);
    assert_eq!(plugin.priority(), 50);
}

#[test]
fn test_modifies_request_headers() {
    let plugin = CorrelationId::new(&json!({}));
    assert!(plugin.modifies_request_headers());
}

// ── Default configuration ───────────────────────────────────────────

#[tokio::test]
async fn test_default_config_uses_x_request_id_header() {
    // Default header_name should be "x-request-id" — verify by running the plugin
    // and checking that it inserts the correlation ID into the correct header
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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

// ── Custom header name ──────────────────────────────────────────────

#[tokio::test]
async fn test_custom_header_name() {
    let plugin = CorrelationId::new(&json!({
        "header_name": "X-Correlation-ID"
    }));
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
    }));
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
    }));
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
    }));
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
    }));
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
    }));
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
    }));
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
    let plugin = CorrelationId::new(&json!({}));
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
    let plugin = CorrelationId::new(&json!({}));
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
    }));
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
    let plugin = CorrelationId::new(&json!({}));

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
    }));
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
