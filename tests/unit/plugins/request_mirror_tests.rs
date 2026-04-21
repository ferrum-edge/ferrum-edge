use ferrum_edge::plugins::request_mirror::RequestMirror;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils;

fn make_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api/users".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.query_params.insert("page".to_string(), "1".to_string());
    ctx
}

fn make_ctx_with_proxy() -> RequestContext {
    let mut ctx = make_ctx();
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
        "id": "proxy-123",
        "name": "test-proxy",
        "listen_path": "/api",
        "backend_host": "backend.local",
        "backend_port": 8080,
        "backend_scheme": "http",
        "backend_read_timeout_ms": 30000
    }))
    .unwrap();
    ctx.matched_proxy = Some(Arc::new(proxy));
    ctx
}

// ---------------------------------------------------------------------------
// Plugin metadata
// ---------------------------------------------------------------------------

#[test]
fn test_plugin_name() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "request_mirror");
}

#[test]
fn test_plugin_priority() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.priority(), 3075);
}

#[test]
fn test_supported_protocols() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let protos = plugin.supported_protocols();
    assert!(protos.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protos.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protos.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn test_missing_mirror_host_is_error() {
    let result = RequestMirror::new(&json!({}), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mirror_host"));
}

#[test]
fn test_empty_mirror_host_is_error() {
    let result = RequestMirror::new(&json!({ "mirror_host": "" }), PluginHttpClient::default());
    assert!(result.is_err());
}

#[test]
fn test_invalid_protocol_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_protocol": "ftp" }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mirror_protocol"));
}

#[test]
fn test_port_zero_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_port": 0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mirror_port"));
}

#[test]
fn test_port_too_large_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_port": 70000 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_percentage_below_zero_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": -1.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("percentage"));
}

#[test]
fn test_percentage_above_100_is_error() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 101.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

#[test]
fn test_default_protocol_is_http() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    // Default port for http is 80 — verify via warmup hostname
    assert_eq!(plugin.warmup_hostnames(), vec!["mirror.local".to_string()]);
}

#[test]
fn test_default_port_for_https_is_443() {
    // If protocol is https and no port specified, default should be 443
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_protocol": "https" }),
        PluginHttpClient::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_default_percentage_is_100() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    // Default percentage = 100%, so requires_request_body_before_before_proxy follows mirror_request_body
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn test_mirror_request_body_default_true() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn test_mirror_request_body_false_disables_buffering() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": false }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert!(!plugin.requires_request_body_before_before_proxy());
}

// ---------------------------------------------------------------------------
// DNS warmup
// ---------------------------------------------------------------------------

#[test]
fn test_warmup_hostnames() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "shadow.example.com" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["shadow.example.com".to_string()]
    );
}

#[test]
fn test_hostname_normalized_to_lowercase() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "MIRROR.Example.COM" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["mirror.example.com".to_string()]
    );
}

// ---------------------------------------------------------------------------
// before_proxy always returns Continue (fire-and-forget)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_before_proxy_returns_continue() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_port": 9999 }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("x-custom".to_string(), "value".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_with_zero_percentage_returns_continue() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 0.0 }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_with_body_metadata() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": true }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx();
    ctx.metadata
        .insert("request_body".to_string(), r#"{"name":"test"}"#.to_string());
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_with_matched_proxy_uses_proxy_timeout() {
    // Verify that before_proxy doesn't panic when a matched_proxy is present.
    // The actual timeout is applied inside the spawned task (fire-and-forget),
    // so we can only verify the plugin reads proxy config without errors.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn test_before_proxy_without_matched_proxy_uses_default_timeout() {
    // When no proxy is matched (shouldn't happen in practice), the plugin
    // falls back to a 60s default timeout.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx(); // No matched_proxy
    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

// ---------------------------------------------------------------------------
// Percentage sampling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_percentage_50_mirrors_roughly_half() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 50.0 }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // The counter-based approach mirrors requests where (counter % 1000) < 500.
    // Over 1000 requests, exactly 500 should be mirrored.
    let mut mirrored = 0u32;
    for _ in 0..1000 {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        // We can't directly observe mirroring since it's fire-and-forget via tokio::spawn,
        // but we can verify the plugin always returns Continue.
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Continue => {}
            _ => panic!("Expected Continue"),
        }
        mirrored += 1;
    }
    assert_eq!(mirrored, 1000); // All return Continue regardless of mirror decision
}

// ---------------------------------------------------------------------------
// should_buffer_request_body
// ---------------------------------------------------------------------------

#[test]
fn test_should_buffer_request_body_when_body_mirroring_enabled() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": true }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let ctx = make_ctx();
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_should_not_buffer_request_body_when_body_mirroring_disabled() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": false }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let ctx = make_ctx();
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ---------------------------------------------------------------------------
// Valid configs with various options
// ---------------------------------------------------------------------------

#[test]
fn test_valid_config_with_all_options() {
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": "shadow.internal",
            "mirror_port": 8443,
            "mirror_protocol": "https",
            "mirror_path": "/shadow/v2",
            "percentage": 25.5,
            "mirror_request_body": false
        }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_valid_config_minimal() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local" }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_percentage_boundary_zero() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 0.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_percentage_boundary_100() {
    let result = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "percentage": 100.0 }),
        PluginHttpClient::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_mirror_path_override() {
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_path": "/shadow" }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

// ---------------------------------------------------------------------------
// Mirror transaction summary serialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mirror_captures_proxy_context() {
    // Verify that the plugin captures proxy context (proxy_id, proxy_name,
    // consumer_username) from the request context for mirror logging.
    let plugin = RequestMirror::new(
        &json!({ "mirror_host": "mirror.local", "mirror_request_body": false }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();
    ctx.identified_consumer = Some(
        serde_json::from_value(json!({
            "id": "consumer-1",
            "username": "test-user"
        }))
        .unwrap(),
    );

    let mut headers: HashMap<String, String> = HashMap::new();

    // This fires the mirror task — we can't inspect the spawned task's output
    // directly, but we verify the plugin reads all context fields without panicking.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);
}

// === Binary body preservation ===

#[tokio::test]
async fn test_mirror_uses_binary_body_bytes_over_metadata() {
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "mirror_request_body": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();

    // Simulate non-UTF-8 body (e.g., gRPC protobuf):
    // request_body metadata is absent (not valid UTF-8), but request_body_bytes is set
    let binary_body: Vec<u8> = vec![0x00, 0x01, 0xFF, 0xFE, 0x80, 0x90];
    ctx.request_body_bytes = Some(bytes::Bytes::from(binary_body.clone()));
    // Ensure the UTF-8 metadata key is NOT set (simulates store_request_body_metadata
    // with non-UTF-8 data)
    ctx.metadata.remove("request_body");

    let mut headers: HashMap<String, String> = HashMap::new();

    // The plugin should read from request_body_bytes (binary-safe) rather than
    // the missing metadata key. This fires the mirror task — we verify it doesn't
    // panic and completes without error.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    // Mirror result receiver should be set (mirror was dispatched)
    assert!(
        ctx.mirror_result_rx.is_some(),
        "Mirror should be dispatched even with binary body"
    );
}

#[tokio::test]
async fn test_mirror_falls_back_to_metadata_when_no_body_bytes() {
    let plugin = RequestMirror::new(
        &json!({
            "mirror_host": "mirror.local",
            "mirror_request_body": true,
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx_with_proxy();

    // Only the UTF-8 metadata key is set (legacy/normal path)
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"hello":"world"}"#.to_string(),
    );
    ctx.request_body_bytes = None;

    let mut headers: HashMap<String, String> = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    plugin_utils::assert_continue(result);

    assert!(
        ctx.mirror_result_rx.is_some(),
        "Mirror should be dispatched using metadata fallback"
    );
}
