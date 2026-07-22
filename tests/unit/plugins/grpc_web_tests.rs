use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::plugins::grpc_web::{GRPC_WEB_CONFIG_KEYS, GrpcWebPlugin};
use ferrum_edge::plugins::security_headers::SecurityHeaders;
use ferrum_edge::plugins::{
    BufferedInitialResponseHeaderPolicyState, HTTP_GRPC_PROTOCOLS, Plugin, PluginFailurePolicy,
    PluginResult, create_plugin, plugin_failure_policy, priority, validate_plugin_config,
};
use ferrum_edge::proxy::grpc_proxy;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

use super::plugin_utils::create_test_context;

fn create_grpc_web_context(content_type: &str) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = "/my.Service/MyMethod".to_string();
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    ctx
}

fn create_plugin_default() -> std::sync::Arc<dyn Plugin> {
    create_plugin("grpc_web", &json!({})).unwrap().unwrap()
}

fn grpc_web_trailer_payload(body: &[u8]) -> String {
    assert!(
        body.len() >= 5,
        "gRPC-Web trailer frame must include header"
    );
    assert_eq!(body[0], ferrum_edge::_test_support::GRPC_FRAME_TRAILER);
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert_eq!(body.len(), 5 + len);
    String::from_utf8(body[5..].to_vec()).unwrap()
}

fn trailing_grpc_web_trailer_payload(body: &[u8]) -> String {
    let flag_pos = body
        .iter()
        .rposition(|byte| *byte == ferrum_edge::_test_support::GRPC_FRAME_TRAILER)
        .expect("trailing gRPC-Web trailer frame");
    grpc_web_trailer_payload(&body[flag_pos..])
}

// ── Plugin creation ──

#[test]
fn test_plugin_creation_default() {
    let plugin = create_plugin_default();
    assert_eq!(plugin.name(), "grpc_web");
    assert_eq!(plugin.priority(), priority::GRPC_WEB);
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_plugin_creation_with_expose_headers() {
    let config = json!({
        "expose_headers": ["custom-header-bin", "x-request-id"]
    });
    let plugin = create_plugin("grpc_web", &config).unwrap().unwrap();
    assert_eq!(plugin.name(), "grpc_web");
}

#[test]
fn test_invalid_expose_headers_rejected() {
    for config in [
        json!({"expose_headers": "x-request-id"}),
        json!({"expose_headers": [42]}),
        json!({"expose_headers": [""]}),
        json!({"expose_headers": ["bad header"]}),
    ] {
        let err = create_plugin("grpc_web", &config)
            .err()
            .expect("invalid expose_headers config must be rejected");
        assert!(err.contains("expose_headers"), "got: {err}");
    }
}

#[test]
fn test_config_must_be_an_object_for_every_json_value_class() {
    // Explicit null is rejected (not an alias for {}). Build-out policy prefers
    // a strict object contract over silent defaulting.
    for config in [
        json!(null),
        json!([]),
        json!("expose_headers: [x-request-id]"),
        json!(42),
        json!(3.5),
        json!(true),
        json!(false),
    ] {
        let err = GrpcWebPlugin::new(&config)
            .err()
            .unwrap_or_else(|| panic!("non-object must be rejected: {config}"));
        assert_eq!(err, "grpc_web: config must be an object", "got: {err}");
        let shared = validate_plugin_config("grpc_web", &config)
            .expect_err("shared admission must reject the same non-object");
        assert_eq!(shared, "grpc_web: config must be an object");
    }
}

#[test]
fn test_valid_empty_and_full_objects_are_accepted() {
    GrpcWebPlugin::new(&json!({})).expect("empty object must preserve default expose list");
    GrpcWebPlugin::new(&json!({
        "expose_headers": ["custom-header-bin", "x-request-id"]
    }))
    .expect("full object must be accepted");
    validate_plugin_config("grpc_web", &json!({})).expect("shared admission accepts {}");
    validate_plugin_config("grpc_web", &json!({"expose_headers": ["x-request-id"]}))
        .expect("shared admission accepts a full object");
    assert_eq!(
        plugin_failure_policy("grpc_web"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
}

#[test]
fn test_unknown_keys_rejected_with_path_qualified_suggestions() {
    let err = GrpcWebPlugin::new(&json!({"expose_header": ["x-request-id"]}))
        .err()
        .expect("singular/plural typo must be rejected");
    assert_eq!(
        err,
        "grpc_web: unknown configuration key(s): 'config.expose_header' (did you mean 'expose_headers'?)"
    );

    let err = GrpcWebPlugin::new(&json!({
        "z_unknown": true,
        "expose_headers": ["x-request-id"],
        "a_unknown": false,
        "expose_headerz": []
    }))
    .err()
    .expect("multiple unknown keys must be rejected deterministically");
    assert_eq!(
        err,
        "grpc_web: unknown configuration key(s): 'config.a_unknown', 'config.expose_headerz' (did you mean 'expose_headers'?), 'config.z_unknown'"
    );
    assert_eq!(GRPC_WEB_CONFIG_KEYS, &["expose_headers"]);
}

#[test]
fn test_shared_admin_file_and_snapshot_admission_reject_invalid_shapes() {
    let typo = json!({"expose_header": ["x-request-id"]});
    let shared = validate_plugin_config("grpc_web", &typo)
        .expect_err("shared validate_plugin_config must reject typos");
    assert!(shared.contains("config.expose_header"), "got: {shared}");
    assert!(
        shared.contains("did you mean 'expose_headers'"),
        "got: {shared}"
    );

    let now = chrono::Utc::now();
    let plugin_config = ferrum_edge::config::types::PluginConfig {
        id: "grpc-web-admin".to_string(),
        plugin_name: "grpc_web".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: typo.clone(),
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };
    let admin = ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config)
        .expect_err("admin validation must reject unknown keys");
    assert!(admin.contains("config.expose_header"), "got: {admin}");

    let directory = TempDir::new().unwrap();
    let config_path = directory.path().join("grpc-web-bad.json");
    let file_config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc",
            "listen_path": "/",
            "backend_host": "127.0.0.1",
            "backend_port": 9000
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": "grpc-web",
            "plugin_name": "grpc_web",
            "config": typo,
            "scope": "global",
            "enabled": true
        }]
    });
    std::fs::write(&config_path, serde_json::to_vec(&file_config).unwrap()).unwrap();
    let file_err = load_config_from_file(
        config_path.to_str().expect("utf-8 temp path"),
        30,
        &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        "ferrum",
    )
    .expect_err("file mode must reject unknown grpc_web keys");
    assert!(
        file_err.to_string().contains("1 plugin config error(s)"),
        "got: {file_err}"
    );

    // Database / CP / DP snapshot admission all call validate_plugin_config
    // through the shared constructor — pin that surface for non-object null too.
    let null_err = validate_plugin_config("grpc_web", &json!(null))
        .expect_err("CP-DP/database snapshot admission must reject null");
    assert_eq!(null_err, "grpc_web: config must be an object");
}

// ── on_request_received — detection and header rewriting ──

#[tokio::test]
async fn test_detects_grpc_web_binary() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    assert_eq!(ctx.metadata.get("grpc_web_mode").unwrap(), "binary");
    assert_eq!(
        ctx.metadata.get("grpc_web_original_ct").unwrap(),
        "application/grpc-web"
    );
    assert_eq!(ctx.headers.get("content-type").unwrap(), "application/grpc");
}

#[tokio::test]
async fn test_may_modify_response_content_type_tracks_grpc_web_request() {
    let plugin = create_plugin_default();

    // A gRPC-Web request records its original content-type in
    // on_request_received; after_proxy relabels the response back to the
    // gRPC-Web variant, so the proxy must keep the body buffered for
    // final-response inspection rather than trusting the backend's
    // application/grpc header.
    let mut ctx = create_grpc_web_context("application/grpc-web");
    let _ = plugin.on_request_received(&mut ctx).await;
    // The marker is the precise signal; the backend response type is irrelevant
    // (the relabel keys off the recorded request content-type).
    assert!(plugin.may_modify_response_content_type(&ctx, Some("application/grpc")));

    // A non-gRPC-Web request records no marker, so no relabel will occur.
    let plain = create_test_context();
    assert!(!plugin.may_modify_response_content_type(&plain, Some("application/grpc")));
}

#[tokio::test]
async fn test_response_buffering_only_for_grpc_web_requests() {
    let plugin = create_plugin_default();

    let native = create_grpc_web_context("application/grpc");
    assert!(!plugin.should_buffer_response_body(&native));

    let http = create_grpc_web_context("application/json");
    assert!(!plugin.should_buffer_response_body(&http));

    let mut grpc_web = create_grpc_web_context("application/grpc-web");
    let result = plugin.on_request_received(&mut grpc_web).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&grpc_web));

    let mut grpc_web_text = create_grpc_web_context("application/grpc-web-text");
    let result = plugin.on_request_received(&mut grpc_web_text).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.should_buffer_response_body(&grpc_web_text));
}

#[tokio::test]
async fn test_translated_error_response_binary_uses_grpc_web_trailer_frame() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web+proto");
    plugin.on_request_received(&mut ctx).await;

    let response =
        ferrum_edge::plugins::grpc_web::translated_error_response(&ctx, 14, "blocked").unwrap();

    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/grpc-web+proto")
    );
    assert_eq!(
        response.headers.get("x-grpc-web").map(String::as_str),
        Some("1")
    );
    assert!(!response.headers.contains_key("grpc-status"));
    assert!(!response.headers.contains_key("grpc-message"));
    assert_eq!(
        response
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("grpc-status, grpc-message, grpc-status-details-bin")
    );
    let payload = grpc_web_trailer_payload(&response.body);
    assert!(payload.contains("grpc-status: 14\r\n"));
    assert!(payload.contains("grpc-message: blocked\r\n"));
}

#[tokio::test]
async fn test_translated_error_response_text_base64_encodes_trailer_frame() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text");
    plugin.on_request_received(&mut ctx).await;

    let response =
        ferrum_edge::plugins::grpc_web::translated_error_response(&ctx, 14, "blocked").unwrap();

    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/grpc-web-text")
    );
    assert_eq!(
        response.headers.get("x-grpc-web").map(String::as_str),
        Some("1")
    );
    assert!(!response.headers.contains_key("grpc-status"));
    assert!(!response.headers.contains_key("grpc-message"));
    let decoded = BASE64.decode(&response.body).unwrap();
    let payload = grpc_web_trailer_payload(&decoded);
    assert!(payload.contains("grpc-status: 14\r\n"));
    assert!(payload.contains("grpc-message: blocked\r\n"));
}

#[test]
fn test_error_response_for_content_type_text_base64_encodes_trailer_frame() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let response = ferrum_edge::plugins::grpc_web::error_response_for_content_type(
        "application/grpc-web-text",
        14,
        "blocked",
    );

    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/grpc-web-text")
    );
    assert_eq!(
        response.headers.get("x-grpc-web").map(String::as_str),
        Some("1")
    );
    assert!(!response.headers.contains_key("grpc-status"));
    assert!(!response.headers.contains_key("grpc-message"));
    let decoded = BASE64.decode(&response.body).unwrap();
    let payload = grpc_web_trailer_payload(&decoded);
    assert!(payload.contains("grpc-status: 14\r\n"));
    assert!(payload.contains("grpc-message: blocked\r\n"));
}

#[tokio::test]
async fn test_detects_grpc_web_binary_proto() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web+proto");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    assert_eq!(ctx.metadata.get("grpc_web_mode").unwrap(), "binary");
    assert_eq!(ctx.headers.get("content-type").unwrap(), "application/grpc");
}

#[tokio::test]
async fn test_detects_grpc_web_text() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    assert_eq!(ctx.metadata.get("grpc_web_mode").unwrap(), "text");
    assert_eq!(ctx.headers.get("content-type").unwrap(), "application/grpc");
}

#[tokio::test]
async fn test_detects_grpc_web_text_proto() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text+proto");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    assert_eq!(ctx.metadata.get("grpc_web_mode").unwrap(), "text");
}

#[tokio::test]
async fn test_ignores_native_grpc() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    // Should NOT be marked as gRPC-Web
    assert!(!ctx.metadata.contains_key("grpc_web_mode"));
    // Content-type should remain unchanged
    assert_eq!(ctx.headers.get("content-type").unwrap(), "application/grpc");
}

#[tokio::test]
async fn test_ignores_non_grpc() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/json");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("grpc_web_mode"));
}

#[tokio::test]
async fn test_ignores_missing_content_type() {
    let plugin = create_plugin_default();
    let mut ctx = create_test_context();
    ctx.headers.remove("content-type");

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("grpc_web_mode"));
}

// Regression: a client could spoof the internal `x-grpc-web-mode` header to
// trigger base64 decoding of a non-gRPC-Web request body. The plugin must
// strip the inbound header unconditionally; only `before_proxy` may inject
// it after a content-type-based detection.
#[tokio::test]
async fn test_strips_client_supplied_x_grpc_web_mode_for_non_grpc_web() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/json");
    ctx.headers
        .insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !ctx.headers.contains_key("x-grpc-web-mode"),
        "client-supplied x-grpc-web-mode must be removed before backend dispatch"
    );
    assert!(
        !ctx.metadata.contains_key("grpc_web_mode"),
        "non-grpc-web request must not be flagged as grpc-web"
    );
}

// Regression: end-to-end verification that a spoofed `x-grpc-web-mode: text`
// on a non-gRPC-Web content-type does NOT trigger base64-decoding of the
// request body in `transform_request_body`. Even if a client plants the
// internal marker alongside an `application/json` body, the strip in
// `on_request_received` must ensure the header never reaches downstream
// phases, so base64 is never attempted on non-gRPC-Web bodies (which would
// turn them into garbage that backends would reject or mis-parse).
#[tokio::test]
async fn test_spoofed_x_grpc_web_mode_does_not_base64_decode_non_grpc_web_body() {
    use base64::Engine;
    let plugin = create_plugin_default();

    // A valid-looking base64 JSON body the attacker wants decoded
    let json_body = br#"{"user":"alice","action":"delete"}"#;
    let base64_body = base64::engine::general_purpose::STANDARD.encode(json_body);

    let mut ctx = create_grpc_web_context("application/json");
    ctx.headers
        .insert("x-grpc-web-mode".to_string(), "text".to_string());

    // on_request_received must strip the spoofed header and NOT mark the
    // request as gRPC-Web, since the content-type is JSON.
    plugin.on_request_received(&mut ctx).await;
    assert!(!ctx.headers.contains_key("x-grpc-web-mode"));
    assert!(!ctx.metadata.contains_key("grpc_web_mode"));

    // Simulate the downstream dispatch: `before_proxy` sees no
    // `grpc_web_mode` in metadata, so it doesn't re-inject the header.
    let mut outgoing = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut outgoing).await;
    assert!(
        !outgoing.contains_key("x-grpc-web-mode"),
        "before_proxy must not re-inject the marker for non-gRPC-Web requests"
    );

    // `transform_request_body` receives the outgoing headers — with the
    // marker absent, it must NOT attempt base64 decoding.
    let decoded = plugin
        .transform_request_body(base64_body.as_bytes(), Some("application/json"), &outgoing)
        .await;
    assert!(
        decoded.is_none(),
        "transform_request_body must leave non-gRPC-Web bodies untouched, got: {decoded:?}"
    );
}

#[tokio::test]
async fn test_strips_client_supplied_x_grpc_web_mode_then_redetects() {
    // Client sends a real grpc-web-text request AND a misleading marker — plugin
    // should ignore the client's marker, detect via content-type, and re-inject
    // its own marker in before_proxy.
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text");
    ctx.headers
        .insert("x-grpc-web-mode".to_string(), "binary".to_string());

    plugin.on_request_received(&mut ctx).await;
    // Content-type-based detection wins
    assert_eq!(ctx.metadata.get("grpc_web_mode").unwrap(), "text");

    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text".to_string(),
    );
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-grpc-web-mode").unwrap(), "text");
}

// ── before_proxy — outgoing header rewriting ──

#[tokio::test]
async fn test_before_proxy_rewrites_headers() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );
    headers.insert("x-grpc-web".to_string(), "1".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
    // x-grpc-web request header stripped
    assert!(!headers.contains_key("x-grpc-web"));
    // Mode marker injected for transform_request_body
    assert_eq!(headers.get("x-grpc-web-mode").unwrap(), "binary");
}

#[tokio::test]
async fn test_before_proxy_injects_text_mode_marker() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text");
    plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(headers.get("x-grpc-web-mode").unwrap(), "text");
}

#[tokio::test]
async fn test_before_proxy_noop_for_non_grpc_web() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc");
    // Don't call on_request_received — metadata not set

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
    // No mode marker should be injected
    assert!(!headers.contains_key("x-grpc-web-mode"));
}

// ── should_buffer_request_body ──

#[test]
fn test_buffer_request_body_text_mode() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text");

    // Simulate on_request_received setting metadata
    ctx.metadata
        .insert("grpc_web_mode".to_string(), "text".to_string());

    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_no_buffer_request_body_binary_mode() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");

    ctx.metadata
        .insert("grpc_web_mode".to_string(), "binary".to_string());

    assert!(!plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_no_buffer_request_body_no_metadata() {
    let plugin = create_plugin_default();
    let ctx = create_grpc_web_context("application/grpc");

    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ── transform_request_body — base64 decoding ──

#[tokio::test]
async fn test_transform_request_body_base64_decode() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let plugin = create_plugin_default();

    // Build a valid gRPC frame: flag=0x00, length=5, payload="hello"
    let mut grpc_frame = vec![0x00u8];
    grpc_frame.extend_from_slice(&5u32.to_be_bytes());
    grpc_frame.extend_from_slice(b"hello");

    // Base64-encode it (simulating gRPC-Web text mode)
    let encoded = BASE64.encode(&grpc_frame);

    // Mode marker from before_proxy tells transform_request_body it's text mode
    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin
        .transform_request_body(encoded.as_bytes(), Some("application/grpc"), &headers)
        .await;

    assert!(result.is_some());
    assert_eq!(result.unwrap(), grpc_frame);
}

#[tokio::test]
async fn test_transform_request_body_binary_passthrough() {
    let plugin = create_plugin_default();

    // Binary gRPC frame — should not be transformed (mode is "binary")
    let mut grpc_frame = vec![0x00u8];
    grpc_frame.extend_from_slice(&5u32.to_be_bytes());
    grpc_frame.extend_from_slice(b"hello");

    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "binary".to_string());

    let result = plugin
        .transform_request_body(&grpc_frame, Some("application/grpc"), &headers)
        .await;

    // Binary mode: no transformation
    assert!(result.is_none());
}

#[tokio::test]
async fn test_transform_request_body_no_mode_header() {
    let plugin = create_plugin_default();

    let body = b"some data";
    let headers = HashMap::new(); // No x-grpc-web-mode header

    let result = plugin
        .transform_request_body(body, Some("application/grpc"), &headers)
        .await;

    // Not a gRPC-Web request — no transformation
    assert!(result.is_none());
}

#[tokio::test]
async fn test_transform_request_body_invalid_base64_returns_none() {
    let plugin = create_plugin_default();

    // Invalid base64 data in text mode
    let body = b"not!!!valid===base64";
    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin
        .transform_request_body(body, Some("application/grpc"), &headers)
        .await;

    // Returns None — on_final_request_body will catch the invalid framing
    assert!(result.is_none());
}

#[tokio::test]
async fn test_transform_request_body_empty() {
    let plugin = create_plugin_default();
    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin
        .transform_request_body(&[], Some("application/grpc"), &headers)
        .await;

    assert!(result.is_none());
}

// ── on_final_request_body — validation ──

#[tokio::test]
async fn test_final_request_body_valid_grpc_framing() {
    let plugin = create_plugin_default();

    let mut body = vec![0x00u8]; // data frame flag
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");

    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin.on_final_request_body(&headers, &body).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_rejects_too_short() {
    let plugin = create_plugin_default();

    let body = b"abc"; // Too short for gRPC framing (needs >= 5 bytes)

    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin.on_final_request_body(&headers, body).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 400,
            ..
        }
    ));
}

#[tokio::test]
async fn test_final_request_body_rejects_invalid_flag() {
    let plugin = create_plugin_default();

    let mut body = vec![0x42u8]; // Invalid flag byte (not 0x00 or 0x80)
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");

    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "text".to_string());

    let result = plugin.on_final_request_body(&headers, &body).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 400,
            ..
        }
    ));
}

#[tokio::test]
async fn test_final_request_body_skips_binary_mode() {
    let plugin = create_plugin_default();

    let body = b"anything"; // Invalid gRPC framing, but binary mode skips validation

    let mut headers = HashMap::new();
    headers.insert("x-grpc-web-mode".to_string(), "binary".to_string());

    let result = plugin.on_final_request_body(&headers, body).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_skips_non_grpc_web() {
    let plugin = create_plugin_default();

    let body = b"anything";
    let headers = HashMap::new(); // No mode header

    let result = plugin.on_final_request_body(&headers, body).await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── after_proxy — response header rewriting ──

#[tokio::test]
async fn test_after_proxy_rewrites_content_type_binary() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert("grpc-status".to_string(), "0".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        response_headers.get("content-type").unwrap(),
        "application/grpc-web"
    );
    // x-grpc-web response header signals gRPC-Web to clients
    assert_eq!(response_headers.get("x-grpc-web").unwrap(), "1");
}

#[tokio::test]
async fn test_after_proxy_rewrites_content_type_text() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text+proto");
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        response_headers.get("content-type").unwrap(),
        "application/grpc-web-text+proto"
    );
}

#[tokio::test]
async fn test_preserved_statuses_keep_native_headers_and_release_buffering() {
    let plugin = create_plugin_default();

    for status in [206, 226] {
        let mut ctx = create_grpc_web_context("application/grpc-web-text+proto");
        plugin.on_request_received(&mut ctx).await;
        let mut response_headers = HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("content-length".to_string(), "17".to_string()),
        ]);

        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/grpc"),
            status,
            &response_headers
        ));
        assert!(
            plugin.should_release_response_body_before_content_type_rewrite(
                &ctx,
                status,
                &response_headers
            )
        );
        assert!(matches!(
            plugin
                .after_proxy(&mut ctx, status, &mut response_headers)
                .await,
            PluginResult::Continue
        ));
        assert_eq!(
            response_headers.get("content-type").map(String::as_str),
            Some("application/grpc")
        );
        assert_eq!(
            response_headers.get("content-length").map(String::as_str),
            Some("17")
        );
        assert!(!response_headers.contains_key("x-grpc-web"));
        assert!(!response_headers.contains_key("access-control-expose-headers"));
    }
}

#[tokio::test]
async fn test_after_proxy_noop_for_non_grpc_web() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc");
    // metadata not set — not a grpc-web request

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    // Should remain unchanged
    assert_eq!(
        response_headers.get("content-type").unwrap(),
        "application/grpc"
    );
}

#[tokio::test]
async fn test_after_proxy_sets_expose_headers_when_backend_omits_them() {
    // Regression test: previously, after_proxy only added expose-headers when
    // the backend response already contained the header. That left browsers
    // unable to read grpc-status/grpc-message on backends without CORS config.
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert("grpc-status".to_string(), "0".to_string());

    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    let expose = response_headers
        .get("access-control-expose-headers")
        .expect("access-control-expose-headers must be set");
    assert!(expose.contains("grpc-status"));
    assert!(expose.contains("grpc-message"));
    assert!(expose.contains("grpc-status-details-bin"));
}

#[tokio::test]
async fn test_after_proxy_merges_expose_headers_with_existing() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert(
        "access-control-expose-headers".to_string(),
        "x-trace-id".to_string(),
    );

    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    let expose = response_headers
        .get("access-control-expose-headers")
        .expect("access-control-expose-headers must be set");
    assert!(expose.contains("x-trace-id"), "should preserve existing");
    assert!(expose.contains("grpc-status"), "should add grpc-status");
    assert!(expose.contains("grpc-message"), "should add grpc-message");
}

#[tokio::test]
async fn test_after_proxy_does_not_duplicate_existing_grpc_status_token() {
    // Token-based dedup: don't add "grpc-status" if it's already a token in the
    // existing list. The previous substring-based check would falsely match
    // "grpc-status" inside "grpc-status-details-bin" — token-based avoids that.
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert(
        "access-control-expose-headers".to_string(),
        "grpc-status, grpc-message".to_string(),
    );

    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    let expose = response_headers
        .get("access-control-expose-headers")
        .expect("access-control-expose-headers must be set");
    let count = expose
        .split(',')
        .filter(|tok| tok.trim().eq_ignore_ascii_case("grpc-status"))
        .count();
    assert_eq!(
        count, 1,
        "grpc-status must not be duplicated, got: {expose}"
    );
}

// ── transform_response_body — trailer embedding and encoding ──

#[tokio::test]
async fn test_transform_response_body_binary() {
    let plugin = create_plugin_default();

    // Simulate a gRPC response data frame
    let mut body = vec![0x00u8];
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );
    response_headers.insert("grpc-status".to_string(), "0".to_string());
    response_headers.insert("grpc-message".to_string(), "OK".to_string());

    let result = plugin
        .transform_response_body(&body, Some("application/grpc-web"), &response_headers)
        .await;

    assert!(result.is_some());
    let output = result.unwrap();

    // Output should start with the original data frame
    assert_eq!(&output[..10], &body[..]);

    // Followed by a trailer frame (flag=0x80)
    assert_eq!(output[10], 0x80);

    // Parse trailer frame
    let trailer_len = u32::from_be_bytes([output[11], output[12], output[13], output[14]]) as usize;
    let trailer_str = String::from_utf8_lossy(&output[15..15 + trailer_len]);
    assert!(trailer_str.contains("grpc-status: 0"));
    assert!(trailer_str.contains("grpc-message: OK"));
}

#[tokio::test]
async fn test_transform_response_body_text() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let plugin = create_plugin_default();

    // Simulate a gRPC response data frame
    let mut body = vec![0x00u8];
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text".to_string(),
    );
    response_headers.insert("grpc-status".to_string(), "0".to_string());

    let result = plugin
        .transform_response_body(&body, Some("application/grpc-web-text"), &response_headers)
        .await;

    assert!(result.is_some());
    let output = result.unwrap();

    // Output should be base64-encoded
    let decoded = BASE64.decode(&output).expect("Should be valid base64");

    // Decoded should start with original data frame
    assert_eq!(&decoded[..10], &body[..]);

    // Followed by trailer frame
    assert_eq!(decoded[10], 0x80);
}

#[tokio::test]
async fn test_transform_response_body_noop_for_non_grpc_web() {
    let plugin = create_plugin_default();

    let body = b"some response";
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());

    let result = plugin
        .transform_response_body(body, Some("application/grpc"), &response_headers)
        .await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_transform_response_body_no_content_type() {
    let plugin = create_plugin_default();

    let body = b"some response";
    let response_headers = HashMap::new();

    let result = plugin
        .transform_response_body(body, None, &response_headers)
        .await;

    assert!(result.is_none());
}

// ── Protocol support ──

#[test]
fn test_supported_protocols() {
    let plugin = create_plugin_default();
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
}

// ── Trait flags ──

#[test]
fn test_modifies_request_headers() {
    let plugin = create_plugin_default();
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_modifies_request_body() {
    let plugin = create_plugin_default();
    assert!(plugin.modifies_request_body());
}

#[test]
fn test_requires_response_body_buffering() {
    let plugin = create_plugin_default();
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());
    assert!(!plugin.applies_after_proxy_on_reject());
}

// ── End-to-end flow ──

#[tokio::test]
async fn test_full_roundtrip_binary() {
    let plugin = create_plugin_default();

    // 1. Request arrives as gRPC-Web binary
    let mut ctx = create_grpc_web_context("application/grpc-web+proto");
    plugin.on_request_received(&mut ctx).await;
    assert_eq!(ctx.headers.get("content-type").unwrap(), "application/grpc");

    // 2. before_proxy sets outgoing headers and injects mode marker
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
    assert_eq!(headers.get("x-grpc-web-mode").unwrap(), "binary");

    // 3. Response comes back from backend
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/grpc".to_string());
    response_headers.insert("grpc-status".to_string(), "0".to_string());
    response_headers.insert("grpc-message".to_string(), "".to_string());

    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("content-type").unwrap(),
        "application/grpc-web+proto"
    );

    // 4. Response body gets trailer frame appended
    let mut body = vec![0x00u8];
    body.extend_from_slice(&3u32.to_be_bytes());
    body.extend_from_slice(b"abc");

    let result = plugin
        .transform_response_body(&body, Some("application/grpc-web+proto"), &response_headers)
        .await;
    assert!(result.is_some());
    let output = result.unwrap();

    // Verify data frame preserved
    assert_eq!(&output[..8], &body[..]);
    // Verify trailer frame appended
    assert_eq!(output[8], 0x80);
}

#[tokio::test]
async fn test_full_roundtrip_text() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let plugin = create_plugin_default();

    // 1. Build a gRPC-Web text request body
    let mut grpc_frame = vec![0x00u8];
    grpc_frame.extend_from_slice(&3u32.to_be_bytes());
    grpc_frame.extend_from_slice(b"abc");
    let encoded_request = BASE64.encode(&grpc_frame);

    // 2. Request arrives as gRPC-Web text
    let mut ctx = create_grpc_web_context("application/grpc-web-text");
    plugin.on_request_received(&mut ctx).await;
    assert_eq!(ctx.metadata.get("grpc_web_mode").unwrap(), "text");

    // 3. before_proxy injects mode marker, then request body gets base64-decoded
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-grpc-web-mode").unwrap(), "text");

    let decoded = plugin
        .transform_request_body(
            encoded_request.as_bytes(),
            Some("application/grpc"),
            &headers,
        )
        .await;
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), grpc_frame);

    // 4. Response comes back, gets text-encoded with trailers
    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text".to_string(),
    );
    response_headers.insert("grpc-status".to_string(), "0".to_string());

    let response_body = plugin
        .transform_response_body(
            &grpc_frame,
            Some("application/grpc-web-text"),
            &response_headers,
        )
        .await;
    assert!(response_body.is_some());

    // Verify base64 encoding
    let output = response_body.unwrap();
    let decoded_response = BASE64.decode(&output).expect("Should be valid base64");
    // Data frame + trailer frame
    assert_eq!(&decoded_response[..8], &grpc_frame[..]);
    assert_eq!(decoded_response[8], 0x80); // trailer flag
}

// ── Internal helper tests (moved from src/plugins/grpc_web.rs) ───────────────

#[test]
fn test_is_grpc_web_content_type() {
    use ferrum_edge::_test_support::is_grpc_web_content_type;
    for content_type in [
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/grpc-web+json",
        "application/grpc-web-text",
        "application/grpc-web-text+proto",
        "application/grpc-web-text+custom",
        "  Application/gRPC-Web  ",
        "application/grpc-web; charset=utf-8",
        "application/grpc-web-text+proto \t; charset = \"utf-8\"; version=1",
    ] {
        assert!(
            is_grpc_web_content_type(content_type),
            "valid gRPC-Web media type was rejected: {content_type}"
        );
    }

    for content_type in [
        "application/grpc",
        "application/json",
        "application/grpc-website",
        "application/grpc-web-textual",
        "application/grpc-web+",
        "application/grpc-web++proto",
        "application/grpc-web/extra",
        "application/grpc-web;",
        "application/grpc-web; charset",
        "application/grpc-web; charset=\"unterminated",
    ] {
        assert!(
            !is_grpc_web_content_type(content_type),
            "deceptive or malformed media type was accepted: {content_type}"
        );
    }
}

#[test]
fn test_is_grpc_web_text() {
    use ferrum_edge::_test_support::is_grpc_web_text;
    assert!(is_grpc_web_text("application/grpc-web-text"));
    assert!(is_grpc_web_text("application/grpc-web-text+proto"));
    assert!(is_grpc_web_text(
        " Application/Grpc-Web-Text+json ; charset=utf-8 "
    ));
    assert!(!is_grpc_web_text("application/grpc-web"));
    assert!(!is_grpc_web_text("application/grpc-web+proto"));
    assert!(!is_grpc_web_text("application/grpc-web-textual"));
}

#[test]
fn test_response_content_type() {
    use ferrum_edge::_test_support::response_content_type;
    assert_eq!(
        response_content_type("application/grpc-web"),
        "application/grpc-web"
    );
    assert_eq!(
        response_content_type("application/grpc-web+proto"),
        "application/grpc-web+proto"
    );
    assert_eq!(
        response_content_type("application/grpc-web-text"),
        "application/grpc-web-text"
    );
    assert_eq!(
        response_content_type("application/grpc-web-text+proto"),
        "application/grpc-web-text+proto"
    );
    assert_eq!(
        response_content_type("Application/Grpc-Web-Text+Proto"),
        "application/grpc-web-text+proto"
    );
    assert_eq!(
        response_content_type("Application/Grpc-Web+Proto ; charset=utf-8"),
        "application/grpc-web+proto"
    );
    assert_eq!(
        response_content_type("application/grpc-web-text+json; charset=utf-8"),
        "application/grpc-web-text"
    );
    assert_eq!(
        response_content_type("application/grpc-website"),
        "application/grpc-web",
        "unrecognized values must never be reflected"
    );
}

#[test]
fn test_build_trailer_frame() {
    use ferrum_edge::_test_support::{GRPC_FRAME_TRAILER, build_trailer_frame};
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "0".to_string());
    headers.insert("grpc-message".to_string(), "OK".to_string());
    headers.insert("content-type".to_string(), "application/grpc".to_string());

    let frame = build_trailer_frame(&headers);

    assert_eq!(frame[0], GRPC_FRAME_TRAILER);
    let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    assert_eq!(frame.len(), 5 + len);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 0"));
    assert!(trailer_str.contains("grpc-message: OK"));
    assert!(!trailer_str.contains("content-type"));
}

#[test]
fn test_build_trailer_frame_preserves_ascii_custom_and_bin_metadata() {
    use ferrum_edge::_test_support::build_trailer_frame;
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "0".to_string());
    headers.insert("request-id".to_string(), "abc-123".to_string());
    headers.insert("quota-remaining".to_string(), "7".to_string());
    headers.insert("trace-proto-bin".to_string(), "AQID".to_string());
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("x-grpc-web".to_string(), "1".to_string());
    headers.insert(
        "proxy-authenticate".to_string(),
        "Basic realm=x".to_string(),
    );
    headers.insert("connection".to_string(), "close".to_string());
    headers.insert("keep-alive".to_string(), "timeout=5".to_string());
    // Connection-listed smuggling attempt: nominate a custom name via Connection.
    headers.insert("Connection".to_string(), "x-connection-listed".to_string());
    headers.insert("x-connection-listed".to_string(), "leak".to_string());
    headers.insert(":status".to_string(), "200".to_string());
    headers.insert("bad header".to_string(), "nope".to_string());
    headers.insert("x-bad".to_string(), "line\r\ninject".to_string());

    let frame = build_trailer_frame(&headers);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 0"));
    assert!(trailer_str.contains("request-id: abc-123"));
    assert!(trailer_str.contains("quota-remaining: 7"));
    assert!(trailer_str.contains("trace-proto-bin: AQID"));
    assert!(!trailer_str.contains("content-type"));
    assert!(!trailer_str.contains("x-grpc-web"));
    assert!(!trailer_str.contains("proxy-authenticate"));
    assert!(!trailer_str.contains("keep-alive"));
    assert!(!trailer_str.contains("x-connection-listed"));
    assert!(!trailer_str.contains(":status"));
    assert!(!trailer_str.contains("bad header"));
    assert!(!trailer_str.contains("inject"));
}

#[test]
fn test_build_trailer_frame_preserves_duplicate_metadata_and_deterministic_order() {
    use ferrum_edge::_test_support::build_trailer_frame;
    let mut headers = HashMap::new();
    // Newline-joined duplicates mirror collect_buffered_grpc_trailers.
    headers.insert("request-id".to_string(), "first\nsecond".to_string());
    headers.insert("grpc-status".to_string(), "0".to_string());
    headers.insert("zebra-meta".to_string(), "z".to_string());
    headers.insert("alpha-meta".to_string(), "a".to_string());

    let frame = build_trailer_frame(&headers);
    let trailer_str = String::from_utf8(frame[5..].to_vec()).unwrap();
    assert!(trailer_str.contains("request-id: first\r\n"));
    assert!(trailer_str.contains("request-id: second\r\n"));
    assert_eq!(trailer_str.matches("request-id:").count(), 2);

    // Sorted by lowercase name: alpha-meta, grpc-status, request-id..., zebra-meta
    let alpha = trailer_str.find("alpha-meta:").expect("alpha-meta");
    let grpc_status = trailer_str.find("grpc-status:").expect("grpc-status");
    let request_id = trailer_str.find("request-id:").expect("request-id");
    let zebra = trailer_str.find("zebra-meta:").expect("zebra-meta");
    assert!(alpha < grpc_status && grpc_status < request_id && request_id < zebra);
}

#[tokio::test]
async fn test_transform_response_body_binary_and_text_embed_custom_trailers() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let plugin = create_plugin_default();
    let mut body = vec![0x00u8];
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );
    response_headers.insert("grpc-status".to_string(), "0".to_string());
    response_headers.insert("request-id".to_string(), "abc-123".to_string());
    response_headers.insert("trace-proto-bin".to_string(), "AQID".to_string());
    response_headers.insert("request-id-dup".to_string(), "one\ntwo".to_string());
    response_headers.insert("proxy-authenticate".to_string(), "Basic x".to_string());

    let binary = plugin
        .transform_response_body(&body, Some("application/grpc-web"), &response_headers)
        .await
        .expect("binary transform");
    let binary_payload = grpc_web_trailer_payload(&binary[body.len()..]);
    assert!(binary_payload.contains("grpc-status: 0"));
    assert!(binary_payload.contains("request-id: abc-123"));
    assert!(binary_payload.contains("trace-proto-bin: AQID"));
    assert!(binary_payload.contains("request-id-dup: one\r\n"));
    assert!(binary_payload.contains("request-id-dup: two\r\n"));
    assert!(!binary_payload.contains("proxy-authenticate"));

    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web-text".to_string(),
    );
    let text = plugin
        .transform_response_body(&body, Some("application/grpc-web-text"), &response_headers)
        .await
        .expect("text transform");
    let decoded = BASE64.decode(&text).expect("text body is base64");
    assert_eq!(&decoded[..body.len()], &body[..]);
    let text_payload = grpc_web_trailer_payload(&decoded[body.len()..]);
    assert!(text_payload.contains("request-id: abc-123"));
    assert!(text_payload.contains("trace-proto-bin: AQID"));
    assert!(!text_payload.contains("proxy-authenticate"));
}

#[tokio::test]
async fn test_transform_with_provenance_excludes_initial_header_only_fields() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    // Only backend trailers are allowlisted; header-only fields must not leak.
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    trailers.insert("request-id".to_string(), "abc-123".to_string());
    trailers.insert("trace-proto-bin".to_string(), "AQID".to_string());
    ferrum_edge::plugins::grpc_web::record_backend_trailer_names_for_frame(
        &mut ctx.metadata,
        &trailers,
    );

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );
    response_headers.insert("grpc-status".to_string(), "0".to_string());
    response_headers.insert("request-id".to_string(), "abc-123".to_string());
    response_headers.insert("trace-proto-bin".to_string(), "AQID".to_string());
    response_headers.insert("x-powered-by".to_string(), "backend-header".to_string());
    response_headers.insert("quota-remaining".to_string(), "7".to_string());

    let output = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"",
            Some("application/grpc-web"),
            &response_headers,
        )
        .await
        .expect("transform");
    let payload = grpc_web_trailer_payload(&output);
    assert!(payload.contains("grpc-status: 0"));
    assert!(payload.contains("request-id: abc-123"));
    assert!(payload.contains("trace-proto-bin: AQID"));
    assert!(
        !payload.contains("x-powered-by"),
        "initial-header-only field must not enter the trailer frame: {payload}"
    );
    assert!(
        !payload.contains("quota-remaining"),
        "non-trailer merged field must not enter the trailer frame: {payload}"
    );
}

/// Apply after_proxy plugins under buffered initial-header policy state, then
/// transform + reconcile + sync so the body trailer frame matches native H2/H3.
async fn grpc_web_body_frame_after_policy_hooks(
    backend_headers: HashMap<String, String>,
    backend_trailers: HashMap<String, String>,
    hooks: &[Arc<dyn Plugin>],
) -> String {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;
    ferrum_edge::plugins::grpc_web::record_backend_trailer_provenance_for_frame(
        &mut ctx.metadata,
        &backend_headers,
        &backend_trailers,
    );
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    plugin_view.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );

    let policy_names = hooks
        .iter()
        .find(|hook| hook.is_initial_response_header_policy())
        .map(|hook| Arc::new(hook.initial_response_header_policy_names().to_vec()))
        .unwrap_or_else(|| Arc::new(Vec::new()));
    let mut policy_state = BufferedInitialResponseHeaderPolicyState::new(
        Arc::clone(&policy_names),
        &backend_headers,
        &plugin_view,
    );
    ferrum_edge::_test_support::begin_buffered_initial_response_header_policy_for_test(
        &mut ctx,
        Arc::clone(&policy_names),
        &backend_headers,
        &plugin_view,
    );
    for hook in hooks {
        let _ = hook.after_proxy(&mut ctx, 200, &mut plugin_view).await;
        if let Some(state) = policy_state.as_mut() {
            state.record_after_proxy_plugin(hook.as_ref(), &mut plugin_view);
        }
        ferrum_edge::_test_support::record_buffered_initial_response_header_plugin_for_test(
            &mut ctx,
            hook.as_ref(),
            &mut plugin_view,
        );
    }

    let mut body = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"",
            Some("application/grpc-web"),
            &plugin_view,
        )
        .await
        .expect("transform");
    let mut wire_trailers = backend_trailers;
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        policy_state.as_ref(),
    );
    assert!(
        ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut body,
            Some("application/grpc-web"),
            &wire_trailers,
            Some(200),
        )
    );
    grpc_web_trailer_payload(&body)
}

#[test]
fn test_sync_trailer_frame_refuses_malformed_draft_body() {
    // An incomplete data frame followed by a syntactically complete trailer
    // must not gain another trailer. Production always supplies a complete
    // transform-phase draft, so failure to prove that shape is fail-closed.
    let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x20, 0x01];
    body.extend(ferrum_edge::_test_support::build_trailer_frame(
        &HashMap::from([("grpc-status".to_string(), "0".to_string())]),
    ));
    let original = body.clone();

    assert!(
        !ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut body,
            Some("application/grpc-web"),
            &HashMap::from([("grpc-status".to_string(), "13".to_string())]),
            Some(200),
        )
    );
    assert_eq!(body, original);
}

/// H1/H2/H3 buffered gRPC-Web must sync the body trailer frame from the
/// reconciled wire trailer map *before* retiring application trailers.
///
/// A properly framed DATA+TRAILER draft (the H3→H2 bridge shape) makes sync
/// succeed; discarding first would leave only `grpc-status` and rebuild a
/// sparse frame. Unframed backend bytes accidentally mask that ordering bug
/// because truncate-then-sync fails closed and keeps the transform draft.
#[test]
fn test_sync_before_discard_preserves_custom_trailers_on_framed_body() {
    let backend_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let backend_trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("request-id".to_string(), "abc-123\nabc-456".to_string()),
        ("trace-proto-bin".to_string(), "AQID".to_string()),
    ]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    plugin_view.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );

    // Proper length-prefixed DATA frame + transform-phase trailer draft.
    let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x04];
    body.extend_from_slice(b"pong");
    body.extend(ferrum_edge::_test_support::build_trailer_frame(
        &plugin_view,
    ));

    let mut wire_trailers = backend_trailers.clone();
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        None,
    );
    assert!(
        ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut body,
            Some("application/grpc-web"),
            &wire_trailers,
            Some(200),
        ),
        "framed DATA+TRAILER draft must sync from reconciled trailers"
    );
    ferrum_edge::_test_support::discard_grpc_application_trailers_after_body_rewrite_for_test(
        &mut plugin_view,
        &mut wire_trailers,
        &[],
    );
    assert_eq!(
        wire_trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert!(!wire_trailers.contains_key("request-id"));

    let payload = trailing_grpc_web_trailer_payload(&body);
    assert!(
        payload.contains("request-id: abc-123\r\n"),
        "sync-before-discard must keep ASCII custom trailers: {payload}"
    );
    assert!(
        payload.contains("request-id: abc-456\r\n"),
        "sync-before-discard must keep duplicate ASCII trailers: {payload}"
    );
    assert!(
        payload.contains("trace-proto-bin: AQID\r\n"),
        "sync-before-discard must keep binary trailers: {payload}"
    );
}

#[test]
fn test_truncate_trailing_trailer_frames_suffix_and_malformed() {
    use ferrum_edge::_test_support::{
        GRPC_FRAME_TRAILER, build_trailer_frame, truncate_trailing_trailer_frames_for_test,
    };

    let data_frame = {
        let mut frame = vec![0x00, 0x00, 0x00, 0x00, 0x04];
        frame.extend_from_slice(b"pong");
        frame
    };
    let t1 = build_trailer_frame(&HashMap::from([("grpc-status".to_string(), "0".to_string())]));
    let t2 = build_trailer_frame(&HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("request-id".to_string(), "a".to_string()),
    ]));

    // Multiple contiguous trailer frames at EOS truncate once to the data prefix.
    let mut body = data_frame.clone();
    body.extend_from_slice(&t1);
    body.extend_from_slice(&t2);
    assert!(truncate_trailing_trailer_frames_for_test(&mut body));
    assert_eq!(body, data_frame);

    // Trailer interspersed before a final data frame is not a trailer suffix.
    let mut body = t1.clone();
    body.extend_from_slice(&data_frame);
    let original = body.clone();
    assert!(!truncate_trailing_trailer_frames_for_test(&mut body));
    assert_eq!(body, original);

    // data + trailer + data: no contiguous trailer suffix at EOS.
    let mut body = data_frame.clone();
    body.extend_from_slice(&t1);
    body.extend_from_slice(&data_frame);
    let original = body.clone();
    assert!(!truncate_trailing_trailer_frames_for_test(&mut body));
    assert_eq!(body, original);

    // Malformed: declared length overruns the buffer — leave bytes untouched.
    let mut body = vec![GRPC_FRAME_TRAILER, 0x00, 0x00, 0x00, 0x10, 0x01];
    let original = body.clone();
    assert!(!truncate_trailing_trailer_frames_for_test(&mut body));
    assert_eq!(body, original);

    // Large synthetic sequence: many data frames then two trailer frames.
    let mut body = Vec::new();
    for i in 0..64u8 {
        body.push(0x00);
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(i);
    }
    let prefix_len = body.len();
    body.extend_from_slice(&t1);
    body.extend_from_slice(&t2);
    assert!(truncate_trailing_trailer_frames_for_test(&mut body));
    assert_eq!(body.len(), prefix_len);
}

#[test]
fn test_sync_trailer_frame_short_circuits_when_already_identical() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ferrum_edge::_test_support::build_trailer_frame;

    let trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("request-id".to_string(), "abc".to_string()),
    ]);
    let mut binary = vec![0x00, 0x00, 0x00, 0x00, 0x04];
    binary.extend_from_slice(b"pong");
    binary.extend(build_trailer_frame(&trailers));

    // Text mode: unchanged trailer suffix must keep the original base64 bytes.
    let mut text_body = BASE64.encode(&binary).into_bytes();
    let original_text = text_body.clone();
    assert!(
        ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut text_body,
            Some("application/grpc-web-text"),
            &trailers,
            Some(200),
        )
    );
    assert_eq!(
        text_body, original_text,
        "identical trailer suffix must short-circuit without re-encoding"
    );

    // Changed metadata must rebuild (and re-encode in text mode).
    let mut changed = trailers.clone();
    changed.insert("request-id".to_string(), "mutated".to_string());
    assert!(
        ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut text_body,
            Some("application/grpc-web-text"),
            &changed,
            Some(200),
        )
    );
    assert_ne!(text_body, original_text);
    let decoded = BASE64.decode(&text_body).expect("valid text body");
    let payload = trailing_grpc_web_trailer_payload(&decoded);
    assert!(payload.contains("request-id: mutated\r\n"));
}

/// Mesh-mTLS translated path must discard trailer-only names from initial
/// headers after syncing the body trailer frame (H1/H2/H3 parity).
#[test]
fn test_mesh_sync_then_discard_matches_h2_parity() {
    let mut response_headers = HashMap::from([
        (
            "content-type".to_string(),
            "application/grpc-web".to_string(),
        ),
        ("x-initial".to_string(), "keep".to_string()),
        ("x-shared".to_string(), "initial-value".to_string()),
        ("request-id".to_string(), "trailer-only".to_string()),
        ("grpc-status".to_string(), "0".to_string()),
    ]);
    let mut trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("request-id".to_string(), "trailer-only".to_string()),
        ("x-shared".to_string(), "trailer-value".to_string()),
    ]);

    let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x04];
    body.extend_from_slice(b"pong");
    body.extend(ferrum_edge::_test_support::build_trailer_frame(
        &response_headers,
    ));

    assert!(
        ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut body,
            Some("application/grpc-web"),
            &trailers,
            Some(200),
        )
    );
    ferrum_edge::_test_support::discard_grpc_application_trailers_after_body_rewrite_for_test(
        &mut response_headers,
        &mut trailers,
        &["x-shared"],
    );

    assert_eq!(
        response_headers.get("x-initial").map(String::as_str),
        Some("keep")
    );
    assert_eq!(
        response_headers.get("x-shared").map(String::as_str),
        Some("initial-value"),
        "shadowed initial-header collision must be preserved"
    );
    assert!(
        !response_headers.contains_key("request-id"),
        "trailer-only custom metadata must leave initial headers after mesh sync"
    );
    assert_eq!(
        response_headers.get("grpc-status").map(String::as_str),
        Some("0"),
        "reserved terminal metadata remains until finalize"
    );
    assert_eq!(
        trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
    assert!(!trailers.contains_key("request-id"));
    assert!(!trailers.contains_key("x-shared"));

    let payload = trailing_grpc_web_trailer_payload(&body);
    assert!(payload.contains("request-id: trailer-only\r\n"));
    assert!(payload.contains("x-shared: trailer-value\r\n"), "{payload}");
}

/// Inverse of [`test_sync_before_discard_preserves_custom_trailers_on_framed_body`]:
/// discard-then-sync on a framed body is the exact H3 provenance-loss shape.
#[test]
fn test_discard_before_sync_on_framed_body_drops_custom_trailers() {
    let backend_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let backend_trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("request-id".to_string(), "abc-123\nabc-456".to_string()),
        ("trace-proto-bin".to_string(), "AQID".to_string()),
    ]);
    let (mut plugin_view, shadowed) =
        grpc_proxy::build_grpc_plugin_header_view(&backend_headers, &backend_trailers);
    plugin_view.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );

    let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x04];
    body.extend_from_slice(b"pong");
    body.extend(ferrum_edge::_test_support::build_trailer_frame(
        &plugin_view,
    ));

    let mut wire_trailers = backend_trailers;
    ferrum_edge::_test_support::discard_grpc_application_trailers_after_body_rewrite_for_test(
        &mut plugin_view,
        &mut wire_trailers,
        &[],
    );
    grpc_proxy::reconcile_grpc_trailers_from_view(
        &mut wire_trailers,
        &plugin_view,
        &backend_headers,
        &shadowed,
        None,
    );
    assert!(
        ferrum_edge::_test_support::sync_translated_body_trailer_frame_from_trailers(
            &mut body,
            Some("application/grpc-web"),
            &wire_trailers,
            Some(200),
        )
    );
    let payload = trailing_grpc_web_trailer_payload(&body);
    assert!(
        payload.contains("grpc-status: 0\r\n"),
        "reserved status must remain: {payload}"
    );
    assert!(
        !payload.contains("request-id"),
        "discard-before-sync must demonstrate custom-trailer loss on framed bodies: {payload}"
    );
    assert!(
        !payload.contains("trace-proto-bin"),
        "discard-before-sync must demonstrate binary-trailer loss on framed bodies: {payload}"
    );
}

#[tokio::test]
async fn test_transform_policy_set_preserves_backend_trailer_in_body_frame() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": true,
            "set": { "X-Policy": "gateway-enforced" }
        }))
        .unwrap(),
    );
    let payload = grpc_web_body_frame_after_policy_hooks(
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]),
        HashMap::from([
            ("grpc-status".to_string(), "0".to_string()),
            ("x-policy".to_string(), "application-value".to_string()),
        ]),
        &[policy],
    )
    .await;
    assert!(
        payload.contains("x-policy: application-value\r\n"),
        "policy set/override must preserve the backend trailer in the body frame: {payload}"
    );
    assert!(
        !payload.contains("gateway-enforced"),
        "policy value must not replace the body-framed trailer: {payload}"
    );
}

#[tokio::test]
async fn test_transform_policy_removal_suppresses_body_framed_trailer() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "set": {},
            "remove": ["X-Trailer-Only"]
        }))
        .unwrap(),
    );
    let payload = grpc_web_body_frame_after_policy_hooks(
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]),
        HashMap::from([
            ("grpc-status".to_string(), "0".to_string()),
            ("x-trailer-only".to_string(), "backend-trailer".to_string()),
        ]),
        &[policy],
    )
    .await;
    assert!(
        !payload.contains("x-trailer-only"),
        "final policy removal must suppress the body-framed trailer: {payload}"
    );
    assert!(payload.contains("grpc-status: 0"));
}

#[tokio::test]
async fn test_transform_later_rewrite_wins_over_initial_header_policy_in_body_frame() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": false,
            "set": { "X-Policy": "gateway-policy" }
        }))
        .unwrap(),
    );
    let later_mutator: Arc<dyn Plugin> = Arc::new(
        ferrum_edge::plugins::response_transformer::ResponseTransformer::new(&json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "X-Policy",
                "value": "later-transformer"
            }]
        }))
        .unwrap(),
    );
    let payload = grpc_web_body_frame_after_policy_hooks(
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]),
        HashMap::from([
            ("grpc-status".to_string(), "0".to_string()),
            ("x-policy".to_string(), "backend-trailer".to_string()),
        ]),
        &[policy, later_mutator],
    )
    .await;
    assert!(
        payload.contains("x-policy: later-transformer\r\n"),
        "a later genuine rewrite must win in the body frame: {payload}"
    );
    assert!(!payload.contains("backend-trailer"));
    assert!(!payload.contains("gateway-policy"));
}

#[tokio::test]
async fn test_transform_policy_set_preserves_shadowed_collision_trailer_in_body_frame() {
    let policy: Arc<dyn Plugin> = Arc::new(
        SecurityHeaders::new(&json!({
            "override_existing": true,
            "set": { "X-Shared-Meta": "gateway-enforced" }
        }))
        .unwrap(),
    );
    let payload = grpc_web_body_frame_after_policy_hooks(
        HashMap::from([
            ("content-type".to_string(), "application/grpc".to_string()),
            ("x-shared-meta".to_string(), "initial-value".to_string()),
        ]),
        HashMap::from([
            ("grpc-status".to_string(), "0".to_string()),
            ("x-shared-meta".to_string(), "trailer-value".to_string()),
        ]),
        &[policy],
    )
    .await;
    assert!(
        payload.contains("x-shared-meta: trailer-value\r\n"),
        "same-name initial/trailer collision must keep the backend trailer: {payload}"
    );
    assert!(!payload.contains("initial-value"));
    assert!(!payload.contains("gateway-enforced"));
}

/// Owner-staged context plus the compatibility header view for the shadowed
/// `x-shared-meta` collision fixture. Fresh per scenario: response translation
/// is exactly-once per RequestContext under multi-instance ownership.
async fn owner_staged_shadowed_trailer_fixture(
    plugin: &std::sync::Arc<dyn Plugin>,
) -> (
    ferrum_edge::plugins::RequestContext,
    HashMap<String, String>,
) {
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut initial_headers = HashMap::new();
    initial_headers.insert("x-shared-meta".to_string(), "initial-value".to_string());
    let mut trailers = HashMap::new();
    trailers.insert("grpc-status".to_string(), "0".to_string());
    trailers.insert("x-shared-meta".to_string(), "trailer-value".to_string());
    ferrum_edge::plugins::grpc_web::record_backend_trailer_provenance_for_frame(
        &mut ctx.metadata,
        &initial_headers,
        &trailers,
    );

    let mut merged_view = initial_headers;
    merged_view.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );
    merged_view.insert("grpc-status".to_string(), "0".to_string());
    (ctx, merged_view)
}

#[tokio::test]
async fn test_transform_with_provenance_uses_true_shadowed_trailer_value() {
    let plugin = create_plugin_default();

    // Untouched compatibility view recovers the true shadowed trailer value.
    let (mut ctx, merged_view) = owner_staged_shadowed_trailer_fixture(&plugin).await;
    let output = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"",
            Some("application/grpc-web"),
            &merged_view,
        )
        .await
        .expect("transform");
    let payload = grpc_web_trailer_payload(&output);
    assert!(payload.contains("x-shared-meta: trailer-value\r\n"));
    assert!(!payload.contains("x-shared-meta: initial-value\r\n"));

    // Later genuine rewrite wins on a fresh owner-staged request context.
    let (mut ctx, mut merged_view) = owner_staged_shadowed_trailer_fixture(&plugin).await;
    merged_view.insert("x-shared-meta".to_string(), "sanitized".to_string());
    let output = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"",
            Some("application/grpc-web"),
            &merged_view,
        )
        .await
        .expect("sanitized transform");
    let payload = grpc_web_trailer_payload(&output);
    assert!(payload.contains("x-shared-meta: sanitized\r\n"));
    assert!(!payload.contains("trailer-value"));

    // Later removal stays removed on a fresh owner-staged request context.
    let (mut ctx, mut merged_view) = owner_staged_shadowed_trailer_fixture(&plugin).await;
    merged_view.remove("x-shared-meta");
    let output = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"",
            Some("application/grpc-web"),
            &merged_view,
        )
        .await
        .expect("removed transform");
    let payload = grpc_web_trailer_payload(&output);
    assert!(!payload.contains("x-shared-meta"));
}

#[tokio::test]
async fn test_transform_missing_collision_provenance_fails_closed() {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let initial_headers =
        HashMap::from([("x-shared-meta".to_string(), "initial-secret".to_string())]);
    let trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("x-shared-meta".to_string(), "trailer-value".to_string()),
    ]);
    ferrum_edge::plugins::grpc_web::record_backend_trailer_provenance_for_frame(
        &mut ctx.metadata,
        &initial_headers,
        &trailers,
    );
    ctx.metadata.remove("grpc_web_shadowed_trailers");

    let response_headers = HashMap::from([
        (
            "content-type".to_string(),
            "application/grpc-web".to_string(),
        ),
        ("grpc-status".to_string(), "0".to_string()),
        ("x-shared-meta".to_string(), "initial-secret".to_string()),
    ]);
    let output = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"",
            Some("application/grpc-web"),
            &response_headers,
        )
        .await
        .expect("transform");
    let payload = grpc_web_trailer_payload(&output);
    assert!(payload.contains("grpc-status: 0"));
    assert!(
        !payload.contains("x-shared-meta"),
        "missing collision provenance must not frame an initial header: {payload}"
    );
}

#[test]
fn test_mesh_bridge_promotion_strips_value_bearing_internal_headers() {
    let trailers = HashMap::from([("x-shared-meta".to_string(), "trailer-secret".to_string())]);
    let mut response_headers =
        HashMap::from([("x-shared-meta".to_string(), "initial-secret".to_string())]);
    ferrum_edge::plugins::grpc_web::bridge_backend_trailer_provenance_for_frame(
        &mut response_headers,
        &trailers,
    );

    let mut metadata = HashMap::new();
    ferrum_edge::plugins::grpc_web::promote_bridged_trailer_provenance(
        &mut metadata,
        &mut response_headers,
    );

    assert!(!response_headers.contains_key("x-ferrum-grpc-web-trailer-names"));
    assert!(!response_headers.contains_key("x-ferrum-grpc-web-shadowed-trailers"));
    assert!(metadata.contains_key("grpc_web_trailer_names"));
    assert!(metadata.contains_key("grpc_web_shadowed_trailers"));
}

#[test]
fn test_capture_bridged_trailer_split_fails_closed_on_corrupt_shadowed_payload() {
    let mut response_headers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("x-shared-meta".to_string(), "initial-secret".to_string()),
        ("request-id".to_string(), "trailer-only".to_string()),
    ]);
    let trailers = HashMap::from([
        ("grpc-status".to_string(), "0".to_string()),
        ("x-shared-meta".to_string(), "trailer-secret".to_string()),
        ("request-id".to_string(), "trailer-only".to_string()),
    ]);
    ferrum_edge::plugins::grpc_web::bridge_backend_trailer_provenance_for_frame(
        &mut response_headers,
        &trailers,
    );
    // Corrupt the collision payload while leaving trailer-name provenance intact.
    response_headers.insert(
        "x-ferrum-grpc-web-shadowed-trailers".to_string(),
        "not-valid-base64!!!".to_string(),
    );

    let split = ferrum_edge::plugins::grpc_web::capture_bridged_trailer_split_for_policy(
        &response_headers,
    )
    .expect("names provenance still present");

    assert_eq!(
        split.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "reserved terminal metadata survives fail-closed capture"
    );
    assert!(
        !split.trailers.contains_key("x-shared-meta"),
        "corrupt collision payload must not substitute the initial-header value as a trailer"
    );
    assert!(
        !split.trailers.contains_key("request-id"),
        "application trailers are suppressed when collision provenance is corrupt"
    );
    assert!(split.shadowed_keys.is_empty());
    assert!(
        !split.initial_headers.contains_key("x-shared-meta"),
        "listed trailer names are removed from the initial view under fail-closed"
    );
    assert!(!split.initial_headers.contains_key("request-id"));
}

#[test]
fn test_build_trailer_frame_missing_status_defaults_to_unknown() {
    use ferrum_edge::_test_support::{GRPC_FRAME_TRAILER, build_trailer_frame};
    let headers = HashMap::new();
    let frame = build_trailer_frame(&headers);
    assert_eq!(frame[0], GRPC_FRAME_TRAILER);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 2"));
    assert!(!trailer_str.contains("grpc-status: 0"));
}

#[test]
fn test_build_trailer_frame_skips_invalid_trailer_lines() {
    use ferrum_edge::_test_support::build_trailer_frame;
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "0\r\nx-bad: yes".to_string());
    headers.insert("bad header".to_string(), "secret".to_string());
    headers.insert("grpc-message".to_string(), "OK".to_string());

    let frame = build_trailer_frame(&headers);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(!trailer_str.contains("x-bad"));
    assert!(!trailer_str.contains("bad header"));
    assert!(trailer_str.contains("grpc-status: 2"));
    assert!(trailer_str.contains("grpc-message: OK"));
}

#[test]
fn test_build_trailer_frame_empty_status_reports_unknown() {
    use ferrum_edge::_test_support::build_trailer_frame;
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), String::new());

    let frame = build_trailer_frame(&headers);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    // The malformed (empty) status must not be forwarded; only the synthesized
    // UNKNOWN remains.
    assert!(trailer_str.contains("grpc-status: 2"));
    assert_eq!(trailer_str.matches("grpc-status:").count(), 1);
}

#[test]
fn test_build_trailer_frame_malformed_status_uses_http_mapping() {
    use ferrum_edge::_test_support::build_trailer_frame_with_http_status;
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "abc".to_string());

    let frame = build_trailer_frame_with_http_status(&headers, Some(503));
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 14"));
    assert!(!trailer_str.contains("abc"));
    assert_eq!(trailer_str.matches("grpc-status:").count(), 1);
}

#[test]
fn test_build_trailer_frame_non_numeric_status_reports_unknown() {
    use ferrum_edge::_test_support::build_trailer_frame;
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "abc".to_string());

    let frame = build_trailer_frame(&headers);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 2"));
    assert!(!trailer_str.contains("abc"));
    assert_eq!(trailer_str.matches("grpc-status:").count(), 1);
}

#[test]
fn test_build_trailer_frame_valid_nonzero_status_passthrough() {
    use ferrum_edge::_test_support::build_trailer_frame;
    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "5".to_string());

    let frame = build_trailer_frame(&headers);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    // A present, numeric status is preserved verbatim and not overridden.
    assert!(trailer_str.contains("grpc-status: 5"));
    assert!(!trailer_str.contains("grpc-status: 2"));
    assert_eq!(trailer_str.matches("grpc-status:").count(), 1);
}

#[tokio::test]
async fn test_transform_response_body_missing_grpc_status_reports_unknown() {
    let plugin = create_plugin_default();
    let body = b"";
    let mut response_headers = HashMap::new();
    response_headers.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );

    let output = plugin
        .transform_response_body(body, Some("application/grpc-web"), &response_headers)
        .await
        .expect("gRPC-Web response body should be transformed");

    assert_eq!(output[0], 0x80);
    let trailer_len = u32::from_be_bytes([output[1], output[2], output[3], output[4]]) as usize;
    let trailer_str = String::from_utf8_lossy(&output[5..5 + trailer_len]);
    assert!(trailer_str.contains("grpc-status: 2"));
    assert!(!trailer_str.contains("grpc-status: 0"));
}

#[test]
fn test_http_response_status_to_grpc_status_official_mapping_table() {
    use ferrum_edge::_test_support::http_response_status_to_grpc_status;

    // Every row of
    // https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md
    let cases = [
        (400, 13), // INTERNAL
        (401, 16), // UNAUTHENTICATED
        (403, 7),  // PERMISSION_DENIED
        (404, 12), // UNIMPLEMENTED
        (429, 14), // UNAVAILABLE
        (502, 14), // UNAVAILABLE
        (503, 14), // UNAVAILABLE
        (504, 14), // UNAVAILABLE
        (200, 2),  // UNKNOWN (completed response still lacking grpc-status)
        (418, 2),  // UNKNOWN (unmapped)
        (500, 2),  // UNKNOWN (unmapped 5xx)
        (301, 2),  // UNKNOWN (unmapped 3xx)
    ];
    for (http_status, expected_grpc) in cases {
        assert_eq!(
            http_response_status_to_grpc_status(http_status),
            expected_grpc,
            "HTTP {http_status} must map to gRPC {expected_grpc}"
        );
    }
}

#[test]
fn test_build_trailer_frame_maps_http_status_when_grpc_status_missing() {
    use ferrum_edge::_test_support::build_trailer_frame_with_http_status;

    let cases = [
        (401, "grpc-status: 16"),
        (403, "grpc-status: 7"),
        (404, "grpc-status: 12"),
        (429, "grpc-status: 14"),
        (502, "grpc-status: 14"),
        (503, "grpc-status: 14"),
        (504, "grpc-status: 14"),
        (400, "grpc-status: 13"),
        (418, "grpc-status: 2"),
        (200, "grpc-status: 2"),
    ];
    for (http_status, expected) in cases {
        let frame = build_trailer_frame_with_http_status(&HashMap::new(), Some(http_status));
        let trailer_str = String::from_utf8_lossy(&frame[5..]);
        assert!(
            trailer_str.contains(expected),
            "HTTP {http_status}: expected {expected} in {trailer_str}"
        );
        assert_eq!(trailer_str.matches("grpc-status:").count(), 1);
    }
}

#[test]
fn test_build_trailer_frame_keeps_valid_grpc_status_over_http_mapping() {
    use ferrum_edge::_test_support::build_trailer_frame_with_http_status;

    let mut headers = HashMap::new();
    headers.insert("grpc-status".to_string(), "5".to_string());
    headers.insert("grpc-message".to_string(), "not found".to_string());

    // Non-200 HTTP must not override a valid backend grpc-status.
    let frame = build_trailer_frame_with_http_status(&headers, Some(503));
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 5"));
    assert!(trailer_str.contains("grpc-message: not found"));
    assert!(!trailer_str.contains("grpc-status: 14"));
    assert!(!trailer_str.contains("grpc-status: 2"));
}

async fn grpc_web_response_after_proxy_and_transform(
    request_content_type: &str,
    http_status: u16,
    backend_headers: HashMap<String, String>,
    body: &[u8],
) -> (u16, HashMap<String, String>, Vec<u8>) {
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context(request_content_type);
    let received = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(received, PluginResult::Continue));

    let mut response_headers = backend_headers;
    let after = plugin
        .after_proxy(&mut ctx, http_status, &mut response_headers)
        .await;
    assert!(
        matches!(after, PluginResult::Continue),
        "after_proxy must not replace the response; client-visible HTTP status stays {http_status}"
    );

    let output = plugin
        .transform_response_body_with_context(
            &mut ctx,
            body,
            response_headers.get("content-type").map(String::as_str),
            &response_headers,
        )
        .await
        .expect("gRPC-Web response body should be transformed");

    (http_status, response_headers, output)
}

#[tokio::test]
async fn test_binary_maps_http_401_404_503_and_unmapped_without_grpc_status() {
    let cases = [(401, "16"), (404, "12"), (503, "14"), (418, "2")];
    for (http_status, expected_grpc) in cases {
        let (_status, headers, output) = grpc_web_response_after_proxy_and_transform(
            "application/grpc-web+proto",
            http_status,
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]),
            b"",
        )
        .await;

        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/grpc-web+proto")
        );
        assert_eq!(output[0], 0x80);
        let payload = grpc_web_trailer_payload(&output);
        assert!(
            payload.contains(&format!("grpc-status: {expected_grpc}")),
            "HTTP {http_status}: got {payload}"
        );
        assert_eq!(payload.matches("grpc-status:").count(), 1);
    }
}

#[tokio::test]
async fn test_text_maps_http_401_404_503_and_unmapped_without_grpc_status() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let cases = [(401, "16"), (404, "12"), (503, "14"), (418, "2")];
    for (http_status, expected_grpc) in cases {
        let (_status, headers, output) = grpc_web_response_after_proxy_and_transform(
            "application/grpc-web-text",
            http_status,
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]),
            b"",
        )
        .await;

        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/grpc-web-text")
        );
        let decoded = BASE64.decode(&output).expect("text mode body is base64");
        assert_eq!(decoded[0], 0x80);
        let payload = grpc_web_trailer_payload(&decoded);
        assert!(
            payload.contains(&format!("grpc-status: {expected_grpc}")),
            "HTTP {http_status}: got {payload}"
        );
    }
}

#[tokio::test]
async fn test_non_200_with_supplied_grpc_status_stays_authoritative_binary_and_text() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    // Backend HTTP 503 with an explicit grpc-status must win over the mapping.
    let backend = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "8".to_string()),
        ("grpc-message".to_string(), "resource exhausted".to_string()),
    ]);

    let (_status, _headers, binary) = grpc_web_response_after_proxy_and_transform(
        "application/grpc-web",
        503,
        backend.clone(),
        b"",
    )
    .await;
    let binary_payload = grpc_web_trailer_payload(&binary);
    assert!(binary_payload.contains("grpc-status: 8"));
    assert!(binary_payload.contains("grpc-message: resource exhausted"));
    assert!(!binary_payload.contains("grpc-status: 14"));

    let (_status, _headers, text) = grpc_web_response_after_proxy_and_transform(
        "application/grpc-web-text+proto",
        503,
        backend,
        b"",
    )
    .await;
    let decoded = BASE64.decode(&text).expect("text mode body is base64");
    let text_payload = grpc_web_trailer_payload(&decoded);
    assert!(text_payload.contains("grpc-status: 8"));
    assert!(text_payload.contains("grpc-message: resource exhausted"));
    assert!(!text_payload.contains("grpc-status: 14"));
}

#[tokio::test]
async fn test_after_proxy_preserves_client_visible_http_status_contract() {
    // Decision for #2504: keep the backend HTTP status on the wire; only the
    // body trailer synthesizes the mapped grpc-status. after_proxy must not
    // Reject/replace the response to force HTTP 200.
    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web");
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    let result = plugin
        .after_proxy(&mut ctx, 503, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("grpc_web_http_status").map(String::as_str),
        Some("503")
    );
}

#[test]
fn test_parse_grpc_frames() {
    use ferrum_edge::_test_support::{GRPC_FRAME_DATA, GRPC_FRAME_TRAILER, parse_grpc_frames};
    let mut data = vec![0x00];
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(b"hello");
    data.push(0x80);
    data.extend_from_slice(&3u32.to_be_bytes());
    data.extend_from_slice(b"bye");

    let frames = parse_grpc_frames(&data);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].0, GRPC_FRAME_DATA);
    assert_eq!(frames[0].1, b"hello");
    assert_eq!(frames[1].0, GRPC_FRAME_TRAILER);
    assert_eq!(frames[1].1, b"bye");
}

#[test]
fn test_parse_grpc_frames_truncated() {
    use ferrum_edge::_test_support::parse_grpc_frames;
    let data = vec![0x00, 0x00, 0x00, 0x00, 0x05, b'h', b'e'];
    assert!(parse_grpc_frames(&data).is_empty());
}

// ── request_is_grpc_web_translated — mesh dispatch distinction (codex r1-4) ──
//
// The mesh-mTLS dispatch path uses this marker to tell a gRPC-Web request the
// plugin translated to native gRPC (response MUST buffer: trailers are
// re-encoded into the gRPC-Web body) apart from native gRPC (response must
// NOT buffer: trailers must relay on the wire).

#[tokio::test]
async fn test_translated_marker_set_only_after_grpc_web_translation() {
    use ferrum_edge::plugins::grpc_web::request_is_grpc_web_translated;

    let plugin = create_plugin_default();

    // A fresh, untranslated context is not marked.
    let ctx = create_grpc_web_context("application/grpc-web");
    assert!(!request_is_grpc_web_translated(&ctx));

    // on_request_received verifies the gRPC-Web content-type, rewrites it to
    // native gRPC, and stamps the marker.
    let mut ctx = create_grpc_web_context("application/grpc-web");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(request_is_grpc_web_translated(&ctx));
    assert_eq!(
        ctx.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
}

#[tokio::test]
async fn test_native_grpc_request_is_never_marked_translated() {
    use ferrum_edge::plugins::grpc_web::request_is_grpc_web_translated;

    let plugin = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc");
    let _ = plugin.on_request_received(&mut ctx).await;
    assert!(
        !request_is_grpc_web_translated(&ctx),
        "native gRPC must keep the wire-trailer (no-buffer) dispatch contract"
    );
}

#[tokio::test]
async fn test_spoofed_mode_header_cannot_mark_request_translated() {
    use ferrum_edge::plugins::grpc_web::request_is_grpc_web_translated;

    let plugin = create_plugin_default();
    // A client injecting the internal mode header on a non-gRPC-Web request
    // must not flip the dispatch distinction: the plugin strips the header
    // and only stamps the marker after verifying the real content-type.
    let mut ctx = create_grpc_web_context("application/json");
    ctx.headers
        .insert("x-grpc-web-mode".to_string(), "binary".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    assert!(!request_is_grpc_web_translated(&ctx));
    assert!(!ctx.headers.contains_key("x-grpc-web-mode"));
}

// ── Multi-instance ownership (issue #2503) ──

fn count_grpc_web_trailer_frames(body: &[u8]) -> usize {
    use ferrum_edge::_test_support::{GRPC_FRAME_TRAILER, parse_grpc_frames};
    parse_grpc_frames(body)
        .into_iter()
        .filter(|(flag, _)| *flag == GRPC_FRAME_TRAILER || *flag == 0x81)
        .count()
}

async fn run_two_instance_response_chain(
    first: &std::sync::Arc<dyn Plugin>,
    second: &std::sync::Arc<dyn Plugin>,
    request_ct: &str,
    backend_body: &[u8],
) -> (HashMap<String, String>, Vec<u8>) {
    let mut ctx = create_grpc_web_context(request_ct);
    assert!(matches!(
        first.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut outgoing = HashMap::new();
    assert!(matches!(
        first.before_proxy(&mut ctx, &mut outgoing).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.before_proxy(&mut ctx, &mut outgoing).await,
        PluginResult::Continue
    ));
    // Only the owner plants shared request staging.
    assert_eq!(
        outgoing.get("x-grpc-web-mode").map(String::as_str),
        Some(if request_ct.contains("grpc-web-text") {
            "text"
        } else {
            "binary"
        })
    );

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    response_headers.insert("grpc-status".to_string(), "0".to_string());
    assert!(matches!(
        first
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));

    let mut body = backend_body.to_vec();
    for plugin in [first, second] {
        if let Some(next) = plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                response_headers.get("content-type").map(String::as_str),
                &response_headers,
            )
            .await
        {
            body = next;
        }
    }
    (response_headers, body)
}

#[tokio::test]
async fn test_two_instances_binary_translate_once_and_union_expose_headers() {
    let first = create_plugin("grpc_web", &json!({"expose_headers": ["x-request-id"]}))
        .unwrap()
        .unwrap();
    let second = create_plugin("grpc_web", &json!({"expose_headers": ["x-trace-id"]}))
        .unwrap()
        .unwrap();

    let mut data = vec![0x00u8];
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(b"hello");

    let (headers, output) =
        run_two_instance_response_chain(&first, &second, "application/grpc-web", &data).await;

    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc-web")
    );
    assert_eq!(count_grpc_web_trailer_frames(&output), 1);
    assert_eq!(&output[..10], &data[..]);
    assert_eq!(output[10], 0x80);

    let expose = headers
        .get("access-control-expose-headers")
        .expect("expose headers");
    assert!(expose.contains("x-request-id"), "got {expose}");
    assert!(expose.contains("x-trace-id"), "got {expose}");
    assert!(expose.contains("grpc-status"), "got {expose}");
}

#[tokio::test]
async fn test_two_instances_text_decode_and_encode_exactly_once() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let first = create_plugin("grpc_web", &json!({"expose_headers": ["x-a"]}))
        .unwrap()
        .unwrap();
    let second = create_plugin("grpc_web", &json!({"expose_headers": ["x-b"]}))
        .unwrap()
        .unwrap();
    assert!(first.needs_final_request_body_context());
    assert!(second.needs_final_request_body_context());

    let mut ctx = create_grpc_web_context("application/grpc-web-text");
    first.on_request_received(&mut ctx).await;
    second.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.metadata.get("grpc_web_mode").map(String::as_str),
        Some("text")
    );
    assert!(ctx.metadata.contains_key("grpc_web.owner"));

    let mut grpc_frame = vec![0x00u8];
    grpc_frame.extend_from_slice(&5u32.to_be_bytes());
    grpc_frame.extend_from_slice(b"hello");
    let encoded = BASE64.encode(&grpc_frame);

    let mut outgoing = HashMap::new();
    first.before_proxy(&mut ctx, &mut outgoing).await;
    second.before_proxy(&mut ctx, &mut outgoing).await;

    let mut body = encoded.into_bytes();
    for plugin in [&first, &second] {
        if let Some(next) = plugin
            .transform_request_body_with_context(
                &mut ctx,
                &body,
                Some("application/grpc"),
                &outgoing,
            )
            .await
        {
            body = next;
        }
    }
    assert_eq!(body, grpc_frame);
    assert_eq!(
        ctx.metadata
            .get("grpc_web.request_decoded")
            .map(String::as_str),
        ctx.metadata.get("grpc_web.owner").map(String::as_str)
    );

    for plugin in [&first, &second] {
        assert!(matches!(
            plugin
                .on_final_request_body_with_context(&mut ctx, &outgoing, &body)
                .await,
            PluginResult::Continue
        ));
    }

    let mut data = vec![0x00u8];
    data.extend_from_slice(&3u32.to_be_bytes());
    data.extend_from_slice(b"abc");
    let (headers, output) =
        run_two_instance_response_chain(&first, &second, "application/grpc-web-text", &data).await;

    // Fresh chain above re-claims; for the response-only assertion reuse the
    // already-translated output path from this helper call.
    let decoded = BASE64.decode(&output).expect("single base64 layer");
    assert_eq!(count_grpc_web_trailer_frames(&decoded), 1);
    assert_eq!(&decoded[..8], &data[..]);
    let expose = headers
        .get("access-control-expose-headers")
        .expect("expose headers");
    assert!(
        expose.contains("x-a") && expose.contains("x-b"),
        "got {expose}"
    );
}

#[tokio::test]
async fn test_two_instances_priority_order_first_owner_wins() {
    // Simulate distinct priority_override ordering: lower effective priority
    // runs first and must own translation; the later instance only unions
    // expose_headers.
    let early = create_plugin("grpc_web", &json!({"expose_headers": ["x-early"]}))
        .unwrap()
        .unwrap();
    let late = create_plugin("grpc_web", &json!({"expose_headers": ["x-late"]}))
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_web_context("application/grpc-web");
    early.on_request_received(&mut ctx).await;
    let owner = ctx
        .metadata
        .get("grpc_web.owner")
        .cloned()
        .expect("early instance claims ownership");
    late.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.metadata.get("grpc_web.owner").map(String::as_str),
        Some(owner.as_str()),
        "later instance must not overwrite the owner marker"
    );

    let (headers, output) =
        run_two_instance_response_chain(&early, &late, "application/grpc-web+proto", &[]).await;
    assert_eq!(count_grpc_web_trailer_frames(&output), 1);
    let expose = headers
        .get("access-control-expose-headers")
        .expect("expose headers");
    assert!(expose.contains("x-early"), "got {expose}");
    assert!(expose.contains("x-late"), "got {expose}");
}

#[tokio::test]
async fn test_follower_fails_closed_without_owner_staging_on_response_transform() {
    let owner = create_plugin_default();
    let follower = create_plugin("grpc_web", &json!({"expose_headers": ["x-follower"]}))
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_web_context("application/grpc-web");
    owner.on_request_received(&mut ctx).await;
    // Corrupt shared mode staging while leaving ownership intact — owner must
    // refuse speculative translation rather than invent frames from CT alone.
    ctx.metadata
        .insert("grpc_web_mode".to_string(), "not-a-mode".to_string());
    // Clear the namespaced per-instance mode key as well.
    let owner_id = ctx.metadata.get("grpc_web.owner").cloned().unwrap();
    ctx.metadata
        .remove(&format!("grpc_web.instance.{owner_id}.mode"));

    let response_headers = HashMap::from([(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    )]);
    assert!(
        owner
            .transform_response_body_with_context(
                &mut ctx,
                b"",
                Some("application/grpc-web"),
                &response_headers,
            )
            .await
            .is_none(),
        "malformed mode staging must fail closed"
    );
    assert!(
        follower
            .transform_response_body_with_context(
                &mut ctx,
                b"",
                Some("application/grpc-web"),
                &response_headers,
            )
            .await
            .is_none(),
        "non-owner must never translate the response body"
    );
}

#[tokio::test]
async fn test_owner_requires_namespaced_mode_even_when_shared_mode_is_valid() {
    let owner = create_plugin_default();
    let mut ctx = create_grpc_web_context("application/grpc-web-text");
    owner.on_request_received(&mut ctx).await;

    let owner_id = ctx.metadata.get("grpc_web.owner").cloned().unwrap();
    ctx.metadata
        .remove(&format!("grpc_web.instance.{owner_id}.mode"));
    assert_eq!(
        ctx.metadata.get("grpc_web_mode").map(String::as_str),
        Some("text")
    );

    let response_headers = HashMap::from([(
        "content-type".to_string(),
        "application/grpc-web-text".to_string(),
    )]);
    assert!(
        owner
            .transform_response_body_with_context(
                &mut ctx,
                b"",
                Some("application/grpc-web-text"),
                &response_headers,
            )
            .await
            .is_none(),
        "owner must not fall back to shared mode after losing its namespaced staging"
    );
}
