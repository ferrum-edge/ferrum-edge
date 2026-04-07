use ferrum_edge::plugins::{Plugin, PluginResult, create_plugin};
use serde_json::json;
use std::collections::HashMap;

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

// ── Plugin creation ──

#[test]
fn test_plugin_creation_default() {
    let plugin = create_plugin_default();
    assert_eq!(plugin.name(), "grpc_web");
    assert_eq!(plugin.priority(), 260);
}

#[test]
fn test_plugin_creation_with_expose_headers() {
    let config = json!({
        "expose_headers": ["custom-header-bin", "x-request-id"]
    });
    let plugin = create_plugin("grpc_web", &config).unwrap().unwrap();
    assert_eq!(plugin.name(), "grpc_web");
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
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
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
    assert!(is_grpc_web_content_type("application/grpc-web"));
    assert!(is_grpc_web_content_type("application/grpc-web+proto"));
    assert!(is_grpc_web_content_type("application/grpc-web-text"));
    assert!(is_grpc_web_content_type("application/grpc-web-text+proto"));
    assert!(is_grpc_web_content_type("  Application/gRPC-Web  "));
    assert!(!is_grpc_web_content_type("application/grpc"));
    assert!(!is_grpc_web_content_type("application/json"));
}

#[test]
fn test_is_grpc_web_text() {
    use ferrum_edge::_test_support::is_grpc_web_text;
    assert!(is_grpc_web_text("application/grpc-web-text"));
    assert!(is_grpc_web_text("application/grpc-web-text+proto"));
    assert!(!is_grpc_web_text("application/grpc-web"));
    assert!(!is_grpc_web_text("application/grpc-web+proto"));
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
fn test_build_trailer_frame_default_status() {
    use ferrum_edge::_test_support::{GRPC_FRAME_TRAILER, build_trailer_frame};
    let headers = HashMap::new();
    let frame = build_trailer_frame(&headers);
    assert_eq!(frame[0], GRPC_FRAME_TRAILER);
    let trailer_str = String::from_utf8_lossy(&frame[5..]);
    assert!(trailer_str.contains("grpc-status: 0"));
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
