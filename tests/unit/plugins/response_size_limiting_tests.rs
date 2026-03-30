//! Tests for response_size_limiting plugin

use ferrum_edge::plugins::response_size_limiting::ResponseSizeLimiting;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    )
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    assert_eq!(plugin.name(), "response_size_limiting");
    assert_eq!(plugin.priority(), 3950);
}

#[tokio::test]
async fn test_zero_max_bytes_has_no_effect() {
    let plugin = ResponseSizeLimiting::new(&json!({}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "999999999".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Content-Length fast path (after_proxy) ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "512".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1025".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Response body too large"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_content_length_header_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "bad".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Buffered body check (on_response_body) ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 100, "require_buffered_check": true}));
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"short";

    let result = plugin.on_response_body(&mut ctx, 200, &headers, body).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 10, "require_buffered_check": true}));
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"this response body is definitely longer than ten bytes";

    match plugin.on_response_body(&mut ctx, 200, &headers, body).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Response body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_buffered_body_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 5}));
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"12345";

    let result = plugin.on_response_body(&mut ctx, 200, &headers, body).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Response body buffering flag ===

#[tokio::test]
async fn test_requires_buffering_when_configured() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}));
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_no_buffering_by_default() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_no_buffering_when_max_bytes_zero() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 0, "require_buffered_check": true}));
    assert!(!plugin.requires_response_body_buffering());
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}));
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === Rejection body format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 10}));
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "100".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "Response body too large");
            assert_eq!(parsed["limit"], 10);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Large response ===

#[tokio::test]
async fn test_large_content_length_rejects() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1048576})); // 1 MiB
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string()); // 10 MiB

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject"),
    }
}
