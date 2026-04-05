//! Tests for request_size_limiting plugin

use ferrum_edge::plugins::request_size_limiting::RequestSizeLimiting;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "request_size_limiting");
    assert_eq!(plugin.priority(), 2800);
}

#[tokio::test]
async fn test_zero_max_bytes_returns_error() {
    // Empty config defaults max_bytes to 0, which is now rejected at construction time
    let result = RequestSizeLimiting::new(&json!({}));
    assert!(
        result.is_err(),
        "Expected error when max_bytes is zero/missing"
    );
}

// === Content-Length fast path ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "512".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1024".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_413() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1025".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert!(body.contains("Request body too large"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_content_length_header_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    // No content-length header

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_header_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "not-a-number".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_large_content_length_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1048576})).unwrap(); // 1 MiB
    let mut ctx = make_ctx("PUT", "/upload");
    ctx.headers
        .insert("content-length".to_string(), "10485760".to_string()); // 10 MiB

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Buffered body check in before_proxy ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 100})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body".to_string(), "short body".to_string());

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata.insert(
        "request_body".to_string(),
        "this body is definitely longer than 10 bytes".to_string(),
    );

    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert!(body.contains("Request body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_buffered_body_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    // No request_body in metadata

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let headers = HashMap::new();

    let result = plugin.on_final_request_body(&headers, b"1234567890").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let headers = HashMap::new();

    match plugin.on_final_request_body(&headers, b"12345678901").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert!(body.contains("Request body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === GET requests with Content-Length (unusual but valid) ===

#[tokio::test]
async fn test_get_request_with_oversized_content_length_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 100})).unwrap();
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers
        .insert("content-length".to_string(), "200".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Response body JSON format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "100".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "Request body too large");
            assert_eq!(parsed["limit"], 10);
        }
        _ => panic!("Expected Reject"),
    }
}
