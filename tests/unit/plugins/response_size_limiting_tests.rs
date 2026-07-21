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
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "response_size_limiting");
    assert_eq!(plugin.priority(), 3490);
}

#[tokio::test]
async fn test_zero_max_bytes_returns_error() {
    let result = ResponseSizeLimiting::new(&json!({}));
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("max_bytes"));
}

#[tokio::test]
async fn test_non_object_config_returns_error() {
    let result = ResponseSizeLimiting::new(&json!("bad"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[tokio::test]
async fn test_invalid_require_buffered_check_type_returns_error() {
    let result = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_check": "yes"
    }));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("require_buffered_check"));
}

// === Content-Length fast path (after_proxy) ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "512".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
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
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "bad".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Final body check (on_final_response_body) ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 100, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"short";

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 10, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"this response body is definitely longer than ten bytes";

    match plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await
    {
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
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 5})).unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"12345";

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Response body buffering flag ===

#[tokio::test]
async fn test_requires_buffering_when_configured() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_no_buffering_by_default() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_max_bytes_zero_returns_error() {
    let result =
        ResponseSizeLimiting::new(&json!({"max_bytes": 0, "require_buffered_check": true}));
    assert!(result.is_err());
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === Rejection body format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
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
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1048576})).unwrap(); // 1 MiB
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

// === SSE policy boundary ===

#[tokio::test]
async fn test_sse_request_intent_cannot_skip_strict_response_limit() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
    let response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &response_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; profile=event-stream"),
        200,
        &HashMap::new(),
    ));
}

#[tokio::test]
async fn test_non_sse_request_still_buffers() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_buffering_disabled_stays_disabled_for_sse() {
    // When require_buffered_check is off the buffer flag is false; SSE
    // detection must not flip it on.
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_sse_content_length_fast_path_still_runs() {
    // Backends that advertise a Content-Length larger than the limit retain
    // the ordinary fast-path rejection before the SSE-specific boundary.
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "2048".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject when Content-Length exceeds limit"),
    }
}

#[tokio::test]
async fn test_genuine_sse_fails_closed_at_strict_route_limit() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Streaming response size cannot be verified"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected fail-closed event-stream rejection"),
    }
}

/// Keep `docs/size_limits.md` aligned with the streaming runtime contract that
/// `response_size_limiting` points operators at (issue #2346). Unknown-length
/// responses must not be documented as a full-buffer fallback that promises a
/// post-commit JSON 502.
#[test]
fn test_size_limits_guide_matches_streaming_runtime_contract() {
    let size_limits = include_str!("../../../docs/size_limits.md");
    let streaming = include_str!("../../../docs/response_body_streaming.md");
    let plugin_docs = include_str!("../../../docs/plugins.md");

    assert!(
        !size_limits.contains("falls back to buffering"),
        "size_limits.md must not claim unknown-length responses fall back to buffering"
    );
    assert!(
        size_limits.contains("SizeLimitedStreamingResponse"),
        "size_limits.md must name SizeLimitedStreamingResponse for unknown-length streaming"
    );
    assert!(
        size_limits.contains("post-commit"),
        "size_limits.md must distinguish post-commit stream termination from pre-commit rejection"
    );
    assert!(
        size_limits.contains("response_body_streaming.md#interaction-with-response-size-limits"),
        "size_limits.md must link the streaming size-limit section"
    );
    assert!(
        size_limits.contains("plugins.md#response_size_limiting"),
        "size_limits.md must link the response_size_limiting plugin reference"
    );

    // Counterpart docs already describe the streaming adapter; keep the shared
    // terminology from drifting back to a buffering-only story.
    assert!(streaming.contains("SizeLimitedStreamingResponse"));
    assert!(
        plugin_docs.contains("SizeLimitedStreamingResponse"),
        "response_size_limiting reference must mention the global streaming adapter"
    );
}
