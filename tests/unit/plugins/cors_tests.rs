//! Tests for the CORS plugin

use ferrum_gateway::plugins::cors::CorsPlugin;
use ferrum_gateway::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn make_preflight_ctx(origin: &str, method: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/test".to_string(),
    );
    ctx.headers.insert("origin".to_string(), origin.to_string());
    ctx.headers.insert(
        "access-control-request-method".to_string(),
        method.to_string(),
    );
    ctx
}

fn make_cors_ctx(method: &str, origin: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/test".to_string(),
    );
    ctx.headers.insert("origin".to_string(), origin.to_string());
    ctx
}

// ── Config parsing ───────────────────────────────────────────────────

#[tokio::test]
async fn test_cors_plugin_creation_defaults() {
    let plugin = CorsPlugin::new(&json!({}));
    assert_eq!(plugin.name(), "cors");
}

#[tokio::test]
async fn test_cors_plugin_credentials_wildcard_conflict() {
    // allow_credentials with wildcard origins should disable credentials
    let plugin = CorsPlugin::new(&json!({
        "allow_credentials": true
    }));

    // Verify via preflight: should NOT include access-control-allow-credentials
    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert!(!headers.contains_key("access-control-allow-credentials"));
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "*",
                "Should use wildcard since credentials was forced off"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_cors_plugin_credentials_with_specific_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example.com"],
        "allow_credentials": true
    }));

    let mut ctx = make_preflight_ctx("https://app.example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("access-control-allow-credentials").unwrap(),
                "true"
            );
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://app.example.com"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

// ── Preflight tests (on_request_received) ────────────────────────────

#[tokio::test]
async fn test_preflight_with_allowed_origin() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 204);
            assert!(body.is_empty());
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://example.com"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_with_disallowed_origin() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    let mut ctx = make_preflight_ctx("https://evil.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
            // No CORS headers should be present for disallowed origin
            assert!(!headers.contains_key("access-control-allow-origin"));
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_with_wildcard_origins() {
    let plugin = CorsPlugin::new(&json!({}));

    let mut ctx = make_preflight_ctx("https://anything.example.com", "POST");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_includes_methods_and_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_methods": ["GET", "POST"],
        "allowed_headers": ["Authorization", "Content-Type"]
    }));

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(
                headers.get("access-control-allow-methods").unwrap(),
                "GET, POST"
            );
            assert_eq!(
                headers.get("access-control-allow-headers").unwrap(),
                "Authorization, Content-Type"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_includes_max_age() {
    let plugin = CorsPlugin::new(&json!({
        "max_age": 3600
    }));

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("access-control-max-age").unwrap(), "3600");
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_continue_passes_through() {
    let plugin = CorsPlugin::new(&json!({
        "preflight_continue": true
    }));

    let mut ctx = make_preflight_ctx("https://example.com", "GET");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "preflight_continue should pass through"
    );
    // Origin should be stashed in metadata for after_proxy
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "https://example.com"
    );
}

#[tokio::test]
async fn test_preflight_disallowed_method() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_methods": ["GET", "POST"]
    }));

    let mut ctx = make_preflight_ctx("https://example.com", "DELETE");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS method not allowed: DELETE");
            assert!(
                !headers.contains_key("access-control-allow-origin"),
                "No CORS headers for disallowed method"
            );
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_non_options_with_origin_passes_through() {
    let plugin = CorsPlugin::new(&json!({}));

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "https://example.com"
    );
}

#[tokio::test]
async fn test_non_preflight_disallowed_origin_returns_403() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    let mut ctx = make_cors_ctx("GET", "https://evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for disallowed origin on non-preflight request"),
    }
}

#[tokio::test]
async fn test_options_without_request_method_header_disallowed_origin_returns_403() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    // OPTIONS with Origin but WITHOUT Access-Control-Request-Method = not a preflight
    // Disallowed origin should still get rejected
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/test".to_string(),
    );
    ctx.headers
        .insert("origin".to_string(), "https://evil.com".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for disallowed origin"),
    }
}

#[tokio::test]
async fn test_options_without_request_method_header_allowed_origin_passes_through() {
    let plugin = CorsPlugin::new(&json!({}));

    // OPTIONS with Origin but WITHOUT Access-Control-Request-Method = not a preflight
    // Allowed origin should pass through
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/test".to_string(),
    );
    ctx.headers
        .insert("origin".to_string(), "https://example.com".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "OPTIONS without Access-Control-Request-Method with allowed origin should pass through"
    );
}

// ── Actual CORS response tests (after_proxy) ─────────────────────────

#[tokio::test]
async fn test_actual_cors_request_adds_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    // Simulate on_request_received setting metadata
    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://example.com"
    );
    assert_eq!(response_headers.get("vary").unwrap(), "Origin");
}

#[tokio::test]
async fn test_actual_cors_request_with_credentials() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"],
        "allow_credentials": true
    }));

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers
            .get("access-control-allow-credentials")
            .unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_actual_cors_request_with_exposed_headers() {
    let plugin = CorsPlugin::new(&json!({
        "exposed_headers": ["X-Request-ID", "X-RateLimit-Remaining"]
    }));

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers
            .get("access-control-expose-headers")
            .unwrap(),
        "X-Request-ID, X-RateLimit-Remaining"
    );
}

#[tokio::test]
async fn test_non_cors_request_no_headers_added() {
    let plugin = CorsPlugin::new(&json!({}));

    // No Origin header
    let mut ctx = make_ctx();
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(
        !response_headers.contains_key("access-control-allow-origin"),
        "No CORS headers without Origin"
    );
}

// ── Vary header tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_vary_header_set_for_specific_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(response_headers.get("vary").unwrap(), "Origin");
}

#[tokio::test]
async fn test_vary_header_set_for_wildcard() {
    let plugin = CorsPlugin::new(&json!({}));

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(response_headers.get("vary").unwrap(), "Origin");
}

// ── Edge case tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_empty_origin_header_returns_403() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    let mut ctx = make_cors_ctx("GET", "");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for empty origin"),
    }
}

#[tokio::test]
async fn test_case_sensitivity_of_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }));

    // Origins are case-sensitive per spec — mismatched case should return 403
    let mut ctx = make_cors_ctx("GET", "https://Example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for case-mismatched origin"),
    }
}

#[tokio::test]
async fn test_multiple_origins_in_config() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example.com", "https://admin.example.com"]
    }));

    // First origin — allowed
    let mut ctx1 = make_cors_ctx("GET", "https://app.example.com");
    let result1 = plugin.on_request_received(&mut ctx1).await;
    assert!(matches!(result1, PluginResult::Continue));
    assert_eq!(
        ctx1.metadata.get("cors_origin").unwrap(),
        "https://app.example.com"
    );

    // Second origin — allowed
    let mut ctx2 = make_cors_ctx("GET", "https://admin.example.com");
    let result2 = plugin.on_request_received(&mut ctx2).await;
    assert!(matches!(result2, PluginResult::Continue));
    assert_eq!(
        ctx2.metadata.get("cors_origin").unwrap(),
        "https://admin.example.com"
    );

    // Third (not allowed) — should return 403
    let mut ctx3 = make_cors_ctx("GET", "https://evil.com");
    let result3 = plugin.on_request_received(&mut ctx3).await;
    match result3 {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for disallowed origin"),
    }
}
