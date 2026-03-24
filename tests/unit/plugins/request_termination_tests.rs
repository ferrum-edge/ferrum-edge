//! Tests for request_termination plugin

use ferrum_gateway::plugins::request_termination::RequestTermination;
use ferrum_gateway::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

fn make_ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

fn make_ctx_with_header(method: &str, path: &str, header: &str, value: &str) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(header.to_string(), value.to_string());
    ctx
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = RequestTermination::new(&json!({}));
    assert_eq!(plugin.name(), "request_termination");
    assert_eq!(plugin.priority(), 75);
}

// === Always trigger ===

#[tokio::test]
async fn test_always_trigger_rejects() {
    let plugin = RequestTermination::new(&json!({}));
    let mut ctx = make_ctx("GET", "/anything");

    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 503); // default
            assert!(body.contains("Service unavailable"));
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_custom_status_code() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 418
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 418);
            assert!(body.contains("418"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_invalid_status_code_falls_back_to_503() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 999
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 503);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_status_code_zero_falls_back_to_503() {
    let plugin = RequestTermination::new(&json!({
        "status_code": 0
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 503);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Custom body ===

#[tokio::test]
async fn test_custom_body() {
    let plugin = RequestTermination::new(&json!({
        "body": "Custom maintenance page",
        "content_type": "text/plain"
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "Custom maintenance page");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_custom_message_in_json() {
    let plugin = RequestTermination::new(&json!({
        "message": "Under maintenance"
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("Under maintenance"));
            assert!(body.contains("503"));
            // Verify it's valid JSON
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["message"], "Under maintenance");
            assert_eq!(parsed["status_code"], 503);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_json_escaping_in_message() {
    let plugin = RequestTermination::new(&json!({
        "message": "Error: \"invalid\" request\\path"
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            // Body should be valid JSON with properly escaped characters
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
            assert!(parsed.is_ok(), "Body should be valid JSON: {}", body);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_xml_response_body() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "application/xml",
        "message": "Service down"
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(headers.get("content-type").unwrap(), "application/xml");
            assert!(body.contains("<?xml version=\"1.0\"?>"));
            assert!(body.contains("<message>Service down</message>"));
            assert!(body.contains("<status_code>503</status_code>"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_xml_escaping() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "text/xml",
        "message": "Error <b>bad</b> & \"quoted\""
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("&lt;b&gt;bad&lt;/b&gt;"));
            assert!(body.contains("&amp;"));
            assert!(body.contains("&quot;quoted&quot;"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_plain_text_response() {
    let plugin = RequestTermination::new(&json!({
        "content_type": "text/plain",
        "message": "Maintenance"
    }));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "Maintenance");
        }
        _ => panic!("Expected Reject"),
    }
}

// === Path prefix trigger ===

#[tokio::test]
async fn test_path_prefix_trigger_matches() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/admin" }
    }));

    let mut ctx = make_ctx("GET", "/admin/settings");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_path_prefix_trigger_no_match() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/admin" }
    }));

    let mut ctx = make_ctx("GET", "/api/users");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_path_prefix_exact_match() {
    let plugin = RequestTermination::new(&json!({
        "trigger": { "path_prefix": "/maintenance" }
    }));

    let mut ctx = make_ctx("GET", "/maintenance");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

// === Header match trigger ===

#[tokio::test]
async fn test_header_trigger_matches() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Debug",
            "header_value": "true"
        }
    }));

    let mut ctx = make_ctx_with_header("GET", "/", "x-debug", "true");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_header_trigger_value_mismatch() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Debug",
            "header_value": "true"
        }
    }));

    let mut ctx = make_ctx_with_header("GET", "/", "x-debug", "false");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_header_trigger_missing_header() {
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Debug",
            "header_value": "true"
        }
    }));

    let mut ctx = make_ctx("GET", "/");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_header_trigger_any_value() {
    // When header_value is empty, any value should match
    let plugin = RequestTermination::new(&json!({
        "trigger": {
            "header": "X-Maintenance"
        }
    }));

    let mut ctx = make_ctx_with_header("GET", "/", "x-maintenance", "anything");
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

// === Edge cases ===

#[tokio::test]
async fn test_boundary_status_codes() {
    // Minimum valid status code
    let plugin = RequestTermination::new(&json!({ "status_code": 100 }));
    let mut ctx = make_ctx("GET", "/");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 100),
        _ => panic!("Expected Reject"),
    }

    // Maximum valid status code
    let plugin = RequestTermination::new(&json!({ "status_code": 599 }));
    let mut ctx = make_ctx("GET", "/");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 599),
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_empty_message_uses_default() {
    let plugin = RequestTermination::new(&json!({}));
    let mut ctx = make_ctx("GET", "/");

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            assert!(body.contains("Service unavailable"));
        }
        _ => panic!("Expected Reject"),
    }
}
