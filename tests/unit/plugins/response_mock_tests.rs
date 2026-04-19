//! Tests for response_mock plugin

use ferrum_edge::plugins::response_mock::ResponseMock;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::create_test_proxy;

fn make_proxy_with_listen_path(listen_path: &str) -> Arc<ferrum_edge::config::types::Proxy> {
    let mut proxy = create_test_proxy();
    proxy.listen_path = Some(listen_path.to_string());
    Arc::new(proxy)
}

/// Create a context simulating a request to `full_path` matched by a proxy
/// with the given `listen_path`.
fn make_ctx(method: &str, full_path: &str, listen_path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        full_path.to_string(),
    );
    ctx.matched_proxy = Some(make_proxy_with_listen_path(listen_path));
    ctx
}

// === Plugin creation ===

#[test]
fn test_creation_valid_config() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            { "path": "/users", "body": "[]" }
        ]
    }));
    assert!(plugin.is_ok());
    let plugin = plugin.unwrap();
    assert_eq!(plugin.name(), "response_mock");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::RESPONSE_MOCK
    );
}

#[test]
fn test_creation_missing_rules() {
    let err = ResponseMock::new(&json!({})).err().unwrap();
    assert!(err.contains("'rules' must be a JSON array"));
}

#[test]
fn test_creation_empty_rules() {
    let err = ResponseMock::new(&json!({ "rules": [] })).err().unwrap();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_creation_rule_missing_path() {
    let err = ResponseMock::new(&json!({
        "rules": [{ "body": "test" }]
    }))
    .err()
    .unwrap();
    assert!(err.contains("missing 'path'"));
}

#[test]
fn test_creation_invalid_regex() {
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "~[invalid" }]
    }))
    .err()
    .unwrap();
    assert!(err.contains("invalid regex"));
}

// === Path stripping — mock rules are relative to proxy listen_path ===

#[tokio::test]
async fn test_strips_listen_path_prefix() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/users",
            "status_code": 200,
            "body": "{\"users\": []}"
        }]
    }))
    .unwrap();

    // Proxy has listen_path /api/v1, request is /api/v1/users
    // Plugin should strip /api/v1 and match rule path /users
    let mut ctx = make_ctx("GET", "/api/v1/users", "/api/v1");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body, "{\"users\": []}");
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_request_to_listen_path_root_matches_slash() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/",
            "body": "{\"status\": \"ok\"}"
        }]
    }))
    .unwrap();

    // Request to exactly the listen_path with no trailing component → matches "/"
    let mut ctx = make_ctx("GET", "/api/v1", "/api/v1");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "{\"status\": \"ok\"}");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_match_with_wrong_relative_path() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/users",
            "body": "users"
        }],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    // /api/v1/posts → after stripping /api/v1, remaining is /posts → no match
    let mut ctx = make_ctx("GET", "/api/v1/posts", "/api/v1");
    let mut headers = HashMap::new();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_full_path_does_not_match_when_listen_path_stripped() {
    // Rule uses the full path /api/v1/users — should NOT match because
    // the plugin strips the listen_path prefix first.
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/api/v1/users",
            "body": "should not match"
        }],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/v1/users", "/api/v1");
    let mut headers = HashMap::new();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_regex_listen_path_uses_full_path() {
    // For regex listen_paths (~ prefix), no stripping occurs —
    // mock rules match against the full incoming path.
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/api/v1/users",
            "body": "full path match"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/v1/users", "~/api/v[0-9]+");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "full path match");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_matched_proxy_uses_full_path() {
    // Edge case: if matched_proxy is None, use full path
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/api/users",
            "body": "matched"
        }]
    }))
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "matched");
        }
        _ => panic!("Expected Reject"),
    }
}

// === Method matching ===

#[tokio::test]
async fn test_method_match() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "method": "POST",
            "path": "/users",
            "status_code": 201,
            "body": "{\"id\": 1}"
        }]
    }))
    .unwrap();

    // POST matches
    let mut ctx = make_ctx("POST", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 201),
        _ => panic!("Expected Reject"),
    }

    // GET does not match
    let mut ctx = make_ctx("GET", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body.contains("no mock rule matched"));
        }
        _ => panic!("Expected 404 Reject"),
    }
}

#[tokio::test]
async fn test_method_case_insensitive() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "method": "get",
            "path": "/users",
            "body": "[]"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users", "/api");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_no_method_matches_all() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/health",
            "body": "{\"ok\": true}"
        }]
    }))
    .unwrap();

    for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
        let mut ctx = make_ctx(method, "/svc/health", "/svc");
        let mut headers = HashMap::new();
        assert!(
            matches!(
                plugin.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Reject { .. }
            ),
            "Should match for method {}",
            method
        );
    }
}

// === Regex path matching (in mock rules, relative to listen_path) ===

#[tokio::test]
async fn test_regex_rule_path_match() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "~/users/[0-9]+",
            "body": "{\"id\": 42}"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users/42", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, "{\"id\": 42}");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_regex_rule_path_anchored() {
    // Regex is auto-anchored, so /users/42/profile should NOT match ~/users/[0-9]+
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "~/users/[0-9]+",
            "body": "matched"
        }],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users/42/profile", "/api");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_regex_wildcard_suffix() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "~/v[0-9]+/.*",
            "body": "versioned"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/v2/users/42/profile", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => assert_eq!(body, "versioned"),
        _ => panic!("Expected Reject"),
    }
}

// === Multiple rules — first match wins ===

#[tokio::test]
async fn test_first_match_wins() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            { "path": "/users", "body": "first" },
            { "path": "/users", "body": "second" }
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => assert_eq!(body, "first"),
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_multiple_rules_different_paths() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            { "path": "/users", "status_code": 200, "body": "users" },
            { "path": "/posts", "status_code": 200, "body": "posts" }
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/posts", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => assert_eq!(body, "posts"),
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_method_scoped_rules() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            { "method": "GET", "path": "/users", "body": "list" },
            { "method": "POST", "path": "/users", "status_code": 201, "body": "created" }
        ]
    }))
    .unwrap();

    let mut ctx = make_ctx("POST", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 201);
            assert_eq!(body, "created");
        }
        _ => panic!("Expected Reject"),
    }
}

// === Passthrough ===

#[tokio::test]
async fn test_passthrough_on_no_match() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/mocked", "body": "mocked" }],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/real", "/api");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_no_passthrough_returns_404() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/mocked", "body": "mocked" }],
        "passthrough_on_no_match": false
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/real", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body.contains("no mock rule matched"));
        }
        _ => panic!("Expected 404 Reject"),
    }
}

// === Custom headers ===

#[tokio::test]
async fn test_custom_response_headers() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/data",
            "headers": {
                "Content-Type": "text/plain",
                "X-Mock": "true"
            },
            "body": "hello"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/data", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("content-type").unwrap(), "text/plain");
            assert_eq!(headers.get("x-mock").unwrap(), "true");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_default_content_type_when_no_headers() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "body": "{}" }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/svc/test", "/svc");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
        }
        _ => panic!("Expected Reject"),
    }
}

// === Status code defaults ===

#[tokio::test]
async fn test_default_status_code_200() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "body": "ok" }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/svc/test", "/svc");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 200),
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_invalid_status_code_defaults_to_200() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "status_code": 999, "body": "ok" }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/svc/test", "/svc");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 200),
        _ => panic!("Expected Reject"),
    }
}

// === Delay ===

#[tokio::test]
async fn test_delay_ms_applied() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/slow",
            "body": "slow response",
            "delay_ms": 50
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/slow", "/api");
    let mut headers = HashMap::new();
    let start = std::time::Instant::now();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() >= 40, "Delay should be at least ~50ms");
    assert!(matches!(result, PluginResult::Reject { .. }));
}

// === Protocol support ===

#[test]
fn test_supported_protocols() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "body": "ok" }]
    }))
    .unwrap();

    assert_eq!(
        plugin.supported_protocols(),
        ferrum_edge::plugins::HTTP_FAMILY_PROTOCOLS
    );
}

// === Root listen_path ===

#[tokio::test]
async fn test_root_listen_path_no_stripping() {
    // When listen_path is "/", the special-case path means we use the full
    // request path: "/users" should match a rule for "/users".
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/users", "body": "root proxy" }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/users", "/");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => assert_eq!(body, "root proxy"),
        _ => panic!("Expected Reject"),
    }
}

// === UTF-8 boundary safety ===
//
// Defensive: ensure the listen_path strip never panics when ctx.path does not
// actually start with the listen_path (router bug or edge case). Previous
// byte-indexed slicing could panic mid-codepoint.

#[tokio::test]
async fn test_strip_handles_path_not_starting_with_listen_path() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/café", "body": "matched" }],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    // listen_path = "/api" (4 ASCII bytes), ctx.path = "/café" (6 bytes,
    // multibyte). The byte-indexed version would slice mid-codepoint at
    // position 4 (inside é) and panic. The strip_prefix-based code falls
    // back to the full path.
    let mut ctx = make_ctx("GET", "/café", "/api");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    // The full path "/café" matches the rule "/café"
    match result {
        PluginResult::Reject { body, .. } => assert_eq!(body, "matched"),
        _ => panic!("Expected Reject (mismatched listen_path falls back to full path)"),
    }
}

#[tokio::test]
async fn test_strip_handles_multibyte_listen_path() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/users", "body": "ok" }]
    }))
    .unwrap();

    // listen_path with multibyte chars, ctx.path correctly prefixed.
    // strip_prefix correctly yields "/users".
    let mut ctx = make_ctx("GET", "/café/users", "/café");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { body, .. } => assert_eq!(body, "ok"),
        _ => panic!("Expected Reject"),
    }
}
