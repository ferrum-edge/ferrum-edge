//! Tests for response_mock plugin

use ferrum_edge::plugins::response_mock::{
    RESPONSE_MOCK_CONFIG_KEYS, RESPONSE_MOCK_MATCH_KEYS, RESPONSE_MOCK_MAX_BODY_BYTES,
    RESPONSE_MOCK_MAX_DELAY_MS, RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES,
    RESPONSE_MOCK_MAX_HEADERS_PER_RULE, RESPONSE_MOCK_MAX_MATCH_CONDITIONS,
    RESPONSE_MOCK_MAX_RULES, RESPONSE_MOCK_RULE_KEYS, ResponseMock,
};
use ferrum_edge::plugins::utils::fault_delay::FaultDelayAdmission;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::plugin_utils::create_test_proxy;

/// Matched mocks and the plugin's own 404/500 answers are `RejectBinary`
/// (shared immutable bytes); render a body for substring assertions.
fn body_text(body: &bytes::Bytes) -> &str {
    std::str::from_utf8(body).expect("response_mock bodies are UTF-8")
}

/// A cancellation must return far faster than the delay it preempted. Kept
/// generous so a loaded CI runner cannot make it flaky.
const PROMPT: Duration = Duration::from_secs(5);

/// A delayed-work budget and shutdown token owned by one test.
type LocalDelayBounds = (&'static FaultDelayAdmission, &'static CancellationToken);

/// Caller-owned delay bounds, leaked to `'static` (one small allocation per
/// test). Never touches the process-global budget or shutdown token, which
/// other delay tests in the same binary rely on.
fn local_delay_bounds(capacity: usize) -> LocalDelayBounds {
    (
        Box::leak(Box::new(FaultDelayAdmission::new(capacity))),
        Box::leak(Box::new(CancellationToken::new())),
    )
}

fn make_proxy_with_listen_path(listen_path: &str) -> Arc<ferrum_edge::config::types::Proxy> {
    let mut proxy = create_test_proxy();
    proxy.listen_path = Some(listen_path.to_string());
    Arc::new(proxy)
}

fn make_host_only_proxy() -> Arc<ferrum_edge::config::types::Proxy> {
    let mut proxy = create_test_proxy();
    proxy.listen_path = None;
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

fn make_host_only_ctx(method: &str, full_path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        full_path.to_string(),
    );
    ctx.matched_proxy = Some(make_host_only_proxy());
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
fn test_creation_accepts_explicit_null_for_optional_fields() {
    let plugin = ResponseMock::new(&json!({
        "passthrough_on_no_match": null,
        "rules": [{
            "method": null,
            "path": "/",
            "status_code": null,
            "headers": null,
            "body": null,
            "delay_ms": null
        }]
    }));
    assert!(
        plugin.is_ok(),
        "explicit null optional fields must match omitted defaults"
    );
}

#[test]
fn test_creation_rejects_non_object_config() {
    let err = ResponseMock::new(&json!("bad")).err().unwrap();
    assert!(err.contains("config must be an object"));
}

#[test]
fn test_creation_missing_rules() {
    let err = ResponseMock::new(&json!({})).err().unwrap();
    assert!(err.contains("`rules` must be a JSON array"));
}

#[test]
fn test_creation_empty_rules() {
    let err = ResponseMock::new(&json!({ "rules": [] })).err().unwrap();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_creation_rejects_non_object_rule() {
    let err = ResponseMock::new(&json!({ "rules": [42] })).err().unwrap();
    assert_eq!(err, "response_mock: `rule[0]` must be an object");
}

#[test]
fn test_creation_rule_missing_path() {
    let err = ResponseMock::new(&json!({
        "rules": [{ "body": "test" }]
    }))
    .err()
    .unwrap();
    assert!(err.contains("missing `path`"));
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

#[test]
fn test_creation_rejects_invalid_field_shapes() {
    for (config, expected) in [
        (
            json!({
                "rules": [{ "path": "/test" }],
                "passthrough_on_no_match": "yes"
            }),
            "`passthrough_on_no_match` must be a boolean",
        ),
        (
            json!({ "rules": [{ "path": "/test", "method": 42 }] }),
            "`method` must be a string",
        ),
        (
            json!({ "rules": [{ "path": "/test", "method": "GET /admin" }] }),
            "`method` must be a valid HTTP method token",
        ),
        (
            json!({ "rules": [{ "path": "/test", "method": "GET\r\nX-Injected: yes" }] }),
            "`method` must be a valid HTTP method token",
        ),
        (
            json!({ "rules": [{ "path": "", "body": "test" }] }),
            "`path` must not be empty",
        ),
        (
            json!({ "rules": [{ "path": "/test", "headers": [] }] }),
            "`headers` must be an object",
        ),
        (
            json!({ "rules": [{ "path": "/test", "headers": { "x-test": 42 } }] }),
            "header \"x-test\" value must be a string",
        ),
        (
            json!({ "rules": [{ "path": "/test", "body": 42 }] }),
            "`body` must be a string",
        ),
        (
            json!({ "rules": [{ "path": "/test", "delay_ms": "50" }] }),
            "`delay_ms` must be an unsigned integer",
        ),
    ] {
        let err = ResponseMock::new(&config).err().unwrap();
        assert!(err.contains(expected), "expected {expected}, got: {err}");
    }
}

// delay_ms parks a live request, so it shares the fault-delay ceiling (one
// minute). The runtime clamps to the same value, so a larger configured value
// must be refused rather than silently shortened. (Finding #63 capped it at an
// hour; response_mock-CLAUDE-1 aligned it with fault_injection.)
#[test]
fn test_creation_rejects_delay_ms_over_cap() {
    assert_eq!(RESPONSE_MOCK_MAX_DELAY_MS, 60_000);
    for delay_ms in [60_001u64, 3_600_000] {
        let err = ResponseMock::new(&json!({
            "rules": [{ "path": "/test", "delay_ms": delay_ms }]
        }))
        .err()
        .unwrap_or_else(|| panic!("delay_ms {delay_ms} over 1 minute must be rejected"));
        assert!(err.contains("`delay_ms` must be <= 60000"), "got: {err}");
    }
}

#[test]
fn test_creation_accepts_delay_ms_at_cap() {
    // The boundary (exactly 1 minute) must be accepted.
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "delay_ms": 60_000u64 }]
    }));
    assert!(plugin.is_ok(), "delay_ms == cap should be accepted");
}

#[test]
fn test_creation_rejects_unknown_top_level_key() {
    let err = ResponseMock::new(&json!({
        "passthrough_on_no_mach": true,
        "rules": [{ "path": "/health", "body": "ok" }]
    }))
    .err()
    .expect("misspelled top-level key must be rejected");
    assert!(
        err.contains("unknown config key(s) under `config`"),
        "got: {err}"
    );
    assert!(err.contains("passthrough_on_no_mach"), "got: {err}");
    assert!(
        err.contains(RESPONSE_MOCK_CONFIG_KEYS[0]),
        "error should list allowed keys: {err}"
    );
}

#[test]
fn test_creation_rejects_unknown_rule_key() {
    let err = ResponseMock::new(&json!({
        "rules": [{
            "path": "/health",
            "status_cod": 503,
            "body": "unavailable"
        }]
    }))
    .err()
    .expect("misspelled rule key must be rejected");
    assert!(
        err.contains("unknown config key(s) under `config.rules[0]`"),
        "got: {err}"
    );
    assert!(err.contains("status_cod"), "got: {err}");
    assert!(
        err.contains(RESPONSE_MOCK_RULE_KEYS[0]),
        "error should list allowed keys: {err}"
    );
}

#[test]
fn test_creation_rejects_protocol_managed_response_headers() {
    for name in [
        "Connection",
        "CONTENT-LENGTH",
        "Transfer-Encoding",
        "Trailer",
        "Upgrade",
        "Keep-Alive",
        "proxy-connection",
        "TE",
        "Proxy-Authenticate",
    ] {
        let err = ResponseMock::new(&json!({
            "rules": [{
                "path": "/x",
                "headers": { name: "1" }
            }]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected rejection for header {name}"));
        assert!(err.contains("protocol-managed"), "{name}: {err}");
    }
}

#[test]
fn test_creation_accepts_status_code_boundaries() {
    for status_code in [200u64, 599] {
        let plugin = ResponseMock::new(&json!({
            "rules": [{ "path": "/test", "status_code": status_code, "body": "ok" }]
        }));
        assert!(
            plugin.is_ok(),
            "status_code {status_code} should be accepted"
        );
    }
}

#[test]
fn test_creation_rejects_unsupported_informational_status_codes() {
    // 101 included: a mock cannot upgrade the connection, and HTTP/2 / HTTP/3
    // cannot carry 101 at all (response_mock-SOL-1 / response_mock-CLAUDE-2).
    for status_code in [100u64, 101, 102, 103, 199] {
        let err = ResponseMock::new(&json!({
            "rules": [{ "path": "/test", "status_code": status_code, "body": "ok" }]
        }))
        .err()
        .unwrap_or_else(|| panic!("status_code {status_code} must be rejected"));
        assert!(
            err.contains("unsupported informational status"),
            "status {status_code}: {err}"
        );
    }
}

#[test]
fn test_creation_rejects_status_code_below_range() {
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "status_code": 99, "body": "ok" }]
    }))
    .err()
    .unwrap();
    assert!(err.contains("`status_code` must be in range 100-599"));
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
        PluginResult::RejectBinary {
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
        PluginResult::RejectBinary { body, .. } => {
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
        PluginResult::RejectBinary { body, .. } => {
            assert_eq!(body, "full path match");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_exact_listen_path_uses_full_path() {
    // Exact listen_paths (= prefix) are not prefix scopes for response_mock;
    // mock rules match against the full incoming path.
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/api/v1",
            "body": "full path match"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/v1", "=/api/v1");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary { body, .. } => {
            assert_eq!(body, "full path match");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_exact_listen_path_slash_rule_does_not_match() {
    // Unlike prefix listen paths, exact (=) scopes do not rewrite the request
    // to "/". A relative "/" rule therefore misses and returns the default 404.
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/",
            "body": "should not match"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/v1", "=/api/v1");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body_text(&body).contains("no mock rule matched"));
        }
        _ => panic!("Expected 404 Reject"),
    }
}

#[tokio::test]
async fn test_host_only_proxy_uses_full_path() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/health",
            "body": "host-only"
        }]
    }))
    .unwrap();

    let mut ctx = make_host_only_ctx("GET", "/health");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "host-only"),
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
        PluginResult::RejectBinary { body, .. } => {
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
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 201),
        _ => panic!("Expected Reject"),
    }

    // GET does not match
    let mut ctx = make_ctx("GET", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body_text(&body).contains("no mock rule matched"));
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
        PluginResult::RejectBinary { .. }
    ));
}

#[tokio::test]
async fn test_extension_method_matches_same_spelling_only() {
    // A valid mixed-case extension method must match the configured spelling
    // exactly; it must not be folded to uppercase.
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "method": "Foo",
            "path": "/users",
            "body": "extension-mock"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("Foo", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "extension-mock"),
        _ => panic!("Expected Reject for same-spelled extension method"),
    }

    // HTTP method tokens are case-sensitive, so a differently-cased extension
    // token does not match.
    let mut ctx = make_ctx("FOO", "/api/users", "/api");
    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body_text(&body).contains("no mock rule matched"));
        }
        _ => panic!("Expected 404 Reject for differently-cased extension method"),
    }
}

#[tokio::test]
async fn test_extension_method_mismatch_passthrough() {
    let plugin = ResponseMock::new(&json!({
        "passthrough_on_no_match": true,
        "rules": [{
            "method": "Foo",
            "path": "/users",
            "body": "extension-mock"
        }]
    }))
    .unwrap();

    // An extension-method rule must not be case-folded, so a `FOO` request is a
    // no-match and is passed through to the backend.
    let mut ctx = make_ctx("FOO", "/api/users", "/api");
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
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
                PluginResult::RejectBinary { .. }
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
        PluginResult::RejectBinary { body, .. } => {
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
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "versioned"),
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
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "first"),
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
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "posts"),
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
        PluginResult::RejectBinary {
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
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body_text(&body).contains("no mock rule matched"));
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
        PluginResult::RejectBinary { headers, .. } => {
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
        PluginResult::RejectBinary { headers, .. } => {
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
        PluginResult::RejectBinary { status_code, .. } => assert_eq!(status_code, 200),
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_invalid_status_code_rejects() {
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/test", "status_code": 999, "body": "ok" }]
    }))
    .err()
    .unwrap();

    assert!(err.contains("`status_code` must be in range 100-599"));
}

// === Delay ===

// === Delay retention bounds (response_mock-CLAUDE-1) ===
//
// `delay_ms` runs through the shared fault-delay machinery: process-wide
// admission budget, shutdown-drain cancellation, and HTTP/3 peer-departure
// cancellation. These tests inject caller-owned bounds so they never touch the
// process-global budget or one-shot shutdown token.

/// Test double for a frontend transport watch (the HTTP/3 QUIC
/// connection-close watch): observable without touching request bytes.
struct TestPeerWatch {
    gone: CancellationToken,
}

impl ferrum_edge::plugins::PeerConnectionWatch for TestPeerWatch {
    fn closed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let gone = self.gone.clone();
        Box::pin(async move { gone.cancelled().await })
    }

    fn is_closed(&self) -> bool {
        self.gone.is_cancelled()
    }
}

fn slow_mock(capacity: usize) -> (ResponseMock, LocalDelayBounds) {
    let (admission, shutdown) = local_delay_bounds(capacity);
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/slow", "body": "slow response", "delay_ms": 60_000u64 }]
    }))
    .unwrap()
    .with_delay_bounds(admission, shutdown);
    (plugin, (admission, shutdown))
}

fn assert_mock_served(result: PluginResult) {
    match result {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body, "slow response");
        }
        other => panic!("Expected the configured mock, got {other:?}"),
    }
}

#[tokio::test]
async fn test_delay_completes_within_budget_and_records_nothing() {
    let (admission, shutdown) = local_delay_bounds(4);
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/slow", "body": "slow response", "delay_ms": 20 }]
    }))
    .unwrap()
    .with_delay_bounds(admission, shutdown);

    let mut ctx = make_ctx("GET", "/api/slow", "/api");
    let started = std::time::Instant::now();
    let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    assert!(started.elapsed() >= Duration::from_millis(15));
    assert_mock_served(result);
    assert!(!ctx.metadata.contains_key("fault_delay_outcome"));
    assert_eq!(
        admission.in_flight(),
        0,
        "the permit is released after the delay"
    );
}

/// The amplifier the shared budget removes: once it is exhausted a matching
/// request is answered immediately instead of being parked.
#[tokio::test]
async fn test_delay_admission_exhausted_serves_mock_immediately() {
    let (plugin, (admission, _shutdown)) = slow_mock(0);
    let mut ctx = make_ctx("GET", "/api/slow", "/api");

    let started = std::time::Instant::now();
    let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    assert!(
        started.elapsed() < PROMPT,
        "an exhausted budget must skip the delay"
    );
    assert_mock_served(result);
    assert_eq!(
        ctx.metadata.get("fault_delay_outcome").map(String::as_str),
        Some("admission_exhausted")
    );
    assert_eq!(admission.in_flight(), 0);
}

/// Shutdown drain must release a parked mock at once instead of holding the
/// drain window for the full configured delay.
#[tokio::test]
async fn test_delay_shutdown_cancels_and_serves_mock() {
    let (plugin, (admission, shutdown)) = slow_mock(4);
    let mut ctx = make_ctx("GET", "/api/slow", "/api");

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown.cancel();
    });

    let started = std::time::Instant::now();
    let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    assert!(started.elapsed() < PROMPT, "shutdown must end the delay");
    assert_mock_served(result);
    assert_eq!(
        ctx.metadata.get("fault_delay_outcome").map(String::as_str),
        Some("shutdown")
    );
    assert_eq!(admission.in_flight(), 0);
}

/// A client that reaches a long mock delay and disappears must not keep the
/// request parked; nobody is left to read the mock.
#[tokio::test]
async fn test_delay_peer_departure_answers_499() {
    let (plugin, (admission, _shutdown)) = slow_mock(4);
    let gone = CancellationToken::new();
    let mut ctx = make_ctx("GET", "/api/slow", "/api");
    ctx.peer_connection = Some(ferrum_edge::plugins::PeerConnectionSignal::new(Arc::new(
        TestPeerWatch { gone: gone.clone() },
    )));

    let closer = gone.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        closer.cancel();
    });

    let started = std::time::Instant::now();
    let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    assert!(
        started.elapsed() < PROMPT,
        "peer departure must end the delay"
    );
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 499, "client-closed-request convention");
            assert!(body.is_empty(), "no body is owed to a departed client");
        }
        other => panic!("Expected a 499 reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata.get("fault_delay_outcome").map(String::as_str),
        Some("peer_gone")
    );
    assert_eq!(admission.in_flight(), 0);
}

/// An already-dead transport must not even consume a budget slot.
#[tokio::test]
async fn test_delay_with_already_closed_peer_skips_admission() {
    // Capacity 1 and a parked permit: admission would be exhausted, so a 499
    // here proves the pre-check ran before the budget was consulted.
    let (plugin, (admission, _shutdown)) = slow_mock(1);
    let _held = admission.try_admit().expect("one slot");
    let gone = CancellationToken::new();
    gone.cancel();
    let mut ctx = make_ctx("GET", "/api/slow", "/api");
    ctx.peer_connection = Some(ferrum_edge::plugins::PeerConnectionSignal::new(Arc::new(
        TestPeerWatch { gone },
    )));

    let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 499,
                ..
            }
        ),
        "got {result:?}"
    );
    assert_eq!(
        ctx.metadata.get("fault_delay_outcome").map(String::as_str),
        Some("peer_gone")
    );
    assert_eq!(
        admission.in_flight(),
        1,
        "only the test's own permit is held"
    );
}

/// Call-site audit: the mock delay must never return to a bare timer.
#[test]
fn test_delay_runs_through_the_shared_bounded_helper() {
    let source = include_str!("../../../src/plugins/response_mock.rs");
    assert_eq!(
        source.matches("run_fault_delay_in(").count(),
        1,
        "the rule delay must run through the bounded helper exactly once"
    );
    assert!(source.contains("self.delay_admission,"));
    assert!(!source.contains("tokio::time::sleep("));
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
        &[
            ferrum_edge::plugins::ProxyProtocol::Http,
            ferrum_edge::plugins::ProxyProtocol::WebSocket,
        ]
    );
    assert!(
        plugin
            .supported_protocols()
            .contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket),
        "response_mock intentionally participates in WebSocket upgrade handshakes"
    );
    assert!(
        !plugin
            .supported_protocols()
            .contains(&ferrum_edge::plugins::ProxyProtocol::Grpc),
        "native gRPC must be excluded (#2442): response_mock has no provenance-authorized \
         framed unary Reject contract — only serverless_function terminate does"
    );
}

// === WebSocket handshake short-circuit (HTTP Upgrade / Extended CONNECT) ===
//
// Runtime classifies upgrades as ProxyProtocol::WebSocket and still selects
// this plugin for HTTP + WebSocket. Matching only Rejects the handshake
// HTTP response; it never establishes a frame stream, so success-shaped (2xx)
// rules fail closed at a real handshake boundary and 101 is never accepted.

#[tokio::test]
async fn test_websocket_upgrade_matching_rule_short_circuits_handshake() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/socket",
            "status_code": 200,
            "body": "handshake-mock",
            "headers": { "x-mock": "ws" }
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/socket", "/api");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body, "handshake-mock");
            assert_eq!(headers.get("x-mock").map(String::as_str), Some("ws"));
        }
        _ => panic!("Expected Reject for matching WebSocket upgrade path"),
    }
}

#[tokio::test]
async fn test_websocket_upgrade_unmatched_default_returns_404() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/health", "body": "ok" }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/socket", "/api");
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 404);
            assert!(body_text(&body).contains("no mock rule matched"));
        }
        _ => panic!("Expected default 404 for unmatched WebSocket upgrade"),
    }
}

#[tokio::test]
async fn test_websocket_upgrade_unmatched_passthrough_continues() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/health", "body": "ok" }],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/socket", "/api");
    let mut headers = HashMap::new();

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

/// response_mock-SOL-1 / response_mock-CLAUDE-2: a mock never establishes a
/// WebSocket, so a success-shaped rule that matches a real handshake fails
/// closed with a final 500 instead of a 2xx that HTTP/2 / HTTP/3 Extended
/// CONNECT would read as an established tunnel (and HTTP/2 resets when it
/// carries a body). The same refusal applies on every frontend so one rule set
/// behaves identically on H1, H2, and H3.
#[tokio::test]
async fn test_websocket_handshake_success_status_fails_closed() {
    for status_code in [200u16, 204, 299] {
        let plugin = ResponseMock::new(&json!({
            "rules": [{
                "path": "/socket",
                "status_code": status_code,
                "body": "would-claim-an-open-tunnel",
                "delay_ms": 60_000u64
            }]
        }))
        .unwrap();

        let mut ctx = make_ctx("GET", "/api/socket", "/api");
        ferrum_edge::_test_support::set_websocket_response_boundary_for_test(&mut ctx, true);
        let mut headers = HashMap::new();

        // The refusal precedes the configured delay: nothing is parked.
        let started = std::time::Instant::now();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            started.elapsed() < PROMPT,
            "refusal must not wait out the delay"
        );
        match result {
            PluginResult::RejectBinary {
                status_code: returned,
                body,
                headers,
            } => {
                assert_eq!(returned, 500, "status {status_code}");
                assert!(
                    body_text(&body).contains("cannot mock a successful WebSocket handshake"),
                    "status {status_code}: {}",
                    body_text(&body)
                );
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
            }
            other => panic!("Expected fail-closed 500 for status {status_code}, got {other:?}"),
        }
    }
}

/// A non-2xx handshake mock is an ordinary final failure response on every
/// transport, so it is still served verbatim at the WebSocket boundary.
#[tokio::test]
async fn test_websocket_handshake_failure_status_is_served() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/socket",
            "status_code": 418,
            "body": "teapot",
            "headers": { "x-mock": "ws" }
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/socket", "/api");
    ferrum_edge::_test_support::set_websocket_response_boundary_for_test(&mut ctx, true);
    let mut headers = HashMap::new();

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 418);
            assert_eq!(body, "teapot");
            assert_eq!(headers.get("x-mock").map(String::as_str), Some("ws"));
        }
        other => panic!("Expected the configured 418 handshake mock, got {other:?}"),
    }
}

#[test]
fn test_status_101_is_rejected_at_construction() {
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/socket", "status_code": 101, "body": "" }]
    }))
    .err()
    .expect("101 can never be a valid terminal mock response");
    assert!(
        err.contains("unsupported informational status"),
        "got: {err}"
    );
    assert!(err.contains("`rule[0]`"), "got: {err}");
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
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "root proxy"),
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
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "matched"),
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
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "ok"),
        _ => panic!("Expected Reject"),
    }
}

/// Issue #2445: HEAD keeps representation Content-Length but omits content
/// bytes after shared synthetic-response finalization.
#[tokio::test]
async fn test_head_wire_omits_body_and_keeps_content_length() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{
            "path": "/head",
            "status_code": 200,
            "headers": { "content-type": "text/plain" },
            "body": "must-not-be-sent"
        }]
    }))
    .unwrap();

    let mut ctx = make_ctx("HEAD", "/api/head", "/api");
    let mut request_headers = HashMap::new();
    let rejection = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    let PluginResult::RejectBinary {
        status_code,
        body,
        headers,
    } = rejection
    else {
        panic!("Expected Reject");
    };
    assert_eq!(status_code, 200);
    assert_eq!(body, "must-not-be-sent");

    let plugins: Vec<std::sync::Arc<dyn Plugin>> = vec![std::sync::Arc::new(plugin)];
    let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
        &plugins,
        &mut ctx,
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        },
    )
    .await;

    match finalized {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert!(body.is_empty(), "HEAD wire body must be empty");
            assert_eq!(
                headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.as_str()),
                Some("16"),
                "HEAD Content-Length must match the configured representation"
            );
        }
        other => panic!("Expected finalized RejectBinary, got {other:?}"),
    }
}

/// Issue #2445: 204/205/304 suppress configured bodies and Content-Length.
#[tokio::test]
async fn test_no_body_statuses_suppress_configured_body_on_wire() {
    for status in [204u16, 205, 304] {
        let plugin = ResponseMock::new(&json!({
            "rules": [{
                "path": "/empty",
                "status_code": status,
                "body": "must-not-be-sent"
            }]
        }))
        .unwrap_or_else(|e| panic!("status {status} must accept a configured body: {e}"));

        let mut ctx = make_ctx("GET", "/api/empty", "/api");
        let mut request_headers = HashMap::new();
        let rejection = plugin.before_proxy(&mut ctx, &mut request_headers).await;
        let PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } = rejection
        else {
            panic!("Expected Reject for status {status}");
        };
        assert_eq!(status_code, status);
        assert_eq!(body, "must-not-be-sent");

        let plugins: Vec<std::sync::Arc<dyn Plugin>> = vec![std::sync::Arc::new(plugin)];
        let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
            &plugins,
            &mut ctx,
            PluginResult::RejectBinary {
                status_code,
                body,
                headers,
            },
        )
        .await;

        match finalized {
            PluginResult::RejectBinary {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(status_code, status);
                assert!(
                    body.is_empty(),
                    "status {status} must omit content bytes, got {} bytes",
                    body.len()
                );
                assert!(
                    !headers
                        .keys()
                        .any(|k| k.eq_ignore_ascii_case("content-length")),
                    "status {status} must strip Content-Length"
                );
            }
            other => panic!("Expected finalized RejectBinary for {status}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn prefix_trailing_slash_preserves_rule_path_coordinates() {
    let plugin = ResponseMock::new(&json!({
        "rules": [{"path": "/users", "body": "users"}, {"path": "/", "body": "root"}]
    }))
    .unwrap();
    for (listen, path, expected) in [
        ("/api/", "/api/users", "users"),
        ("/api", "/api/users", "users"),
        ("/api/", "/api/", "root"),
        ("/", "/users", "users"),
        ("~/users", "/users", "users"),
        ("=/users", "/users", "users"),
    ] {
        let mut ctx = make_ctx("GET", path, listen);
        let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
        let PluginResult::RejectBinary {
            status_code, body, ..
        } = result
        else {
            panic!("mock must match {listen} at {path}");
        };
        assert_eq!(status_code, 200);
        assert_eq!(body, expected);
        assert_eq!(ctx.path, path);
    }
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let token = "'\"`UNREGISTERED_TRAFFIC_TOKEN\\tail";
    for (config, field, reason) in [
        (json!({"rules": [token]}), "`rule[0]`", "must be an object"),
        (
            json!({"rules": [{"path": "/", "headers": {token: true}}]}),
            "`rule[0]`",
            "not a valid name",
        ),
        (
            json!({"rules": [{token: true}]}),
            "`config.rules[0]`",
            "unknown config key",
        ),
        (
            json!({"rules": [{"path": "/", "status_code": 103}]}),
            "`status_code`",
            "unsupported",
        ),
        (
            json!({"rules": [{"path": format!("~{token}[")}]}),
            "`rule[0].path`",
            "invalid regex",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("response_mock", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in [
            "UNREGISTERED_TRAFFIC_TOKEN",
            "918273641",
            "103",
            "true",
            "false",
        ] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// === Shared immutable bodies (response_mock-SOL-2) ===

/// The configured body is converted to `Bytes` once at construction; every
/// hit hands out a reference-counted clone of that one allocation instead of
/// copying the bytes per request (HEAD included).
#[tokio::test]
async fn test_matched_mock_bodies_share_one_allocation() {
    let configured = "x".repeat(4096);
    let plugin = ResponseMock::new(&json!({
        "rules": [{ "path": "/large", "body": configured }]
    }))
    .unwrap();

    let mut bodies = Vec::new();
    for method in ["GET", "GET", "HEAD"] {
        let mut ctx = make_ctx(method, "/api/large", "/api");
        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::RejectBinary { body, .. } => bodies.push(body),
            other => panic!("Expected RejectBinary for {method}, got {other:?}"),
        }
    }
    assert_eq!(bodies[0], configured.as_str());
    for body in &bodies[1..] {
        assert_eq!(
            body.as_ptr(),
            bodies[0].as_ptr(),
            "every hit must share the configured allocation"
        );
        assert_eq!(body.len(), configured.len());
    }
}

// === Indexed first-match (response_mock-CLAUDE-3) ===

/// Interleaved exact / regex / method / `match` rules must pick exactly the
/// winner an in-order scan would: an earlier regex shadows a later exact
/// rule, an earlier exact rule shadows a later regex, and an exact candidate
/// whose extra conditions fail falls through to later rules.
#[tokio::test]
async fn test_indexed_matching_preserves_ordered_first_match() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            { "method": "POST", "path": "~/users/[0-9]+", "body": "regex-post" },
            { "method": "GET", "path": "/users/1", "body": "exact-get" },
            { "path": "~/users/1", "body": "regex-one" },
            { "path": "/users/1", "body": "exact-any" },
            {
                "path": "/users/2",
                "match": { "headers": { "x-variant": "b" } },
                "body": "exact-variant"
            },
            { "path": "~/users/2", "body": "regex-two" },
            { "path": "/other", "body": "other" }
        ]
    }))
    .unwrap();

    for (method, path, variant, expected) in [
        ("POST", "/api/users/1", None, Some("regex-post")),
        ("POST", "/api/users/2", None, Some("regex-post")),
        ("GET", "/api/users/1", None, Some("exact-get")),
        ("PUT", "/api/users/1", None, Some("regex-one")),
        ("GET", "/api/users/2", Some("b"), Some("exact-variant")),
        ("GET", "/api/users/2", Some("c"), Some("regex-two")),
        ("GET", "/api/users/2", None, Some("regex-two")),
        ("GET", "/api/other", None, Some("other")),
        ("GET", "/api/users/3", None, None),
        ("GET", "/api/missing", None, None),
    ] {
        let mut ctx = make_ctx(method, path, "/api");
        if let Some(variant) = variant {
            ctx.headers
                .insert("x-variant".to_string(), variant.to_string());
        }
        let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
        match (result, expected) {
            (
                PluginResult::RejectBinary {
                    status_code, body, ..
                },
                Some(expected),
            ) => {
                assert_eq!(status_code, 200, "{method} {path}");
                assert_eq!(body, expected, "{method} {path} {variant:?}");
            }
            (
                PluginResult::RejectBinary {
                    status_code, body, ..
                },
                None,
            ) => {
                assert_eq!(status_code, 404, "{method} {path}");
                assert!(body_text(&body).contains("no mock rule matched"));
            }
            (other, _) => panic!("{method} {path}: unexpected {other:?}"),
        }
    }
}

/// Several regex rules whose combined prefilter rejects the path pass through
/// without matching any of them.
#[tokio::test]
async fn test_regex_prefilter_miss_passes_through() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            { "path": "~/users/[0-9]+", "body": "users" },
            { "path": "~/orders/[a-z]+", "body": "orders" },
            { "path": "~/v[0-9]+/.*", "body": "versioned" }
        ],
        "passthrough_on_no_match": true
    }))
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users/abc", "/api");
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Continue
    ));
    let mut ctx = make_ctx("GET", "/api/orders/abc", "/api");
    match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
        PluginResult::RejectBinary { body, .. } => assert_eq!(body, "orders"),
        other => panic!("Expected the orders mock, got {other:?}"),
    }
}

// === Construction bounds (response_mock-CLAUDE-4) ===

#[test]
fn test_rule_count_is_bounded() {
    let rules = |count: usize| -> Vec<serde_json::Value> {
        (0..count)
            .map(|i| json!({ "path": format!("/r{i}") }))
            .collect()
    };
    assert!(ResponseMock::new(&json!({ "rules": rules(RESPONSE_MOCK_MAX_RULES) })).is_ok());
    let err = ResponseMock::new(&json!({ "rules": rules(RESPONSE_MOCK_MAX_RULES + 1) }))
        .err()
        .expect("one rule over the cap must be rejected");
    assert!(
        err.contains(&format!("at most {RESPONSE_MOCK_MAX_RULES} rules")),
        "got: {err}"
    );
}

#[test]
fn test_body_size_is_bounded() {
    let at_cap = "b".repeat(RESPONSE_MOCK_MAX_BODY_BYTES);
    assert!(ResponseMock::new(&json!({ "rules": [{ "path": "/", "body": at_cap }] })).is_ok());

    let over = "b".repeat(RESPONSE_MOCK_MAX_BODY_BYTES + 1);
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/ok" }, { "path": "/", "body": over }]
    }))
    .err()
    .expect("an oversized body must be rejected");
    assert!(
        err.contains(&format!(
            "`rule[1]` `body` must be at most {RESPONSE_MOCK_MAX_BODY_BYTES} bytes"
        )),
        "got: {err}"
    );
}

#[test]
fn test_response_header_count_and_value_size_are_bounded() {
    let headers = |count: usize| -> serde_json::Map<String, serde_json::Value> {
        (0..count)
            .map(|i| (format!("x-h{i}"), json!("v")))
            .collect()
    };
    assert!(
        ResponseMock::new(&json!({
            "rules": [{ "path": "/", "headers": headers(RESPONSE_MOCK_MAX_HEADERS_PER_RULE) }]
        }))
        .is_ok()
    );
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/", "headers": headers(RESPONSE_MOCK_MAX_HEADERS_PER_RULE + 1) }]
    }))
    .err()
    .expect("too many response headers must be rejected");
    assert!(
        err.contains(&format!(
            "`rule[0]` `headers` must contain at most {RESPONSE_MOCK_MAX_HEADERS_PER_RULE} entries"
        )),
        "got: {err}"
    );

    let at_cap = "v".repeat(RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES);
    assert!(
        ResponseMock::new(&json!({
            "rules": [{ "path": "/", "headers": { "x-big": at_cap } }]
        }))
        .is_ok()
    );
    let over = "v".repeat(RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES + 1);
    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/", "headers": { "x-big": over } }]
    }))
    .err()
    .expect("an oversized response header value must be rejected");
    assert!(
        err.contains(&format!(
            "value must be at most {RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES} bytes"
        )),
        "got: {err}"
    );
}

// === Request conditions (response_mock-CLAUDE-5, ACCEPT-lite) ===

#[tokio::test]
async fn test_match_headers_select_a_variant_and_fall_through_otherwise() {
    let plugin = ResponseMock::new(&json!({
        "rules": [
            {
                "path": "/users",
                "match": { "headers": { "X-Scenario": "empty" } },
                "body": "[]"
            },
            { "path": "/users", "body": "[{\"id\":1}]" }
        ]
    }))
    .unwrap();

    for (header, expected) in [
        (Some("empty"), "[]"),
        // Values are compared byte-for-byte (case-sensitive).
        (Some("EMPTY"), "[{\"id\":1}]"),
        (Some("full"), "[{\"id\":1}]"),
        (None, "[{\"id\":1}]"),
    ] {
        let mut ctx = make_ctx("GET", "/api/users", "/api");
        if let Some(value) = header {
            ctx.headers
                .insert("x-scenario".to_string(), value.to_string());
        }
        match plugin.before_proxy(&mut ctx, &mut HashMap::new()).await {
            PluginResult::RejectBinary { body, .. } => {
                assert_eq!(body, expected, "x-scenario {header:?}")
            }
            other => panic!("Expected a mock for {header:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_match_query_params_and_headers_must_all_hold() {
    let plugin = ResponseMock::new(&json!({
        "passthrough_on_no_match": true,
        "rules": [{
            "path": "~/items",
            "match": {
                "headers": { "x-tenant": "acme" },
                "query_params": { "page": "2", "flag": "" }
            },
            "body": "page-two"
        }]
    }))
    .unwrap();

    for (tenant, page, flag, matched) in [
        (Some("acme"), Some("2"), true, true),
        (Some("acme"), Some("3"), true, false),
        (Some("acme"), Some("2"), false, false),
        (None, Some("2"), true, false),
        (Some("acme"), None, true, false),
    ] {
        let mut ctx = make_ctx("GET", "/api/items", "/api");
        if let Some(tenant) = tenant {
            ctx.headers
                .insert("x-tenant".to_string(), tenant.to_string());
        }
        if let Some(page) = page {
            ctx.query_params
                .insert("page".to_string(), page.to_string());
        }
        if flag {
            ctx.query_params.insert("flag".to_string(), String::new());
        }
        let result = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;
        match (result, matched) {
            (PluginResult::RejectBinary { body, .. }, true) => assert_eq!(body, "page-two"),
            (PluginResult::Continue, false) => {}
            (other, _) => panic!("{tenant:?} {page:?} {flag}: unexpected {other:?}"),
        }
    }
}

#[test]
fn test_match_null_is_equivalent_to_omission() {
    assert!(
        ResponseMock::new(&json!({
            "rules": [{ "path": "/", "match": null }]
        }))
        .is_ok()
    );
}

#[test]
fn test_match_configuration_is_validated() {
    let too_many: serde_json::Map<String, serde_json::Value> = (0
        ..=RESPONSE_MOCK_MAX_MATCH_CONDITIONS)
        .map(|i| (format!("x-c{i}"), json!("1")))
        .collect();
    let long_value = "v".repeat(RESPONSE_MOCK_MAX_HEADER_VALUE_BYTES + 1);
    for (rule_match, expected) in [
        (json!("x-test"), "`match` must be an object"),
        (
            json!({}),
            "`match` must contain `headers` or `query_params`",
        ),
        (
            json!({ "headers": [] }),
            "`match.headers` must be an object",
        ),
        (
            json!({ "headers": {} }),
            "`match.headers` must name at least one entry",
        ),
        (
            json!({ "headers": too_many }),
            "`match.headers` must name at most 16 entries",
        ),
        (
            json!({ "headers": { "bad name": "1" } }),
            "must be valid HTTP header names",
        ),
        (
            json!({ "headers": { "X-Consumer-Id": "alice" } }),
            "must not name gateway-asserted headers",
        ),
        (
            json!({ "headers": { "X-Test": "1", "x-test": "2" } }),
            "must be unique ignoring case",
        ),
        (
            json!({ "headers": { "x-test": 1 } }),
            "`match.headers` values must be strings",
        ),
        (
            json!({ "headers": { "x-test": "a\r\nb" } }),
            "must be valid HTTP header values",
        ),
        (
            json!({ "headers": { "x-test": long_value } }),
            "`match.headers` values must be at most 8192 bytes",
        ),
        (
            json!({ "query_params": "page=2" }),
            "`match.query_params` must be an object",
        ),
        (
            json!({ "query_params": { "": "2" } }),
            "`match.query_params` names must be 1-256 bytes",
        ),
        (
            json!({ "query_params": { "page": 2 } }),
            "`match.query_params` values must be strings",
        ),
    ] {
        let err = ResponseMock::new(&json!({
            "rules": [{ "path": "/", "match": rule_match }]
        }))
        .err()
        .unwrap_or_else(|| panic!("expected rejection for {rule_match}"));
        assert!(
            err.contains(expected),
            "{rule_match}: expected {expected}, got: {err}"
        );
    }

    let err = ResponseMock::new(&json!({
        "rules": [{ "path": "/", "match": { "header": { "x-test": "1" } } }]
    }))
    .err()
    .expect("misspelled match key must be rejected");
    assert!(
        err.contains("unknown config key(s) under `config.rules[0].match`"),
        "got: {err}"
    );
    assert!(err.contains(RESPONSE_MOCK_MATCH_KEYS[0]), "got: {err}");
}
