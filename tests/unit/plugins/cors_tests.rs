//! Tests for the CORS plugin

use ferrum_edge::plugins::cors::CorsPlugin;
use ferrum_edge::plugins::response_mock::ResponseMock;
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use serde_json::{Value, json};
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

fn permissive_backend_cors_headers() -> HashMap<String, String> {
    HashMap::from([
        ("access-control-allow-origin".to_string(), "*".to_string()),
        (
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        ),
        (
            "access-control-allow-methods".to_string(),
            "GET, POST, PUT, DELETE".to_string(),
        ),
        (
            "access-control-allow-headers".to_string(),
            "Authorization, X-Admin".to_string(),
        ),
        (
            "access-control-expose-headers".to_string(),
            "X-Secret".to_string(),
        ),
        ("access-control-max-age".to_string(), "99999".to_string()),
        (
            "Access-Control-Allow-Private-Network".to_string(),
            "true".to_string(),
        ),
        ("x-backend".to_string(), "ok".to_string()),
    ])
}

fn assert_no_access_control_headers(headers: &HashMap<String, String>) {
    assert!(
        headers
            .keys()
            .all(|name| !name.to_ascii_lowercase().starts_with("access-control-")),
        "backend Access-Control-* headers must be removed: {headers:?}"
    );
}

// ── Config parsing ───────────────────────────────────────────────────

#[tokio::test]
async fn test_cors_plugin_creation_defaults() {
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();
    assert_eq!(plugin.name(), "cors");
    assert_eq!(plugin.priority(), priority::CORS);
    assert_eq!(plugin.priority(), 100);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_constructor_rejects_noop_non_object_unknown_and_null_configs() {
    for config in [
        json!({}),
        json!(null),
        json!(true),
        json!([]),
        json!("cors"),
        json!(42),
    ] {
        assert!(
            CorsPlugin::new(&config).is_err(),
            "no-op or non-object config must be rejected: {config}"
        );
    }

    for config in [
        json!({"origins": ["https://app.example"]}),
        json!({"allowed_origins": ["https://app.example"], "allowed_origns": ["*"]}),
    ] {
        assert!(
            CorsPlugin::new(&config).is_err(),
            "unknown or null config must be rejected: {config}"
        );
    }

    for key in [
        "allowed_origins",
        "allowed_methods",
        "allowed_headers",
        "exposed_headers",
        "allow_credentials",
        "max_age",
        "preflight_continue",
        "unmatched_preflights",
    ] {
        let mut config = json!({"allowed_origins": ["*"]});
        config[key] = Value::Null;
        assert!(
            CorsPlugin::new(&config).is_err(),
            "null field must be rejected: {key}"
        );
    }
}

#[test]
fn test_constructor_rejects_padded_method_and_header_tokens() {
    for config in [
        json!({"allowed_origins": ["*"], "allowed_methods": [" GET"]}),
        json!({"allowed_origins": ["*"], "allowed_headers": ["X-Test "]}),
    ] {
        let err = CorsPlugin::new(&config)
            .err()
            .expect("whitespace-padded policy tokens must be rejected");
        assert!(err.contains("leading or trailing whitespace"), "got: {err}");
    }
}

#[test]
fn test_constructor_rejects_non_array_allowed_origins() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": "https://example.com"
    }))
    .err()
    .expect("allowed_origins must reject non-array values");

    assert!(err.contains("allowed_origins"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_allowed_origins() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": []
    }))
    .err()
    .expect("empty allowed_origins must be rejected");

    assert!(err.contains("at least one origin"), "got: {err}");
}

#[test]
fn test_constructor_rejects_non_string_origin_entry() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [42]
    }))
    .err()
    .expect("non-string origin entries must be rejected");

    assert!(err.contains("entries must be strings"), "got: {err}");
}

#[test]
fn test_constructor_validates_every_origin_even_when_list_contains_wildcard() {
    for config in [
        json!({"allowed_origins": ["*", 42]}),
        json!({"allowed_origins": [{"exact": "*"}, {"prefix": ""}]}),
    ] {
        assert!(
            CorsPlugin::new(&config).is_err(),
            "a wildcard must not hide a malformed sibling matcher: {config}"
        );
    }
}

#[test]
fn test_constructor_rejects_malformed_exact_origin() {
    for origin in ["example.com", "https://exa\nmple.com"] {
        assert!(
            CorsPlugin::new(&json!({"allowed_origins": [origin]})).is_err(),
            "malformed exact origin must be rejected: {origin:?}"
        );
    }
}

#[test]
fn test_constructor_rejects_exact_origin_with_empty_authority() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["https:///example.com"]
    }))
    .err()
    .expect("empty authority exact origin must be rejected");

    assert!(err.contains("hostname"), "got: {err}");
}

#[tokio::test]
async fn test_constructor_rejects_exact_origin_with_raw_post_authority() {
    for origin in [
        "https://example.com/api",
        "https://example.com/foo/..",
        "https://example.com/%2e%2e",
        "https://example.com\\foo\\..",
    ] {
        // NATIVE plain-string form only: it canonicalizes, so a raw
        // post-authority component could collapse to `/` and be serialized as
        // permission for the whole origin.
        let err = CorsPlugin::new(&json!({"allowed_origins": [origin]}))
            .err()
            .expect("origins with a raw post-authority component must be rejected");
        assert!(err.contains("without path"), "got: {err}");

        // The Istio `{exact}` matcher is LITERAL (issue #3254): nothing is
        // canonicalized, so there is nothing to collapse. It is accepted and
        // matches ONLY that literal string — strictly narrower than the
        // canonicalizing form, never wider.
        let plugin = CorsPlugin::new(&json!({"allowed_origins": [{"exact": origin}]}))
            .expect("a literal exact matcher is accepted verbatim");
        assert!(
            !plugin_allows_origin(&plugin, "https://example.com").await,
            "literal exact `{origin}` must not authorize the bare origin"
        );
        assert!(
            plugin_allows_origin(&plugin, origin).await,
            "literal exact `{origin}` must authorize exactly its own string"
        );
    }
}

/// Drive one actual cross-origin request and report whether the policy allowed
/// it (the 403 rejection is the plugin's disallowed-origin signal).
async fn plugin_allows_origin(plugin: &CorsPlugin, origin: &str) -> bool {
    let mut ctx = make_cors_ctx("GET", origin);
    matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    )
}

#[test]
fn test_constructor_rejects_malformed_wildcard_origin() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*example.com"]
    }))
    .err()
    .expect("wildcard origins without dot must be rejected");

    assert!(err.contains("*.example.com"), "got: {err}");
}

#[test]
fn test_constructor_rejects_invalid_method() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "allowed_methods": ["GET", "BAD METHOD"]
    }))
    .err()
    .expect("invalid method tokens must be rejected");

    assert!(err.contains("invalid HTTP method"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_allowed_methods() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "allowed_methods": []
    }))
    .err()
    .expect("empty allowed_methods must be rejected");

    assert!(err.contains("allowed_methods"), "got: {err}");
}

#[test]
fn test_constructor_rejects_invalid_header_name() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "allowed_headers": ["Content-Type", "Bad Header"]
    }))
    .err()
    .expect("invalid allowed header names must be rejected");

    assert!(err.contains("invalid HTTP header name"), "got: {err}");
}

#[test]
fn test_constructor_rejects_non_bool_allow_credentials() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "allow_credentials": "true"
    }))
    .err()
    .expect("non-bool allow_credentials must be rejected");

    assert!(err.contains("allow_credentials"), "got: {err}");
}

#[test]
fn test_constructor_rejects_non_integer_max_age() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "max_age": -1
    }))
    .err()
    .expect("negative max_age must be rejected");

    assert!(err.contains("max_age"), "got: {err}");
}

#[tokio::test]
async fn test_cors_plugin_credentials_wildcard_conflict() {
    // allow_credentials with wildcard origins should disable credentials
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "allow_credentials": true
    }))
    .unwrap();

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
    }))
    .unwrap();

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
    }))
    .unwrap();

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
            for token in [
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
            ] {
                assert!(
                    headers["vary"]
                        .split(',')
                        .any(|value| value.trim().eq_ignore_ascii_case(token)),
                    "missing preflight Vary token {token}: {}",
                    headers["vary"]
                );
            }
        }
        _ => panic!("Expected Reject for preflight"),
    }
}

#[tokio::test]
async fn test_preflight_with_disallowed_origin() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

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
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();

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
        "allowed_origins": ["*"],
        "allowed_methods": ["GET", "POST"],
        "allowed_headers": ["Authorization", "Content-Type"]
    }))
    .unwrap();

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
        "allowed_origins": ["*"],
        "max_age": 3600
    }))
    .unwrap();

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
        "allowed_origins": ["*"],
        "preflight_continue": true
    }))
    .unwrap();

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
async fn test_preflight_continue_replaces_backend_policy_with_complete_gateway_policy() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "allowed_methods": ["PUT"],
        "allowed_headers": ["X-Custom"],
        "exposed_headers": ["X-Response"],
        "allow_credentials": true,
        "max_age": 600,
        "preflight_continue": true
    }))
    .unwrap();
    let mut ctx = make_preflight_ctx("https://app.example", "PUT");
    ctx.headers.insert(
        "access-control-request-headers".to_string(),
        "X-Custom".to_string(),
    );
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut response_headers = permissive_backend_cors_headers();
    response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 202, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        response_headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(response_headers["access-control-allow-methods"], "PUT");
    assert_eq!(response_headers["access-control-allow-headers"], "X-Custom");
    assert_eq!(response_headers["access-control-max-age"], "600");
    assert_eq!(response_headers["access-control-allow-credentials"], "true");
    assert_eq!(
        response_headers["access-control-expose-headers"],
        "X-Response"
    );
    assert!(!response_headers.contains_key("Access-Control-Allow-Private-Network"));
    for token in [
        "Accept-Encoding",
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ] {
        assert!(
            response_headers["vary"]
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case(token)),
            "missing Vary token {token}: {}",
            response_headers["vary"]
        );
    }
}

#[tokio::test]
async fn test_istio_omitted_policy_fields_and_unmatched_modes_are_preserved() {
    let forward = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "unmatched_preflights": "forward"
    }))
    .unwrap();

    let mut allowed = make_preflight_ctx("https://app.example", "DELETE");
    match forward.on_request_received(&mut allowed).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(
                headers["access-control-allow-origin"],
                "https://app.example"
            );
            assert!(!headers.contains_key("access-control-allow-methods"));
            assert!(!headers.contains_key("access-control-allow-headers"));
            assert!(!headers.contains_key("access-control-max-age"));
        }
        _ => panic!("matching Istio preflight must be answered locally"),
    }

    let mut unmatched_preflight = make_preflight_ctx("https://other.example", "DELETE");
    assert!(matches!(
        forward.on_request_received(&mut unmatched_preflight).await,
        PluginResult::Continue
    ));
    let mut upstream_headers = permissive_backend_cors_headers();
    let _ = forward
        .after_proxy(&mut unmatched_preflight, 299, &mut upstream_headers)
        .await;
    assert_no_access_control_headers(&upstream_headers);
    assert_eq!(upstream_headers.len(), 1);
    assert_eq!(upstream_headers["x-backend"], "ok");

    let mut unmatched_actual = make_cors_ctx("DELETE", "https://other.example");
    assert!(matches!(
        forward.on_request_received(&mut unmatched_actual).await,
        PluginResult::Continue
    ));
    let mut actual_headers = permissive_backend_cors_headers();
    let _ = forward
        .after_proxy(&mut unmatched_actual, 200, &mut actual_headers)
        .await;
    assert_no_access_control_headers(&actual_headers);
    assert_eq!(actual_headers["x-backend"], "ok");

    let mut matched_actual = make_cors_ctx("DELETE", "https://app.example");
    matched_actual
        .headers
        .insert("authorization".to_string(), "Bearer test".to_string());
    assert!(matches!(
        forward.on_request_received(&mut matched_actual).await,
        PluginResult::Continue
    ));
    let mut matched_actual_headers = HashMap::new();
    let _ = forward
        .after_proxy(&mut matched_actual, 200, &mut matched_actual_headers)
        .await;
    assert_eq!(
        matched_actual_headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert!(!matched_actual_headers.contains_key("access-control-allow-methods"));
    assert!(!matched_actual_headers.contains_key("access-control-allow-headers"));

    let ignore = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "unmatched_preflights": "ignore"
    }))
    .unwrap();
    let mut ignored = make_preflight_ctx("https://other.example", "GET");
    match ignore.on_request_received(&mut ignored).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert!(body.is_empty());
            assert!(headers.is_empty());
        }
        _ => panic!("IGNORE must answer an unmatched preflight locally"),
    }
}

#[tokio::test]
async fn test_istio_forward_owns_access_control_headers_without_origin() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "unmatched_preflights": "forward"
    }))
    .unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut response_headers = permissive_backend_cors_headers();
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_no_access_control_headers(&response_headers);
    assert_eq!(response_headers.len(), 1);
    assert_eq!(response_headers["x-backend"], "ok");
}

#[tokio::test]
async fn test_istio_policy_without_origin_strips_response_mock_access_control_headers() {
    let cors = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "unmatched_preflights": "forward"
    }))
    .unwrap();
    let response_mock = ResponseMock::new(&json!({
        "rules": [{
            "path": "/test",
            "status_code": 202,
            "body": "synthetic body",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "X-Mock": "preserved"
            }
        }]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        cors.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut request_headers = HashMap::new();
    let (status_code, body, mut response_headers) = match response_mock
        .before_proxy(&mut ctx, &mut request_headers)
        .await
    {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body, headers),
        _ => panic!("response_mock must short-circuit the request"),
    };
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());

    assert!(matches!(
        cors.after_proxy(&mut ctx, status_code, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(status_code, 202);
    assert_eq!(body, "synthetic body");
    assert_no_access_control_headers(&response_headers);
    assert_eq!(response_headers["x-mock"], "preserved");
}

#[tokio::test]
async fn test_response_mock_headers_survive_rejection_without_cors_participation() {
    let cors = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "unmatched_preflights": "forward"
    }))
    .unwrap();
    let response_mock = ResponseMock::new(&json!({
        "rules": [{
            "path": "/test",
            "status_code": 202,
            "body": "synthetic body",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "X-Mock": "preserved"
            }
        }]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut request_headers = HashMap::new();
    let (status_code, body, mut response_headers) = match response_mock
        .before_proxy(&mut ctx, &mut request_headers)
        .await
    {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body, headers),
        _ => panic!("response_mock must short-circuit the request"),
    };
    let expected_headers = response_headers.clone();
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());

    assert!(matches!(
        cors.after_proxy(&mut ctx, status_code, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(status_code, 202);
    assert_eq!(body, "synthetic body");
    assert_eq!(response_headers, expected_headers);
}

#[test]
fn test_istio_mode_rejects_direct_preflight_continue_combination() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "unmatched_preflights": "forward",
        "preflight_continue": false
    }))
    .err()
    .expect("the direct and Istio forwarding controls must be mutually exclusive");
    assert!(err.contains("cannot be combined"), "got: {err}");
}

#[tokio::test]
async fn test_preflight_disallowed_method() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*"],
        "allowed_methods": ["GET", "POST"]
    }))
    .unwrap();

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
async fn test_actual_request_does_not_apply_preflight_method_or_header_lists() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example"],
        "allowed_methods": ["GET"],
        "allowed_headers": ["X-Test"],
        "exposed_headers": ["X-Response"],
        "allow_credentials": true
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("DELETE", "https://app.example");
    ctx.headers
        .insert("authorization".to_string(), "Bearer test".to_string());
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut response_headers = HashMap::new();
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        response_headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(
        response_headers["access-control-expose-headers"],
        "X-Response"
    );
    assert_eq!(response_headers["access-control-allow-credentials"], "true");
    assert!(!response_headers.contains_key("access-control-allow-methods"));
    assert!(!response_headers.contains_key("access-control-allow-headers"));
}

#[tokio::test]
async fn test_non_options_with_origin_passes_through() {
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();

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
    }))
    .unwrap();

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
    }))
    .unwrap();

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
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();

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
    }))
    .unwrap();

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
    }))
    .unwrap();

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
        "allowed_origins": ["*"],
        "exposed_headers": ["X-Request-ID", "X-RateLimit-Remaining"]
    }))
    .unwrap();

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
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();

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

#[tokio::test]
async fn test_native_policy_without_origin_still_strips_backend_access_control_headers() {
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));

    let mut response_headers = permissive_backend_cors_headers();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert_no_access_control_headers(&response_headers);
    assert_eq!(response_headers["x-backend"], "ok");
}

#[tokio::test]
async fn test_after_proxy_without_participating_policy_preserves_backend_headers() {
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();
    let mut ctx = make_ctx();
    let mut response_headers = permissive_backend_cors_headers();
    let expected = response_headers.clone();

    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert_eq!(response_headers, expected);
}

#[tokio::test]
async fn test_after_proxy_removes_backend_access_control_headers_when_origin_not_approved() {
    let plugin = CorsPlugin::new(&json!({
        "preflight_continue": true,
        "allowed_origins": ["https://trusted.example"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.example");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::from([
        ("access-control-allow-origin".to_string(), "*".to_string()),
        (
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        ),
        ("x-test".to_string(), "ok".to_string()),
    ]);

    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert!(!response_headers.contains_key("access-control-allow-origin"));
    assert!(!response_headers.contains_key("access-control-allow-credentials"));
    assert_eq!(
        response_headers.get("x-test").map(String::as_str),
        Some("ok")
    );
}

// ── Vary header tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_vary_header_set_for_specific_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

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
    let plugin = CorsPlugin::new(&json!({"allowed_origins": ["*"]})).unwrap();

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
    }))
    .unwrap();

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
    }))
    .unwrap();

    // Origins are compared case-insensitively — mismatched case should be allowed
    let mut ctx = make_cors_ctx("GET", "https://Example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Expected Continue for case-mismatched origin (case-insensitive comparison)"
    );
    assert_eq!(
        ctx.metadata.get("cors_origin").map(|s| s.as_str()),
        Some("https://Example.com"),
    );
}

#[tokio::test]
async fn test_plain_string_exact_origins_are_canonicalized_on_the_config_path() {
    for (configured, request) in [
        ("HTTPS://EXAMPLE.COM:443", "https://example.com"),
        ("http://example.com:80", "http://example.com"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
        ("http://127.1:80", "http://127.0.0.1"),
        (
            "https://[2001:0db8:0000:0000:0000:ff00:0042:8329]:443",
            "https://[2001:db8::ff00:42:8329]",
        ),
        ("https://example.com:8443", "https://example.com:8443"),
    ] {
        // NATIVE plain-string form only. The Istio `{exact}` object matcher is
        // deliberately NOT canonicalized (issue #3254) — see
        // `test_object_exact_origin_is_literal_and_never_widened`.
        let plugin = CorsPlugin::new(&json!({"allowed_origins": [configured]})).unwrap();
        let mut ctx = make_cors_ctx("GET", request);
        assert!(
            matches!(
                plugin.on_request_received(&mut ctx).await,
                PluginResult::Continue
            ),
            "configured {configured} should match browser origin {request}"
        );
    }
}

/// Issue #3254: the Istio `{exact}` matcher is a LITERAL, case-sensitive,
/// byte-for-byte comparison. It must never be canonicalized into the browser
/// serialization (which would authorize an origin the source never matched),
/// and a wildcard-shaped literal must never become native wildcard-subdomain
/// syntax (which would authorize every subdomain).
#[tokio::test]
async fn test_object_exact_origin_is_literal_and_never_widened() {
    for (configured, canonical) in [
        ("HTTPS://EXAMPLE.COM:443", "https://example.com"),
        ("http://example.com:80", "http://example.com"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
        ("http://127.1:80", "http://127.0.0.1"),
    ] {
        let plugin = CorsPlugin::new(&json!({"allowed_origins": [{"exact": configured}]}))
            .expect("a literal exact matcher is accepted verbatim");
        assert!(
            plugin_allows_origin(&plugin, configured).await,
            "literal `{configured}` must match its own string"
        );
        assert!(
            !plugin_allows_origin(&plugin, canonical).await,
            "literal `{configured}` must NOT be widened to canonical `{canonical}`"
        );
    }

    // The headline case: a wildcard-SHAPED literal authorizes only itself.
    let plugin = CorsPlugin::new(&json!({"allowed_origins": [{"exact": "*.example.com"}]}))
        .expect("a wildcard-shaped literal exact is representable");
    for subdomain in [
        "https://app.example.com",
        "https://deep.sub.example.com",
        "https://example.com",
    ] {
        assert!(
            !plugin_allows_origin(&plugin, subdomain).await,
            "a literal `*.example.com` must not authorize `{subdomain}` as native wildcard syntax would"
        );
    }
    assert!(
        plugin_allows_origin(&plugin, "*.example.com").await,
        "the literal matcher still matches its own exact string"
    );

    // Contrast: the NATIVE plain-string form keeps wildcard-subdomain meaning.
    let native = CorsPlugin::new(&json!({"allowed_origins": ["*.example.com"]}))
        .expect("native wildcard syntax is unchanged");
    assert!(
        plugin_allows_origin(&native, "https://app.example.com").await,
        "the native plain-string form must keep wildcard-subdomain semantics"
    );
}

#[tokio::test]
async fn test_non_default_port_origin_stays_distinct_in_both_matcher_forms() {
    for allowed_origins in [
        json!(["https://example.com:8443"]),
        json!([{"exact": "https://example.com:8443"}]),
    ] {
        let non_default = CorsPlugin::new(&json!({"allowed_origins": allowed_origins})).unwrap();
        let mut mismatch = make_cors_ctx("GET", "https://example.com");
        assert!(matches!(
            non_default.on_request_received(&mut mismatch).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn test_istio_exact_star_has_allow_all_semantics_in_both_forms() {
    for allowed_origins in [json!([{"exact": "*"}]), json!(["*"])] {
        let plugin = CorsPlugin::new(&json!({
            "allowed_origins": allowed_origins,
            "allowed_methods": [],
            "allowed_headers": [],
            "unmatched_preflights": "forward"
        }))
        .unwrap();
        let mut ctx = make_cors_ctx("GET", "https://anything.example");
        assert!(matches!(
            plugin.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ));
        let mut headers = HashMap::new();
        let _ = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
        assert_eq!(headers["access-control-allow-origin"], "*");
    }
}

#[tokio::test]
async fn test_multiple_origins_in_config() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://app.example.com", "https://admin.example.com"]
    }))
    .unwrap();

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

// ── Wildcard subdomain origin tests ─────────────────────────────────

#[tokio::test]
async fn test_wildcard_subdomain_origin_matches() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match https://app.company.com"
    );
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "https://app.company.com"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_deep_subdomain_matches() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://deep.sub.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match https://deep.sub.company.com"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_rejects_non_match() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject for non-matching origin"),
    }
}

#[tokio::test]
async fn test_wildcard_subdomain_does_not_match_bare_domain() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    // "company.com" has no subdomain prefix, so it should NOT match "*.company.com"
    let mut ctx = make_cors_ctx("GET", "https://company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject — bare domain should not match wildcard subdomain"),
    }
}

#[tokio::test]
async fn test_wildcard_subdomain_case_insensitive() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.Company.Com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://APP.COMPANY.COM");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Wildcard subdomain matching should be case-insensitive"
    );
}

// Regression for finding #51: wildcard-subdomain matching must enforce the
// same http(s) scheme allow-list as exact-origin matching. A non-http scheme
// (e.g. `ftp://`) that suffix-matches the host must NOT be allowed/reflected.
#[tokio::test]
async fn test_wildcard_subdomain_rejects_non_http_scheme() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "ftp://app.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject — non-http scheme must not match wildcard subdomain"),
    }
    assert!(!ctx.metadata.contains_key("cors_origin"));
}

#[tokio::test]
async fn test_wildcard_subdomain_rejects_malformed_origin_authority() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    for origin in [
        "https://user@app.company.com",
        "https://app.company.com/path",
        "https://app.company.com?query",
        "https://app.company.com:99999",
        "https://app..company.com",
    ] {
        let mut ctx = make_cors_ctx("GET", origin);
        assert!(
            matches!(
                plugin.on_request_received(&mut ctx).await,
                PluginResult::Reject {
                    status_code: 403,
                    ..
                }
            ),
            "malformed Origin must not match a wildcard policy: {origin}"
        );
    }
}

// No-regression guard for finding #51: `http://` (not just `https://`) must
// still match a wildcard-subdomain rule.
#[tokio::test]
async fn test_wildcard_subdomain_allows_plain_http_scheme() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "http://app.company.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match http://app.company.com"
    );
    assert_eq!(
        ctx.metadata.get("cors_origin").unwrap(),
        "http://app.company.com"
    );
}

#[tokio::test]
async fn test_mixed_exact_and_wildcard_origins() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://exact.com", "*.company.com"]
    }))
    .unwrap();

    // Exact match
    let mut ctx1 = make_cors_ctx("GET", "https://exact.com");
    let result1 = plugin.on_request_received(&mut ctx1).await;
    assert!(
        matches!(result1, PluginResult::Continue),
        "Exact origin should match"
    );

    // Wildcard subdomain match
    let mut ctx2 = make_cors_ctx("GET", "https://app.company.com");
    let result2 = plugin.on_request_received(&mut ctx2).await;
    assert!(
        matches!(result2, PluginResult::Continue),
        "Wildcard subdomain should match"
    );

    // Neither
    let mut ctx3 = make_cors_ctx("GET", "https://evil.com");
    let result3 = plugin.on_request_received(&mut ctx3).await;
    assert!(
        matches!(
            result3,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "Unmatched origin should be rejected"
    );
}

#[tokio::test]
async fn test_star_in_list_with_other_origins_becomes_wildcard() {
    // If "*" appears anywhere in the list, treat the whole config as Wildcard
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*", "https://specific.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://anything.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "\"*\" in list should make all origins allowed"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_preflight() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://app.company.com", "POST");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 204);
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://app.company.com",
                "Preflight should reflect the actual origin, not the pattern"
            );
        }
        _ => panic!("Expected 204 Reject for approved preflight"),
    }
}

#[tokio::test]
async fn test_wildcard_subdomain_reflects_origin_in_response() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.company.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://app.company.com",
        "Response should reflect the actual matched origin, not the wildcard pattern"
    );
}

#[tokio::test]
async fn test_wildcard_subdomain_with_port() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["*.company.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.company.com:8443");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "*.company.com should match https://app.company.com:8443"
    );
}

// ── Vary header merge — preserves backend Vary while adding Origin ───
//
// Regression: previously `after_proxy` blindly inserted `Vary: Origin`,
// clobbering any backend Vary value (e.g., compression's
// `Vary: Accept-Encoding`). That broke downstream caches.

#[tokio::test]
async fn test_vary_header_merges_with_existing_backend_vary() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    let vary = response_headers.get("vary").unwrap();
    assert!(
        vary.contains("Accept-Encoding"),
        "merged Vary must preserve backend Accept-Encoding, got: {}",
        vary
    );
    assert!(
        vary.to_ascii_lowercase().contains("origin"),
        "merged Vary must include Origin, got: {}",
        vary
    );
}

#[tokio::test]
async fn test_vary_header_origin_already_present_not_duplicated() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert("vary".to_string(), "origin, Accept-Language".to_string());
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    let vary = response_headers.get("vary").unwrap();
    // Case-insensitive match — should not duplicate
    let origin_count = vary
        .split(',')
        .filter(|tok| tok.trim().eq_ignore_ascii_case("Origin"))
        .count();
    assert_eq!(
        origin_count, 1,
        "Origin already present (case-insensitive) must not be duplicated, got: {}",
        vary
    );
    assert!(
        vary.contains("Accept-Language"),
        "other tokens must be preserved"
    );
}

#[tokio::test]
async fn test_vary_header_wildcard_preserved_origin_redundant() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    // Vary: * means "any header" — adding Origin would be redundant per RFC 9110.
    response_headers.insert("vary".to_string(), "*".to_string());
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("vary").unwrap(),
        "*",
        "Vary: * must be preserved (Origin would be redundant)"
    );
}

#[tokio::test]
async fn test_after_proxy_rejection_with_cors_origin_strips_stale_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": ["https://example.com"],
        "allow_credentials": false
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://example.com");
    let _ = plugin.on_request_received(&mut ctx).await;
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert(
        "access-control-allow-credentials".to_string(),
        "true".to_string(),
    );
    response_headers.insert(
        "access-control-expose-headers".to_string(),
        "x-secret".to_string(),
    );

    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;

    assert_eq!(
        response_headers.get("access-control-allow-origin"),
        Some(&"https://example.com".to_string())
    );
    assert!(!response_headers.contains_key("access-control-allow-credentials"));
    assert!(!response_headers.contains_key("access-control-expose-headers"));
}

// ── Istio StringMatch object origin matchers (exact / prefix / regex) ────────
//
// These back the VirtualService `corsPolicy` `prefix`/`regex` origin
// projection: a `corsPolicy.allowOrigins[]` StringMatch entry is emitted into
// `allowed_origins` as `{exact|prefix|regex}`, and the plugin reflects a
// matching Origin into `Access-Control-Allow-Origin` and 403s a non-match.

#[tokio::test]
async fn test_object_exact_origin_matches_and_reflects() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"exact": "https://app.example.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "{{exact}} matcher should match the same origin string"
    );

    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://app.example.com",
        "a matched origin is reflected verbatim"
    );
}

#[tokio::test]
async fn test_prefix_origin_matches_and_reflects() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app."}]
    }))
    .unwrap();

    // Matching origin: starts with the literal prefix → reflected.
    let mut ctx = make_cors_ctx("GET", "https://app.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "prefix matcher should admit an origin that starts with the prefix"
    );
    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://app.example.com",
    );
}

#[tokio::test]
async fn test_prefix_origin_rejects_non_match() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app."}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://evil.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert_eq!(body, "CORS origin not allowed");
        }
        _ => panic!("Expected 403 Reject — origin without the prefix must not match"),
    }
    assert!(!ctx.metadata.contains_key("cors_origin"));
}

#[tokio::test]
async fn test_regex_origin_full_match_reflects() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://.*\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://sub.example.com");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "regex matcher should admit a fully-matching origin"
    );
    let mut response_headers: HashMap<String, String> = HashMap::new();
    let _ = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("access-control-allow-origin").unwrap(),
        "https://sub.example.com",
    );
}

#[tokio::test]
async fn test_regex_origin_rejects_non_match() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://.*\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://sub.evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        _ => panic!("Expected 403 Reject — origin not matching the regex"),
    }
}

#[tokio::test]
async fn test_regex_origin_requires_full_match_not_substring() {
    // Istio `StringMatch.regex` is a FULL match. A pattern that matches only a
    // substring of the Origin must NOT admit it (no implicit `.*` on the ends),
    // so a trailing-garbage origin is rejected even though the prefix matches.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://app\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.example.com.evil.com");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(
            status_code, 403,
            "regex must full-match; a suffix-extended origin must be rejected"
        ),
        _ => panic!("Expected 403 Reject — regex is a full match, not a substring search"),
    }
}

#[tokio::test]
async fn test_regex_origin_alternation_full_match_accepts_later_branch() {
    // Regression for the anchored-vs-first-find bug: with a top-level
    // alternation whose FIRST branch is a strict prefix of the Origin, an
    // unanchored `find` returns the shorter leading match and the full-length
    // check rejects the Origin — even though a LATER branch matches the whole
    // string. Anchoring the compiled pattern (`^(?:...)$`) makes `is_match`
    // try every branch, so the Origin is correctly admitted.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://app|https://app\\.example\\.com"}]
    }))
    .unwrap();

    let mut ctx = make_cors_ctx("GET", "https://app.example.com");
    assert!(
        matches!(
            plugin.on_request_received(&mut ctx).await,
            PluginResult::Continue
        ),
        "a later alternation branch fully matching the Origin must admit it"
    );
}

#[tokio::test]
async fn test_mixed_string_and_object_origin_matchers() {
    // Plain-string and object matchers can be mixed in one `allowed_origins`.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [
            "https://exact.example.com",
            {"prefix": "https://app."},
            {"regex": "https://.*\\.api\\.example\\.com"}
        ]
    }))
    .unwrap();

    for origin in [
        "https://exact.example.com",
        "https://app.anything.com",
        "https://v2.api.example.com",
    ] {
        let mut ctx = make_cors_ctx("GET", origin);
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "origin {origin} should match one of the mixed matchers"
        );
    }

    let mut ctx = make_cors_ctx("GET", "https://nope.com");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        _ => panic!("Expected 403 Reject for an origin matching none of the matchers"),
    }
}

#[tokio::test]
async fn test_preflight_with_prefix_origin_emits_cors_headers() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app."}],
        "allowed_methods": ["GET", "POST"]
    }))
    .unwrap();

    let mut ctx = make_preflight_ctx("https://app.example.com", "POST");
    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 204);
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "https://app.example.com",
            );
        }
        _ => panic!("Expected 204 preflight approval for a prefix-matched origin"),
    }
}

#[test]
fn test_constructor_rejects_uncompilable_regex_origin() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://(example"}]
    }))
    .err()
    .expect("an un-compilable regex origin must be rejected at config time");
    assert!(err.contains("regex matcher"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_prefix_origin() {
    // An empty prefix would match every origin — reject it rather than create
    // an accidental allow-all policy.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": ""}]
    }))
    .err()
    .expect("an empty prefix origin must be rejected");
    assert!(err.contains("prefix matcher"), "got: {err}");
}

#[test]
fn test_constructor_rejects_multi_key_origin_matcher() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app.", "regex": "https://.*"}]
    }))
    .err()
    .expect("an object matcher with two keys must be rejected");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn test_constructor_rejects_object_matcher_with_non_string_extra_key() {
    // Regression: a recognized key with a NON-string value (here `regex`)
    // alongside a valid string key must NOT be silently dropped, leaving a bare
    // prefix matcher — the StringMatch contract is exactly one well-typed key.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app.", "regex": 123}]
    }))
    .err()
    .expect("an object matcher with an extra (non-string) key must be rejected");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn test_constructor_rejects_object_matcher_with_unknown_key() {
    // An unknown key must be rejected rather than ignored while a sibling valid
    // key is honored.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"prefix": "https://app.", "bogus": "x"}]
    }))
    .err()
    .expect("an object matcher with an unknown key must be rejected");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn test_constructor_rejects_empty_object_origin_matcher() {
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{}]
    }))
    .err()
    .expect("an object matcher with no exact/prefix/regex must be rejected");
    assert!(
        err.contains("exact") && err.contains("prefix") && err.contains("regex"),
        "got: {err}"
    );
}

// ── Bounded origin matchers (issue #3253) ─────────────────────────────────
//
// Regex origins are compiled ONCE at config construction/reload under explicit
// byte, complexity, and count bounds. An over-budget matcher is a config error
// with a field-specific diagnostic — never a silently dropped, truncated, or
// approximated matcher, and never a per-request compile.

#[test]
fn test_constructor_rejects_oversized_origin_matchers() {
    let oversized = "a".repeat(600);
    for allowed_origins in [
        json!([oversized.clone()]),
        json!([{"exact": &oversized}]),
        json!([{"prefix": &oversized}]),
        json!([{"regex": &oversized}]),
    ] {
        let err = CorsPlugin::new(&json!({"allowed_origins": allowed_origins.clone()}))
            .err()
            .unwrap_or_else(|| panic!("an oversized matcher must be rejected: {allowed_origins}"));
        assert!(
            err.contains("byte matcher limit") && err.contains("allowed_origins"),
            "got: {err}"
        );
    }
}

#[test]
fn test_constructor_rejects_too_many_origin_matchers() {
    let too_many: Vec<serde_json::Value> = (0..65)
        .map(|i| json!({"exact": format!("https://app{i}.example.com")}))
        .collect();
    let err = CorsPlugin::new(&json!({"allowed_origins": too_many}))
        .err()
        .expect("an over-budget matcher list must be rejected");
    assert!(err.contains("at most 64 entries"), "got: {err}");

    // Exactly at the bound is accepted — the ceiling is inclusive.
    let at_bound: Vec<serde_json::Value> = (0..64)
        .map(|i| json!({"exact": format!("https://app{i}.example.com")}))
        .collect();
    CorsPlugin::new(&json!({"allowed_origins": at_bound}))
        .expect("a matcher list exactly at the bound is accepted");
}

#[test]
fn test_constructor_rejects_over_complex_origin_regex() {
    // Deeply nested groups exceed the explicit AST nesting bound even though
    // the pattern is short and syntactically valid.
    let err = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "((((((((((((((((((((((((((((a))))))))))))))))))))))))))))"}]
    }))
    .err()
    .expect("an over-complex regex origin must be rejected");
    assert!(err.contains("complexity bounds"), "got: {err}");
}

#[test]
fn test_constructor_rejects_whitespace_only_exact_matcher() {
    let err = CorsPlugin::new(&json!({"allowed_origins": [{"exact": "   "}]}))
        .err()
        .expect("a whitespace-only exact matcher must be rejected");
    assert!(err.contains("non-whitespace"), "got: {err}");
}

#[tokio::test]
async fn test_safe_regex_origin_positives_and_negatives() {
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"regex": "https://[a-z0-9-]+\\.api\\.example\\.com"}]
    }))
    .expect("a bounded, safe regex origin compiles at config time");

    for allowed in ["https://v2.api.example.com", "https://a-b.api.example.com"] {
        assert!(
            plugin_allows_origin(&plugin, allowed).await,
            "`{allowed}` must full-match the configured regex"
        );
    }
    for denied in [
        // Full match, not a substring search: no implicit `.*` on either end.
        "https://v2.api.example.com.evil.com",
        "https://evil.com/https://v2.api.example.com",
        "https://api.example.com",
        "http://v2.api.example.com",
    ] {
        assert!(
            !plugin_allows_origin(&plugin, denied).await,
            "`{denied}` must not be authorized by the anchored regex"
        );
    }
}

#[tokio::test]
async fn test_credentialed_literal_exact_preflight_reflects_the_source_origin() {
    // Issue #3254 + credentialed CORS: a literal exact is a concrete origin, so
    // credentials remain usable and the response reflects that exact string
    // rather than `*`.
    let plugin = CorsPlugin::new(&json!({
        "allowed_origins": [{"exact": "https://app.example.com"}],
        "allow_credentials": true
    }))
    .expect("credentialed literal exact policy constructs");

    let mut ctx = make_preflight_ctx("https://app.example.com", "POST");
    let result = plugin.on_request_received(&mut ctx).await;
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = result
    else {
        panic!("an allowed preflight is answered locally");
    };
    assert_eq!(status_code, 204);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://app.example.com")
    );
    assert_eq!(
        headers
            .get("access-control-allow-credentials")
            .map(String::as_str),
        Some("true")
    );

    // An uncredentialed disallowed origin is still fail-closed.
    let mut denied = make_preflight_ctx("https://evil.example.com", "POST");
    assert!(matches!(
        plugin.on_request_received(&mut denied).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}
