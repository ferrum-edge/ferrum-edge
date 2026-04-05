use ferrum_edge::plugins::{PluginResult, create_plugin};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn create_grpc_context(path: &str) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = path.to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    ctx
}

// ── Plugin creation ──

#[test]
fn test_plugin_creation() {
    let config = json!({
        "deny_methods": ["/pkg.Svc/Dangerous"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();
    assert_eq!(plugin.name(), "grpc_method_router");
    assert_eq!(plugin.priority(), 275);
}

#[test]
fn test_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"grpc_method_router"));
}

#[test]
fn test_supported_protocols() {
    let config = json!({"deny_methods": ["/pkg.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0], ferrum_edge::plugins::ProxyProtocol::Grpc);
}

// ── gRPC path parsing and metadata population ──

#[tokio::test]
async fn test_metadata_populated_on_valid_path() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/my.package.UserService/GetUser");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    assert_eq!(
        ctx.metadata.get("grpc_service").unwrap(),
        "my.package.UserService"
    );
    assert_eq!(ctx.metadata.get("grpc_method").unwrap(), "GetUser");
    assert_eq!(
        ctx.metadata.get("grpc_full_method").unwrap(),
        "my.package.UserService/GetUser"
    );
}

#[tokio::test]
async fn test_metadata_populated_simple_service() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/Greeter/SayHello");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("grpc_service").unwrap(), "Greeter");
    assert_eq!(ctx.metadata.get("grpc_method").unwrap(), "SayHello");
}

#[tokio::test]
async fn test_invalid_path_no_metadata() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/invalid-path");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    assert!(!ctx.metadata.contains_key("grpc_service"));
    assert!(!ctx.metadata.contains_key("grpc_method"));
}

#[tokio::test]
async fn test_empty_path_no_metadata() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    assert!(!ctx.metadata.contains_key("grpc_service"));
}

#[tokio::test]
async fn test_path_with_extra_slashes_no_metadata() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/a/b/c");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Should not parse — method part contains slashes
    assert!(!ctx.metadata.contains_key("grpc_service"));
}

// ── Allow list enforcement ──

#[tokio::test]
async fn test_allow_list_permits_listed_method() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Allowed"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Allowed");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_allow_list_blocks_unlisted_method() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Allowed"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/NotAllowed");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

// ── Deny list enforcement ──

#[tokio::test]
async fn test_deny_list_blocks_listed_method() {
    let config = json!({
        "deny_methods": ["/pkg.Svc/Dangerous"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Dangerous");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_deny_list_allows_unlisted_method() {
    let config = json!({
        "deny_methods": ["/pkg.Svc/Dangerous"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Safe");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_deny_wins_over_allow() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Method"],
        "deny_methods": ["/pkg.Svc/Method"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Method");
    let _ = plugin.on_request_received(&mut ctx).await;

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

// ── Per-method rate limiting ──

#[tokio::test]
async fn test_method_rate_limiting_within_limit() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 5, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    for _ in 0..5 {
        let mut ctx = create_grpc_context("/pkg.Svc/Create");
        let _ = plugin.on_request_received(&mut ctx).await;
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }
}

#[tokio::test]
async fn test_method_rate_limiting_exceeded() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 2, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // First two should pass
    for _ in 0..2 {
        let mut ctx = create_grpc_context("/pkg.Svc/Create");
        let _ = plugin.on_request_received(&mut ctx).await;
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }

    // Third should be rate limited
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_different_methods_have_independent_limits() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 },
            "/pkg.Svc/Delete": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // Exhaust Create limit
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    // Delete should still work
    let mut ctx = create_grpc_context("/pkg.Svc/Delete");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_unlimited_method_passes_even_with_other_limits() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // Read has no limit, should always pass
    for _ in 0..10 {
        let mut ctx = create_grpc_context("/pkg.Svc/Read");
        let _ = plugin.on_request_received(&mut ctx).await;
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }
}

// ── Rate limiting by consumer ──

#[tokio::test]
async fn test_rate_limiting_by_consumer() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        },
        "limit_by": "consumer"
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // Consumer 1 exhausts limit
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    // Different consumer should pass (different IP, no consumer set)
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.client_ip = "10.0.0.2".to_string();
    ctx.identified_consumer = None;
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Rejection body format ──

#[tokio::test]
async fn test_rejection_body_format() {
    let config = json!({
        "deny_methods": ["/pkg.Svc/Blocked"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Blocked");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 403);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(parsed.get("error").is_some());
            assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_rate_limit_rejection_includes_headers() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // Exhaust limit
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Second request should be rejected with rate limit headers
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert!(headers.contains_key("x-grpc-ratelimit-limit"));
            assert!(headers.contains_key("x-grpc-ratelimit-remaining"));
            assert!(headers.contains_key("x-grpc-ratelimit-method"));
        }
        _ => panic!("Expected Reject"),
    }
}

// ── Tracked keys count ──

#[tokio::test]
async fn test_tracked_keys_count() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/A": { "max_requests": 100, "window_seconds": 60 },
            "/pkg.Svc/B": { "max_requests": 100, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_eq!(plugin.tracked_keys_count(), Some(0));

    // Trigger some rate checks
    let mut ctx = create_grpc_context("/pkg.Svc/A");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

// ── Empty config returns error ──

#[test]
fn test_empty_config_returns_error() {
    let result = create_plugin("grpc_method_router", &json!({}));
    let err = result.err().expect("Empty config should return Err");
    assert!(err.contains("no rules configured"), "got: {err}");
}

// ── Path edge cases ──

#[tokio::test]
async fn test_path_without_leading_slash() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("pkg.Svc/Method");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // No leading slash — not a valid gRPC path
    assert!(!ctx.metadata.contains_key("grpc_service"));
}

#[tokio::test]
async fn test_path_with_empty_method() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Empty method part — not valid
    assert!(!ctx.metadata.contains_key("grpc_service"));
}

#[tokio::test]
async fn test_path_with_empty_service() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("//Method");
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    assert!(!ctx.metadata.contains_key("grpc_service"));
}

// ── Rate limiting with authenticated_identity fallback ──

#[tokio::test]
async fn test_rate_limiting_by_authenticated_identity() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        },
        "limit_by": "consumer"
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // JWKS-authenticated user (no gateway Consumer, but authenticated_identity set)
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("jwks-user@example.com".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Same identity again — should be rate limited
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("jwks-user@example.com".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    // Different authenticated_identity should pass (separate bucket)
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("other-user@example.com".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_consumer_takes_precedence_over_authenticated_identity() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        },
        "limit_by": "consumer"
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // Consumer set — should use consumer.username ("testuser"), not authenticated_identity
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.authenticated_identity = Some("jwks-identity".to_string());
    // ctx.identified_consumer is set by create_test_context() -> "testuser"
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // Same consumer again — should be rate limited (keyed by "testuser")
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.authenticated_identity = Some("jwks-identity".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

// ── Non-parseable path passes through (no enforcement) ──

#[tokio::test]
async fn test_unparseable_path_skips_enforcement() {
    let config = json!({
        "deny_methods": ["/pkg.Svc/Method"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/not-a-grpc-path");
    let _ = plugin.on_request_received(&mut ctx).await;
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}
