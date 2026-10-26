use ferrum_edge::plugins::{GRPC_ONLY_PROTOCOLS, Plugin, PluginResult, create_plugin, priority};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn create_grpc_context(path: &str) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.path = path.to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    ctx
}

async fn enforce_effective_path(
    plugin: &dyn Plugin,
    ctx: &mut ferrum_edge::plugins::RequestContext,
) -> PluginResult {
    let path = ctx.path.clone();
    plugin.on_backend_path_resolved(ctx, &path).await
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
    assert_eq!(plugin.priority(), priority::GRPC_METHOD_ROUTER);
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(plugin.requires_backend_path_resolution());
    assert!(!plugin.applies_after_proxy_on_reject());
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
    assert_eq!(plugin.supported_protocols(), GRPC_ONLY_PROTOCOLS);
}

/// Every configuration enforces an allow list, deny list, or rate limit, so
/// the instance is request-admission policy: a route configured with it is
/// gRPC-intended and refuses the plain HTTP and WebSocket flavors that would
/// skip it (issue #6110).
#[test]
fn every_configuration_gates_request_admission() {
    for config in [
        json!({"allow_methods": ["pkg.Svc/Allowed"]}),
        json!({"deny_methods": ["pkg.Svc/Blocked"]}),
        json!({"method_rate_limits": {"pkg.Svc/Hot": {"max_requests": 5, "window_seconds": 60}}}),
    ] {
        let plugin = create_plugin("grpc_method_router", &config)
            .unwrap()
            .unwrap();
        assert!(plugin.gates_request_admission(), "{config}");
        assert!(!plugin.is_auth_plugin(), "{config}");
    }
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

#[tokio::test]
async fn test_backend_effective_rewrite_refreshes_metadata_before_enforcement() {
    let config = json!({
        "allow_methods": ["/public.Service/Allowed"],
        "deny_methods": ["/admin.Service/Delete"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/public.Service/Allowed");
    assert_continue(plugin.on_request_received(&mut ctx).await);
    assert_eq!(
        ctx.metadata.get("grpc_full_method").map(String::as_str),
        Some("public.Service/Allowed")
    );

    let result = plugin
        .on_backend_path_resolved(&mut ctx, "/admin.Service/Delete")
        .await;
    assert_reject(result, Some(403));
    assert_eq!(
        ctx.metadata.get("grpc_service").map(String::as_str),
        Some("admin.Service")
    );
    assert_eq!(
        ctx.metadata.get("grpc_method").map(String::as_str),
        Some("Delete")
    );
    assert_eq!(
        ctx.metadata.get("grpc_full_method").map(String::as_str),
        Some("admin.Service/Delete")
    );
}

#[tokio::test]
async fn test_stripped_prefix_is_enforced_as_backend_effective_method() {
    let config = json!({"deny_methods": ["/pkg.Svc/Denied"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/prefix/pkg.Svc/Denied");
    assert_continue(plugin.on_request_received(&mut ctx).await);
    assert!(!ctx.metadata.contains_key("grpc_full_method"));

    let result = plugin
        .on_backend_path_resolved(&mut ctx, "/pkg.Svc/Denied")
        .await;
    assert_reject(result, Some(403));
    assert_eq!(
        ctx.metadata.get("grpc_full_method").map(String::as_str),
        Some("pkg.Svc/Denied")
    );
}

#[tokio::test]
async fn test_invalid_backend_effective_rewrite_clears_provisional_metadata() {
    let config = json!({"deny_methods": ["/pkg.Svc/Denied"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/public.Service/Allowed");
    assert_continue(plugin.on_request_received(&mut ctx).await);
    assert!(ctx.metadata.contains_key("grpc_full_method"));

    let result = plugin
        .on_backend_path_resolved(&mut ctx, "/invalid/extra/segment")
        .await;
    assert_reject(result, Some(403));
    assert!(!ctx.metadata.contains_key("grpc_service"));
    assert!(!ctx.metadata.contains_key("grpc_method"));
    assert!(!ctx.metadata.contains_key("grpc_full_method"));
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

    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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

    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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

    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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

    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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

    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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
        let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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
        let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
        assert_continue(result);
    }

    // Third should be rate limited
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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
    let _ = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_reject(result, Some(429));

    // Delete should still work
    let mut ctx = create_grpc_context("/pkg.Svc/Delete");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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
        let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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
    let _ = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_reject(result, Some(429));

    // Different consumer should pass (different IP, no consumer set)
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.client_ip = "10.0.0.2".to_string();
    ctx.identified_consumer = None;
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
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
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

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
async fn test_rejection_body_escapes_untrusted_method_path() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Allowed"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Bad\"Method");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    match result {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                parsed["error"],
                "backend-effective gRPC method path could not be parsed"
            );
            assert!(!body.contains("Bad\\\"Method"));
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
    let _ = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    // Second request should be rejected with rate limit headers
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

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
    let _ = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

// ── Empty config returns error ──

#[test]
fn test_empty_config_returns_error() {
    let result = create_plugin("grpc_method_router", &json!({}));
    let err = result.err().expect("Empty config should return Err");
    assert!(err.contains("no rules configured"), "got: {err}");
}

#[test]
fn test_empty_additive_rules_return_error() {
    for config in [
        json!({"deny_methods": []}),
        json!({"method_rate_limits": {}}),
    ] {
        let result = create_plugin("grpc_method_router", &config);
        let err = result
            .err()
            .expect("empty additive rule should be rejected");
        assert!(err.contains("no rules configured"), "got: {err}");
    }
}

// ── Constructor validation: limit_by ──

#[test]
fn test_unknown_limit_by_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "deny_methods": ["/blocked/X"],
            "limit_by": "user"
        }),
    );
    let err = result.err().expect("unknown limit_by must be rejected");
    assert!(err.contains("`limit_by` must be one of"), "got: {err}");
}

#[test]
fn test_limit_by_consumer_accepted() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "deny_methods": ["/blocked/X"],
            "limit_by": "consumer"
        }),
    );
    assert!(result.is_ok());
}

// ── Constructor validation: method lists ──

#[test]
fn test_non_array_method_list_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({"deny_methods": "/pkg.Svc/Blocked"}),
    );
    let err = result
        .err()
        .expect("non-array deny_methods must be rejected");
    assert!(
        err.contains("`deny_methods` must be an array"),
        "got: {err}"
    );
}

#[test]
fn test_non_string_method_list_entry_rejected() {
    let result = create_plugin("grpc_method_router", &json!({"allow_methods": [42]}));
    let err = result
        .err()
        .expect("non-string allow_methods entry must be rejected");
    assert!(
        err.contains("`allow_methods[0]` must be a string"),
        "got: {err}"
    );
}

#[test]
fn test_invalid_method_list_entry_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({"deny_methods": ["/pkg.Svc/"]}),
    );
    let err = result.err().expect("invalid method path must be rejected");
    assert!(err.contains("invalid gRPC method path"), "got: {err}");
}

#[test]
fn test_duplicate_method_list_entry_rejected_after_normalization() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({"deny_methods": ["/pkg.Svc/Blocked", "pkg.Svc/Blocked"]}),
    );
    let err = result
        .err()
        .expect("duplicate normalized method must be rejected");
    assert!(err.contains("duplicate method"), "got: {err}");
}

#[test]
fn test_empty_allow_list_is_valid_block_all_config() {
    let result = create_plugin("grpc_method_router", &json!({"allow_methods": []}));
    assert!(result.is_ok());
}

#[test]
fn test_warmup_hostnames_for_redis() {
    let plugin = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 5, "window_seconds": 60 }
            },
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0"
        }),
    )
    .unwrap()
    .unwrap();

    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["cache.internal".to_string()]
    );
}

#[test]
fn test_accepts_redis_connect_timeout_above_one_second() {
    // Issue #2310: values above the redis-rs 1s default must remain admissible.
    let plugin = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 5, "window_seconds": 60 }
            },
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_connect_timeout_seconds": 5
        }),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["cache.internal".to_string()]
    );
}

// ── Constructor validation: rate-limit specs ──

#[test]
fn test_zero_max_requests_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 0, "window_seconds": 60 }
            }
        }),
    );
    let err = result.err().expect("max_requests=0 should be rejected");
    assert!(
        err.contains("`max_requests` must be greater than zero"),
        "got: {err}"
    );
}

#[test]
fn test_zero_window_seconds_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 5, "window_seconds": 0 }
            }
        }),
    );
    let err = result.err().expect("window_seconds=0 should be rejected");
    assert!(
        err.contains("`window_seconds` must be greater than zero"),
        "got: {err}"
    );
}

#[test]
fn test_missing_max_requests_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "window_seconds": 60 }
            }
        }),
    );
    let err = result
        .err()
        .expect("missing max_requests should be rejected, not silently dropped");
    assert!(err.contains("`max_requests` is required"), "got: {err}");
}

#[test]
fn test_missing_window_seconds_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 5 }
            }
        }),
    );
    let err = result
        .err()
        .expect("missing window_seconds should be rejected, not silently dropped");
    assert!(err.contains("`window_seconds` is required"), "got: {err}");
}

#[test]
fn test_method_rate_limits_must_be_object() {
    let result = create_plugin("grpc_method_router", &json!({"method_rate_limits": []}));
    let err = result
        .err()
        .expect("non-object method_rate_limits must be rejected");
    assert!(
        err.contains("`method_rate_limits` must be an object"),
        "got: {err}"
    );
}

#[test]
fn test_method_rate_limit_spec_must_be_object() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": 10
            }
        }),
    );
    let err = result
        .err()
        .expect("non-object rate-limit spec must be rejected");
    assert!(err.contains("must be an object"), "got: {err}");
}

#[test]
fn test_invalid_method_rate_limit_key_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/": { "max_requests": 5, "window_seconds": 60 }
            }
        }),
    );
    let err = result
        .err()
        .expect("invalid rate-limit method key must be rejected");
    assert!(err.contains("invalid gRPC method path"), "got: {err}");
}

#[test]
fn test_duplicate_rate_limit_key_rejected_after_normalization() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 5, "window_seconds": 60 },
                "svc/M": { "max_requests": 5, "window_seconds": 60 }
            }
        }),
    );
    let err = result
        .err()
        .expect("duplicate normalized rate-limit key must be rejected");
    assert!(
        err.contains("duplicate `method_rate_limits` entry"),
        "got: {err}"
    );
}

#[test]
fn test_database_sync_mode_rejected() {
    let result = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/svc/M": { "max_requests": 5, "window_seconds": 60 }
            },
            "sync_mode": "database"
        }),
    );
    let err = result.err().expect("database sync_mode must be rejected");
    assert!(
        err.contains("`sync_mode` must be exactly `local` or `redis`"),
        "got: {err}"
    );
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
    let _ = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    // Same identity again — should be rate limited
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("jwks-user@example.com".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_reject(result, Some(429));

    // Different authenticated_identity should pass (separate bucket)
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("other-user@example.com".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_consumer_identity_equal_to_ip_does_not_share_ip_budget() {
    // An authenticated identity that happens to equal an IP must not drain
    // the anonymous budget of the caller at that IP (and vice versa).
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        },
        "limit_by": "consumer"
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.client_ip = "203.0.113.7".to_string();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("203.0.113.7".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    assert_continue(enforce_effective_path(plugin.as_ref(), &mut ctx).await);

    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.client_ip = "203.0.113.7".to_string();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = None;
    let _ = plugin.on_request_received(&mut ctx).await;
    assert_continue(enforce_effective_path(plugin.as_ref(), &mut ctx).await);
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
    let _ = enforce_effective_path(plugin.as_ref(), &mut ctx).await;

    // Same consumer again — should be rate limited (keyed by "testuser")
    let mut ctx = create_grpc_context("/pkg.Svc/Create");
    ctx.authenticated_identity = Some("jwks-identity".to_string());
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_reject(result, Some(429));
}

// ── Non-parseable backend-effective paths fail closed for every policy shape ──

#[tokio::test]
async fn test_unparseable_path_fails_closed_under_deny_list() {
    let config = json!({
        "deny_methods": ["/pkg.Svc/Method"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/not-a-grpc-path");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_reject(result, Some(403));
    assert!(!ctx.metadata.contains_key("grpc_full_method"));
}

#[tokio::test]
async fn test_unparseable_path_fails_closed_under_rate_limit_only() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Create": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/svc/method/extra");
    let _ = plugin.on_request_received(&mut ctx).await;
    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_reject(result, Some(403));
    assert!(!ctx.metadata.contains_key("grpc_full_method"));
}

// Regression for finding #21: under a strict allow-list (deny-by-default), a
// gRPC POST whose :path cannot be parsed as `/package.Service/Method` must
// FAIL CLOSED (Reject 403 -> trailers-only gRPC PERMISSION_DENIED), not slip
// past the allow-list gate. Several malformed shapes that leave
// grpc_full_method unset are exercised.
#[tokio::test]
async fn test_unparseable_path_fails_closed_under_allow_list() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Allowed"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    // Each path is unparseable by parse_grpc_path: extra slash, empty service,
    // empty method, single segment, no leading slash.
    for path in [
        "/svc/method/extra",
        "//Method",
        "/pkg.Svc/",
        "/onlyone",
        "not-a-grpc-path",
    ] {
        let mut ctx = create_grpc_context(path);
        let _ = plugin.on_request_received(&mut ctx).await;
        // Precondition: the path genuinely did not parse into gRPC metadata.
        assert!(
            !ctx.metadata.contains_key("grpc_full_method"),
            "path {path:?} unexpectedly parsed; test no longer exercises the fail-closed branch"
        );

        let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
        assert_reject(result, Some(403));
    }
}

// A normally allowed path still passes after the fail-closed change, confirming
// the fix does not over-reject parseable, listed methods.
#[tokio::test]
async fn test_allow_list_still_permits_listed_method_after_fail_closed_fix() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Allowed"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Allowed");
    let _ = plugin.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.metadata.get("grpc_full_method").unwrap(),
        "pkg.Svc/Allowed"
    );

    let result = enforce_effective_path(plugin.as_ref(), &mut ctx).await;
    assert_continue(result);
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let token = "'\"`UNREGISTERED_TRAFFIC_TOKEN\\tail";
    for (config, field, reason) in [
        (
            json!({"method_rate_limits": {token: {}}}),
            "`method_rate_limits`",
            "`max_requests` is required",
        ),
        (
            json!({"method_rate_limits": {token: true}}),
            "`method_rate_limits`",
            "must be an object",
        ),
        (
            json!({"allow_methods": [918273641]}),
            "`allow_methods[0]`",
            "must be a string",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("grpc_method_router", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

#[test]
fn shared_method_rate_bounds_keep_the_parent_without_promoting_supplied_keys() {
    use ferrum_edge::plugins::utils::rate_limit::{
        MAX_RATE_LIMIT_MAX_REQUESTS, MAX_RATE_LIMIT_WINDOW_SECONDS,
    };

    // Bounds are checked before method-path normalization, so even these bare
    // numeric and hostile keys reach the shared validators through admission.
    for key in [
        "/pkg.Service/MethodIdentifierCanary",
        "918273641",
        "'\"\\\n`GRPC_METHOD_CANARY",
    ] {
        for (field, maximum) in [
            ("max_requests", MAX_RATE_LIMIT_MAX_REQUESTS),
            ("window_seconds", MAX_RATE_LIMIT_WINDOW_SECONDS),
        ] {
            for value in [0, maximum + 1] {
                let mut spec = json!({"max_requests": 10, "window_seconds": 60});
                spec[field] = json!(value);
                let config = json!({"method_rate_limits": {key: spec}});
                let error =
                    ferrum_edge::plugins::validate_plugin_config("grpc_method_router", &config)
                        .expect_err("invalid bound must be rejected before method normalization");
                let rendered =
                    ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
                assert!(
                    rendered.contains("grpc_method_router: `method_rate_limits`"),
                    "{rendered}"
                );
                assert!(rendered.contains(&format!("`{field}`")), "{rendered}");
                if value == 0 {
                    assert!(rendered.contains("must be greater than zero"), "{rendered}");
                    assert!(!rendered.contains('0'), "{rendered}");
                } else {
                    assert!(
                        rendered.contains(&format!("must be <= {maximum}")),
                        "{rendered}"
                    );
                    assert!(!rendered.contains(&value.to_string()), "{rendered}");
                }
                for withheld in ["MethodIdentifierCanary", "918273641", "GRPC_METHOD_CANARY"] {
                    assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
                }
            }
        }
    }
}

#[test]
fn method_rate_shape_errors_keep_schema_and_suggestions_without_supplied_content() {
    for key in [
        "/pkg.Service/MethodIdentifierCanary",
        "918273641",
        "'\"\\\n`GRPC_METHOD_CANARY",
    ] {
        let hostile_key = "'\"\\\n`GRPC_KEY_CANARY";
        for (spec, reason) in [
            (
                json!({
                    "window_seconds": 60,
                    "max_requets": {"GRPC_PAYLOAD_KEY": ["GRPC_VALUE_CANARY"]},
                    hostile_key: "GRPC_SCALAR_CANARY",
                    "918273642": ["GRPC_ARRAY_CANARY"]
                }),
                "did you mean `max_requests`?",
            ),
            (json!({"window_seconds": 60}), "`max_requests` is required"),
            (
                json!({
                    "window_seconds": 60,
                    "max_requests": {"GRPC_PAYLOAD_KEY": ["GRPC_VALUE_CANARY"]}
                }),
                "`max_requests` is required and must be a positive integer",
            ),
        ] {
            let config = json!({"method_rate_limits": {key: spec}});
            let error = ferrum_edge::plugins::validate_plugin_config("grpc_method_router", &config)
                .expect_err("invalid rate spec must fail admission");
            let rendered =
                ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
            assert!(rendered.contains("grpc_method_router:"), "{rendered}");
            assert!(rendered.contains("`method_rate_limits`"), "{rendered}");
            assert!(rendered.contains(reason), "{rendered}");
            if config["method_rate_limits"][key]
                .get("max_requets")
                .is_some()
            {
                assert!(
                    rendered.contains("unknown configuration key(s)"),
                    "{rendered}"
                );
            }
            for withheld in [
                "MethodIdentifierCanary",
                "918273641",
                "GRPC_METHOD_CANARY",
                "max_requets",
                "GRPC_KEY_CANARY",
                "GRPC_PAYLOAD_KEY",
                "GRPC_VALUE_CANARY",
                "GRPC_SCALAR_CANARY",
                "GRPC_ARRAY_CANARY",
                "918273642",
            ] {
                assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
            }
        }
    }
}

// ── Rate-limit metric accounting (grpc_method_router-SOL-2) ──

/// An ordinary per-method quota refusal is a rate-limit rejection and must be
/// counted in `ferrum_rate_limit_exceeded_total`, not only the capacity 429.
#[tokio::test]
async fn quota_refusal_increments_rate_limit_exceeded_metric() {
    use ferrum_edge::_test_support::grpc_method_router_with_metrics_registry_for_test;
    use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;

    for mut config in [
        json!({"method_rate_limits": {
            "/pkg.MetricSvc/Create": {"max_requests": 1, "window_seconds": 60}
        }}),
        json!({"method_rate_limits": {
            "/pkg.MetricSvc/*": {"max_requests": 1, "window_seconds": 60}
        }}),
        json!({"default_rate_limit": {"max_requests": 1, "window_seconds": 60}}),
    ] {
        config["deny_methods"] = json!(["/pkg.MetricSvc/Blocked"]);
        let registry = Arc::new(MetricsRegistry::new());
        let plugin =
            grpc_method_router_with_metrics_registry_for_test(&config, Arc::clone(&registry))
                .unwrap();

        assert_reject(call(&plugin, "/pkg.MetricSvc/Blocked").await, Some(403));
        assert_continue(call(&plugin, "/pkg.MetricSvc/Create").await);
        assert_eq!(
            registry.rate_limit_exceeded.load(Ordering::Relaxed),
            0,
            "admission and access denial must not count as quota refusals: {config}"
        );

        // Only this plugin owns the registry: unrelated tests cannot satisfy
        // the assertion if quota accounting is removed or incremented twice.
        for expected in 1..=2 {
            assert_reject(call(&plugin, "/pkg.MetricSvc/Create").await, Some(429));
            assert_eq!(
                registry.rate_limit_exceeded.load(Ordering::Relaxed),
                expected,
                "each quota refusal must increment ferrum_rate_limit_exceeded_total once: {config}"
            );
        }
    }
}

async fn call(plugin: &dyn Plugin, path: &str) -> PluginResult {
    let mut ctx = create_grpc_context(path);
    let _ = plugin.on_request_received(&mut ctx).await;
    enforce_effective_path(plugin, &mut ctx).await
}

// ── Service-level rules and default rate limit (grpc_method_router-MUSE-1) ──

#[tokio::test]
async fn service_level_deny_blocks_every_method_of_that_service_only() {
    let config = json!({"deny_methods": ["/admin.AdminService/*"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_reject(
        call(plugin.as_ref(), "/admin.AdminService/DeleteAll").await,
        Some(403),
    );
    assert_reject(
        call(plugin.as_ref(), "/admin.AdminService/NewlyShipped").await,
        Some(403),
    );
    // A different service, including one sharing the package prefix, passes.
    assert_continue(call(plugin.as_ref(), "/admin.AuditService/List").await);
    assert_continue(call(plugin.as_ref(), "/admin.AdminServiceV2/DeleteAll").await);
}

#[tokio::test]
async fn service_level_allow_admits_every_method_of_that_service_only() {
    let config = json!({"allow_methods": ["pkg.Public/*", "pkg.Other/Exact"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_continue(call(plugin.as_ref(), "/pkg.Public/Any").await);
    assert_continue(call(plugin.as_ref(), "/pkg.Public/Another").await);
    assert_continue(call(plugin.as_ref(), "/pkg.Other/Exact").await);
    assert_reject(
        call(plugin.as_ref(), "/pkg.Other/NotListed").await,
        Some(403),
    );
    assert_reject(call(plugin.as_ref(), "/pkg.Private/Any").await, Some(403));
}

#[tokio::test]
async fn service_level_deny_wins_over_exact_allow() {
    let config = json!({
        "allow_methods": ["/pkg.Svc/Health"],
        "deny_methods": ["/pkg.Svc/*"]
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_reject(call(plugin.as_ref(), "/pkg.Svc/Health").await, Some(403));
}

#[tokio::test]
async fn service_level_rate_limit_is_one_budget_across_the_service() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.PooledSvc/*": { "max_requests": 2, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_continue(call(plugin.as_ref(), "/pkg.PooledSvc/A").await);
    assert_continue(call(plugin.as_ref(), "/pkg.PooledSvc/B").await);
    assert_reject(call(plugin.as_ref(), "/pkg.PooledSvc/C").await, Some(429));
    // Another service is not covered by the rule.
    assert_continue(call(plugin.as_ref(), "/pkg.OtherSvc/A").await);
    // Distinct method names share one key; they cannot mint new counters.
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn exact_rate_rule_wins_over_service_rule_and_does_not_charge_it() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Hot": { "max_requests": 1, "window_seconds": 60 },
            "/pkg.Svc/*": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_continue(call(plugin.as_ref(), "/pkg.Svc/Hot").await);
    assert_reject(call(plugin.as_ref(), "/pkg.Svc/Hot").await, Some(429));
    // The exact rule's traffic never consumed the service-level budget.
    assert_continue(call(plugin.as_ref(), "/pkg.Svc/Other").await);
    assert_reject(call(plugin.as_ref(), "/pkg.Svc/Another").await, Some(429));
}

#[tokio::test]
async fn default_rate_limit_covers_methods_without_a_specific_rule() {
    let config = json!({
        "method_rate_limits": {
            "/pkg.Svc/Listed": { "max_requests": 5, "window_seconds": 60 },
            "/pkg.Grouped/*": { "max_requests": 5, "window_seconds": 60 }
        },
        "default_rate_limit": { "max_requests": 1, "window_seconds": 60 }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    assert_continue(call(plugin.as_ref(), "/pkg.Svc/Unlisted").await);
    // The default budget is pooled per caller across every uncovered method.
    let refused = call(plugin.as_ref(), "/other.Svc/AlsoUnlisted").await;
    match refused {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(
                headers.get("x-grpc-ratelimit-limit").map(String::as_str),
                Some("1")
            );
            assert_eq!(
                headers.get("x-grpc-ratelimit-method").map(String::as_str),
                Some("other.Svc/AlsoUnlisted")
            );
        }
        other => panic!("expected 429 from the default rule, got {other:?}"),
    }
    // Exact and service-level rules take precedence over the default.
    assert_continue(call(plugin.as_ref(), "/pkg.Svc/Listed").await);
    assert_continue(call(plugin.as_ref(), "/pkg.Grouped/Any").await);
}

#[test]
fn default_rate_limit_alone_is_a_configured_rule() {
    let plugin = create_plugin(
        "grpc_method_router",
        &json!({"default_rate_limit": {"max_requests": 10, "window_seconds": 60}}),
    )
    .unwrap()
    .unwrap();
    assert!(plugin.gates_request_admission());

    // `null` is the same as omission, so it is not a rule on its own.
    let err = create_plugin("grpc_method_router", &json!({"default_rate_limit": null}))
        .err()
        .expect("a null default_rate_limit alone configures nothing");
    assert!(err.contains("no rules configured"), "got: {err}");
    assert!(
        create_plugin(
            "grpc_method_router",
            &json!({"deny_methods": ["pkg.Svc/X"], "default_rate_limit": null}),
        )
        .is_ok()
    );
}

#[test]
fn default_rate_limit_is_a_closed_bounded_spec() {
    for (config, reason) in [
        (json!({"default_rate_limit": 10}), "must be an object"),
        (
            json!({"default_rate_limit": {"max_requests": 5}}),
            "`window_seconds` is required",
        ),
        (
            json!({"default_rate_limit": {"window_seconds": 60}}),
            "`max_requests` is required",
        ),
        (
            json!({"default_rate_limit": {"max_requests": 0, "window_seconds": 60}}),
            "must be greater than zero",
        ),
        (
            json!({"default_rate_limit": {"max_requests": 5, "window_seconds": 60, "burst": 1}}),
            "unknown configuration key(s)",
        ),
    ] {
        let err = create_plugin("grpc_method_router", &config)
            .err()
            .unwrap_or_else(|| panic!("must be rejected: {config}"));
        assert!(err.contains("`default_rate_limit`"), "got: {err}");
        assert!(err.contains(reason), "{reason}: got: {err}");
    }
}

#[test]
fn only_the_literal_service_wildcard_is_admitted() {
    for pattern in [
        "pkg.*/*",
        "*/*",
        "*/Method",
        "pkg.Svc/Get*",
        "pkg.Svc/**",
        "pkg.Svc*/Method",
        "/pkg.Svc/*/Extra",
    ] {
        for config in [
            json!({"deny_methods": [pattern]}),
            json!({"allow_methods": [pattern]}),
            json!({"method_rate_limits": {pattern: {"max_requests": 1, "window_seconds": 60}}}),
        ] {
            let err = create_plugin("grpc_method_router", &config)
                .err()
                .unwrap_or_else(|| panic!("pattern must be rejected: {config}"));
            assert!(err.contains("invalid gRPC method path"), "got: {err}");
        }
    }
}

#[test]
fn duplicate_service_rules_are_rejected_after_normalization() {
    let err = create_plugin(
        "grpc_method_router",
        &json!({"deny_methods": ["/pkg.Svc/*", " pkg.Svc/* "]}),
    )
    .err()
    .expect("duplicate normalized service rule must be rejected");
    assert!(err.contains("duplicate method"), "got: {err}");

    let err = create_plugin(
        "grpc_method_router",
        &json!({
            "method_rate_limits": {
                "/pkg.Svc/*": {"max_requests": 1, "window_seconds": 60},
                "pkg.Svc/*": {"max_requests": 2, "window_seconds": 60}
            }
        }),
    )
    .err()
    .expect("duplicate normalized service rate rule must be rejected");
    assert!(
        err.contains("duplicate `method_rate_limits` entry"),
        "got: {err}"
    );

    // An exact rule and a service rule for the same service coexist.
    assert!(
        create_plugin(
            "grpc_method_router",
            &json!({"deny_methods": ["pkg.Svc/*", "pkg.Svc/Method"]}),
        )
        .is_ok()
    );
}

// ── Metadata refresh reuse (grpc_method_router-MUSE-3) ──

#[tokio::test]
async fn unchanged_backend_path_keeps_published_metadata_without_rebuilding_it() {
    let config = json!({"deny_methods": ["/blocked.Svc/Blocked"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Method");
    assert_continue(plugin.on_request_received(&mut ctx).await);
    let published: Vec<*const u8> = ["grpc_service", "grpc_method", "grpc_full_method"]
        .iter()
        .map(|key| ctx.metadata.get(*key).expect("published").as_ptr())
        .collect();

    assert_continue(
        plugin
            .on_backend_path_resolved(&mut ctx, "/pkg.Svc/Method")
            .await,
    );
    let refreshed: Vec<*const u8> = ["grpc_service", "grpc_method", "grpc_full_method"]
        .iter()
        .map(|key| ctx.metadata.get(*key).expect("still published").as_ptr())
        .collect();
    assert_eq!(
        published, refreshed,
        "an unchanged backend-effective method must not re-materialize metadata"
    );
    assert_eq!(
        ctx.metadata.get("grpc_full_method").map(String::as_str),
        Some("pkg.Svc/Method")
    );
}

#[tokio::test]
async fn backend_refresh_still_overwrites_tampered_metadata_before_enforcement() {
    let config = json!({"deny_methods": ["/pkg.Svc/Denied"]});
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();

    let mut ctx = create_grpc_context("/pkg.Svc/Denied");
    assert_continue(plugin.on_request_received(&mut ctx).await);
    // A later plugin rewrites the published values to spoof another method.
    ctx.metadata
        .insert("grpc_service".to_string(), "pkg.Svc".to_string());
    ctx.metadata
        .insert("grpc_method".to_string(), "Allowed".to_string());
    ctx.metadata.insert(
        "grpc_full_method".to_string(),
        "pkg.Svc/Allowed".to_string(),
    );

    let result = plugin
        .on_backend_path_resolved(&mut ctx, "/pkg.Svc/Denied")
        .await;
    assert_reject(result, Some(403));
    assert_eq!(
        ctx.metadata.get("grpc_service").map(String::as_str),
        Some("pkg.Svc")
    );
    assert_eq!(
        ctx.metadata.get("grpc_method").map(String::as_str),
        Some("Denied")
    );
    assert_eq!(
        ctx.metadata.get("grpc_full_method").map(String::as_str),
        Some("pkg.Svc/Denied")
    );
}

// ── Documented rejection contract (grpc_method_router-MUSE-4) ──

#[tokio::test]
async fn documented_rejection_headers_match_the_runtime_contract() {
    let docs = include_str!("../../../docs/plugins.md");
    let section_start = docs
        .find("### `grpc_method_router`")
        .expect("grpc_method_router docs section");
    let section_end = docs[section_start..]
        .find("### `grpc_deadline`")
        .map(|offset| section_start + offset)
        .expect("next docs section");
    let section = &docs[section_start..section_end];
    for header in [
        "x-grpc-ratelimit-limit",
        "x-grpc-ratelimit-remaining",
        "x-grpc-ratelimit-method",
        "RESOURCE_EXHAUSTED",
        "PERMISSION_DENIED",
        "UNAVAILABLE",
        "default_rate_limit",
        "package.Service/*",
    ] {
        assert!(section.contains(header), "docs must describe {header}");
    }

    let config = json!({
        "method_rate_limits": {
            "/pkg.DocSvc/Create": { "max_requests": 3, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("grpc_method_router", &config)
        .unwrap()
        .unwrap();
    for _ in 0..3 {
        assert_continue(call(plugin.as_ref(), "/pkg.DocSvc/Create").await);
    }
    match call(plugin.as_ref(), "/pkg.DocSvc/Create").await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/grpc")
            );
            assert_eq!(
                headers.get("x-grpc-ratelimit-limit").map(String::as_str),
                Some("3")
            );
            assert_eq!(
                headers
                    .get("x-grpc-ratelimit-remaining")
                    .map(String::as_str),
                Some("0")
            );
            assert_eq!(
                headers.get("x-grpc-ratelimit-method").map(String::as_str),
                Some("pkg.DocSvc/Create")
            );
        }
        other => panic!("expected 429, got {other:?}"),
    }
}
