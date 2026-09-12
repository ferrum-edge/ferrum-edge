//! Tests for rate_limiting plugin

use ferrum_edge::identity::SpiffeId;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
    rate_limiting::RateLimiting,
};
use ferrum_edge::proxy::client_ip::{TrustedProxies, resolve_client_ip};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_consumer, create_test_context,
};

fn rate_limiting_config(mut config: Value) -> Value {
    let Some(object) = config.as_object_mut() else {
        return config;
    };
    if object.contains_key("limits") {
        return config;
    }

    let mut default_rule = serde_json::Map::new();
    default_rule.insert("scope".to_string(), json!("default"));
    for field in [
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
        "window_seconds",
        "max_requests",
    ] {
        if let Some(value) = object.remove(field) {
            default_rule.insert(field.to_string(), value);
        }
    }
    object.insert(
        "limits".to_string(),
        Value::Array(vec![Value::Object(default_rule)]),
    );
    config
}

fn make_rate_limiter(config: Value) -> RateLimiting {
    RateLimiting::new(&rate_limiting_config(config), PluginHttpClient::default()).unwrap()
}

#[tokio::test]
async fn test_rate_limiting_plugin_creation() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "consumer"
    });
    let plugin = make_rate_limiter(config);
    assert_eq!(plugin.name(), "rate_limiting");
    assert_eq!(plugin.priority(), priority::RATE_LIMITING);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(!plugin.is_auth_plugin());
    assert!(plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_rate_limiting_plugin_consumer_limiting() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 3,
        "limit_by": "consumer"
    });
    let plugin = make_rate_limiter(config);

    let consumer = create_test_consumer();

    // In consumer mode, on_request_received should pass through (no-op)
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(consumer.clone()));
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Consumer-based limiting happens in authorize phase (after auth identifies consumer)
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(consumer.clone()));
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // Multiple requests for same consumer should be rate limited via authorize
    let mut rejected_count = 0;
    for _i in 0..6 {
        let mut ctx_test = create_test_context();
        ctx_test.identified_consumer = Some(Arc::new(consumer.clone()));
        let result = plugin.authorize(&mut ctx_test).await;
        if matches!(result, PluginResult::Reject { .. }) {
            rejected_count += 1;
        }
    }

    // Should have some rejections after hitting the limit
    assert!(
        rejected_count > 0,
        "Expected some requests to be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limiting_plugin_ip_limiting() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    // First request should pass
    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Multiple requests should eventually be rate limited
    let mut rejected_count = 0;
    for _i in 0..10 {
        let mut ctx_test = create_test_context();
        let result = plugin.on_request_received(&mut ctx_test).await;
        if matches!(result, PluginResult::Reject { .. }) {
            rejected_count += 1;
        }
    }

    // Should have some rejections after hitting the limit
    assert!(
        rejected_count > 0,
        "Expected some requests to be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limiting_uses_canonical_ingress_identity() {
    let plugin = make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip"
    }));

    let mut native = create_test_context();
    native.client_ip = "192.0.2.10".to_string();
    assert_continue(plugin.on_request_received(&mut native).await);

    let mut mapped = create_test_context();
    let no_trust = TrustedProxies::parse_strict("", "test").expect("empty trust list is valid");
    mapped.client_ip = resolve_client_ip("::ffff:192.0.2.10", None, &no_trust);
    assert_reject(plugin.on_request_received(&mut mapped).await, Some(429));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn test_rate_limiting_plugin_short_window() {
    let config = json!({
        "window_seconds": 1,
        "max_requests": 2,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // First request should pass
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Second request should pass
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Third request should be rejected and exported by the process-wide
    // aggregate limiter metric.
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.rate_limit_exceeded.load(Ordering::Relaxed);
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
    assert!(registry.rate_limit_exceeded.load(Ordering::Relaxed) > before);
}

#[tokio::test]
async fn test_rate_limiting_plugin_zero_limit() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 0,
        "limit_by": "ip"
    });
    let result = RateLimiting::new(&rate_limiting_config(config), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("must be greater than zero"));
}

#[tokio::test]
async fn test_rate_limiting_plugin_invalid_config() {
    let cases = [
        json!(null),
        json!([]),
        json!({"window_seconds": "invalid", "max_requests": 1}),
        json!({"window_seconds": 0, "max_requests": 1}),
        json!({"window_seconds": 60, "max_requests": "10"}),
        json!({"requests_per_second": "10"}),
        json!({"requests_per_minute": false}),
        json!({"requests_per_hour": []}),
        json!({"window_seconds": 60, "max_requests": 1, "limit_by": "invalid_type"}),
        json!({"window_seconds": 60, "max_requests": 1, "limit_by": false}),
        json!({"window_seconds": 60, "max_requests": 1, "expose_headers": "true"}),
        json!({"window_seconds": 60, "max_requests": 1, "sync_mode": "redsi"}),
        json!({"window_seconds": 60, "max_requests": 1, "sync_mode": "database"}),
        json!({"window_seconds": 60, "max_requests": 1, "sync_mode": "redis"}),
        json!({"window_seconds": 60, "max_requests": 1, "sync_mode": "redis", "redis_url": ""}),
        json!({
            "window_seconds": 60,
            "max_requests": 1,
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379/0",
            "redis_health_check_interval_seconds": 0
        }),
    ];

    for config in cases {
        assert!(
            RateLimiting::new(
                &rate_limiting_config(config.clone()),
                PluginHttpClient::default()
            )
            .is_err(),
            "config should fail validation: {config}"
        );
    }
}

#[tokio::test]
async fn test_rate_limiting_consumer_rules_override_default_for_many_consumers() {
    let config = json!({
        "limit_by": "consumer",
        "limits": [
            { "scope": "default", "window_seconds": 60, "max_requests": 3 },
            { "scope": "consumers", "consumers": ["testuser"], "window_seconds": 60, "max_requests": 1 },
            { "scope": "consumers", "consumers": ["partner", "batch-worker"], "window_seconds": 60, "max_requests": 2 }
        ]
    });
    let plugin = make_rate_limiter(config);

    let mut testuser_1 = create_test_context();
    assert_continue(plugin.authorize(&mut testuser_1).await);
    let mut testuser_2 = create_test_context();
    assert_reject(plugin.authorize(&mut testuser_2).await, Some(429));

    let mut partner = create_test_consumer();
    partner.username = "partner".to_string();
    for _ in 0..2 {
        let mut ctx = create_test_context();
        ctx.identified_consumer = Some(Arc::new(partner.clone()));
        assert_continue(plugin.authorize(&mut ctx).await);
    }
    let mut partner_over = create_test_context();
    partner_over.identified_consumer = Some(Arc::new(partner));
    assert_reject(plugin.authorize(&mut partner_over).await, Some(429));

    let mut batch_worker = create_test_consumer();
    batch_worker.username = "batch-worker".to_string();
    for _ in 0..2 {
        let mut ctx = create_test_context();
        ctx.identified_consumer = Some(Arc::new(batch_worker.clone()));
        assert_continue(plugin.authorize(&mut ctx).await);
    }
    let mut batch_over = create_test_context();
    batch_over.identified_consumer = Some(Arc::new(batch_worker));
    assert_reject(plugin.authorize(&mut batch_over).await, Some(429));

    for _ in 0..3 {
        let mut ctx = create_test_context();
        ctx.identified_consumer = None;
        ctx.authenticated_identity = Some("unlisted-consumer".to_string());
        assert_continue(plugin.authorize(&mut ctx).await);
    }
    let mut unlisted_over = create_test_context();
    unlisted_over.identified_consumer = None;
    unlisted_over.authenticated_identity = Some("unlisted-consumer".to_string());
    assert_reject(plugin.authorize(&mut unlisted_over).await, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_consumer_rules_apply_default_to_ip_fallback() {
    let config = json!({
        "limit_by": "consumer",
        "limits": [
            { "scope": "default", "window_seconds": 60, "max_requests": 2 },
            { "scope": "consumers", "consumers": ["testuser"], "window_seconds": 60, "max_requests": 1 }
        ]
    });
    let plugin = make_rate_limiter(config);

    for _ in 0..2 {
        let mut ctx = create_test_context();
        ctx.identified_consumer = None;
        ctx.authenticated_identity = None;
        assert_continue(plugin.authorize(&mut ctx).await);
    }
    let mut over = create_test_context();
    over.identified_consumer = None;
    over.authenticated_identity = None;
    assert_reject(plugin.authorize(&mut over).await, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_limit_scope_is_case_insensitive() {
    let config = json!({
        "limit_by": "Consumer",
        "limits": [
            { "scope": "Default", "window_seconds": 60, "max_requests": 2 },
            { "scope": "Consumers", "consumers": ["testuser"], "window_seconds": 60, "max_requests": 1 }
        ]
    });

    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    assert_continue(plugin.authorize(&mut ctx).await);
    let mut over = create_test_context();
    assert_reject(plugin.authorize(&mut over).await, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_limits_invalid_config() {
    let cases = [
        json!({
            "limit_by": "ip",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10 },
                { "scope": "consumers", "consumers": ["testuser"], "window_seconds": 60, "max_requests": 1 }
            ]
        }),
        json!({
            "limit_by": "consumer",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10 },
                { "scope": "consumers", "consumers": [], "window_seconds": 60, "max_requests": 1 }
            ]
        }),
        json!({
            "limit_by": "consumer",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10 },
                { "scope": "consumers", "consumers": ["testuser"], "sync_mode": "database", "max_requests": 1, "window_seconds": 60 }
            ]
        }),
        json!({
            "limit_by": "ip",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10, "requests_per_minute": 5 }
            ]
        }),
        json!({
            "limit_by": "ip",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10, "limit_by": "consumer" }
            ]
        }),
        json!({
            "limit_by": "ip",
            "limits": [
                { "scope": "default", "requests_per_minute": 10, "requests_per_minutes": 20 }
            ]
        }),
        json!({
            "limit_by": "consumer",
            "limits": [
                { "scope": "consumers", "consumers": ["testuser"], "window_seconds": 60, "max_requests": 1 }
            ]
        }),
        json!({
            "limit_by": "ip",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10 },
                { "scope": "default", "window_seconds": 60, "max_requests": 20 }
            ]
        }),
        json!({
            "limit_by": "consumer",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10 },
                { "scope": "consumers", "consumers": ["alice"], "window_seconds": 60, "max_requests": 1 },
                { "scope": "consumers", "consumers": ["alice"], "window_seconds": 60, "max_requests": 2 }
            ]
        }),
        json!({
            "limit_by": "consumer",
            "limits": [
                { "scope": "default", "window_seconds": 60, "max_requests": 10 },
                { "scope": "consumers", "consumers": ["alice", "alice"], "window_seconds": 60, "max_requests": 1 }
            ]
        }),
        json!({
            "limit_by": "ip",
            "limits": [
                { "scope": "default", "window_seconds": 60 }
            ]
        }),
        json!({
            "limit_by": "ip",
            "limits": []
        }),
        json!({
            "limit_by": "ip",
            "window_seconds": 60,
            "max_requests": 10
        }),
    ];

    for config in cases {
        assert!(
            RateLimiting::new(&config, PluginHttpClient::default()).is_err(),
            "config should fail validation: {config}"
        );
    }
}

#[tokio::test]
async fn test_rate_limiting_ip_mode_authorize_is_noop() {
    // In IP mode, authorize() should NOT apply rate limiting (only on_request_received does)
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // on_request_received uses the limit
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // authorize should always return Continue in IP mode (not count against the limit)
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // The next on_request_received should be rejected (limit=1, already used)
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_consumer_mode_on_request_received_is_noop() {
    // In consumer mode, on_request_received() should be a no-op (authorize handles limiting)
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "consumer"
    });
    let plugin = make_rate_limiter(config);

    let consumer = create_test_consumer();

    // on_request_received should pass through in consumer mode
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(consumer.clone()));
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
    assert_eq!(plugin.tracked_keys_count(), Some(0));

    // authorize uses the limit for consumer mode
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // Second authorize should be rejected (limit=1, already used)
    let mut ctx2 = create_test_context();
    ctx2.identified_consumer = Some(Arc::new(consumer.clone()));
    let result = plugin.authorize(&mut ctx2).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_consumer_fallback_to_ip() {
    // In consumer mode, unauthenticated requests fall back to IP-based keying
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "consumer"
    });
    let plugin = make_rate_limiter(config);

    // No consumer set — should fall back to IP-based key
    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // Second request from same IP (no consumer) should be rejected
    let mut ctx2 = create_test_context();
    ctx2.identified_consumer = None;
    let result = plugin.authorize(&mut ctx2).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_spiffe_mode_on_request_received_is_noop() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "spiffe_identity"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    ctx.peer_spiffe_id = Some(SpiffeId::new("spiffe://example.test/ns/app/sa/api").unwrap());

    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_rate_limiting_spiffe_identity_limits_by_spiffe_id() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "spiffe"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx1 = create_test_context();
    ctx1.client_ip = "10.0.0.1".to_string();
    ctx1.peer_spiffe_id = Some(SpiffeId::new("spiffe://example.test/ns/app/sa/api").unwrap());
    assert_continue(plugin.authorize(&mut ctx1).await);

    let mut ctx2 = create_test_context();
    ctx2.client_ip = "10.0.0.2".to_string();
    ctx2.peer_spiffe_id = Some(SpiffeId::new("spiffe://example.test/ns/app/sa/api").unwrap());
    assert_reject(plugin.authorize(&mut ctx2).await, Some(429));

    let mut ctx3 = create_test_context();
    ctx3.client_ip = "10.0.0.3".to_string();
    ctx3.peer_spiffe_id = Some(SpiffeId::new("spiffe://example.test/ns/app/sa/web").unwrap());
    assert_continue(plugin.authorize(&mut ctx3).await);
}

#[tokio::test]
async fn test_rate_limiting_spiffe_identity_fallback_to_ip() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "spiffe_identity"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx1 = create_test_context();
    ctx1.peer_spiffe_id = None;
    assert_continue(plugin.authorize(&mut ctx1).await);

    let mut ctx2 = create_test_context();
    ctx2.peer_spiffe_id = None;
    assert_reject(plugin.authorize(&mut ctx2).await, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_warmup_hostnames_for_redis() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "sync_mode": "redis",
        "redis_url": "redis://cache.internal:6379/0"
    });
    let plugin = make_rate_limiter(config);
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["cache.internal".to_string()]
    );
}

#[test]
fn test_rate_limiting_accepts_redis_connect_timeout_above_one_second() {
    // Issue #2310: values above the redis-rs 1s default must remain admissible
    // and flow into the shared Redis client.
    let plugin = make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "sync_mode": "redis",
        "redis_url": "redis://cache.internal:6379/0",
        "redis_connect_timeout_seconds": 5
    }));
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["cache.internal".to_string()]
    );
}

#[tokio::test]
async fn test_rate_limiting_different_ips_independent() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    // IP 1: first request passes
    let mut ctx1 = create_test_context();
    ctx1.client_ip = "10.0.0.1".to_string();
    let result = plugin.on_request_received(&mut ctx1).await;
    assert_continue(result);

    // IP 1: second request rejected
    let result = plugin.on_request_received(&mut ctx1).await;
    assert_reject(result, Some(429));

    // IP 2: first request passes (independent counter)
    let mut ctx2 = create_test_context();
    ctx2.client_ip = "10.0.0.2".to_string();
    let result = plugin.on_request_received(&mut ctx2).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_rate_limiting_explicit_rate_config() {
    let config = json!({
        "requests_per_second": 2,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // First two should pass
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Third should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_non_standard_window_exact() {
    // Non-standard window: 45 seconds, 10 requests.
    // Previously this was converted via integer division to per-minute rate:
    //   (10 * 60) / 45 = 13 req/min (precision loss: should be 13.33)
    // Now it should use the exact 45-second window with 10 requests.
    let config = json!({
        "window_seconds": 45,
        "max_requests": 10,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // All 10 requests within the 45s window should pass
    for _i in 0..10 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // The 11th request should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_non_standard_window_7s() {
    // 7-second window with 3 requests
    // Old behavior: (3 * 60) / 7 = 25 req/min (a completely different rate)
    // New behavior: exactly 3 requests per 7 seconds
    let config = json!({
        "window_seconds": 7,
        "max_requests": 3,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // First 3 should pass
    for _ in 0..3 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 4th should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_non_standard_window_90s() {
    // 90-second window (between 60s and 3600s)
    let config = json!({
        "window_seconds": 90,
        "max_requests": 5,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // All 5 should pass
    for _ in 0..5 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 6th should be rejected
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

// ─── Token Bucket (per-second TPS) Tests ───────────────────────────────

#[tokio::test]
async fn test_rate_limiting_tps_uses_token_bucket() {
    // requests_per_second creates a 1s window → token bucket (≤5s threshold)
    let config = json!({
        "requests_per_second": 5,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // All 5 should pass (bucket starts full)
    for _ in 0..5 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 6th should be rejected (bucket empty)
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_tps_refills_over_time() {
    let config = json!({
        "requests_per_second": 10,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // Drain all 10 tokens
    for _ in 0..10 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // Should be rejected now
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));

    // Wait for tokens to refill (100ms = ~1 token at 10/s rate)
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Should have ~1 token available now
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_rate_limiting_high_tps_limit() {
    // Ensure high TPS limits work without memory issues.
    // With a token bucket at 10,000 req/s, micro-refill during the loop
    // means we may slightly exceed the nominal bucket capacity. Fire 2x
    // the bucket capacity to guarantee drainage even on slow CI runners
    // where per-iteration time (~10μs) allows significant token refill.
    let config = json!({
        "requests_per_second": 10000,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // Fire 20,000 requests — 2x bucket capacity guarantees some rejections
    // even if each iteration takes ~10μs (refilling ~100 tokens total)
    let mut passed = 0;
    let mut rejected = 0;
    for _ in 0..20_000 {
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Continue => passed += 1,
            PluginResult::Reject { .. } | PluginResult::RejectBinary { .. } => rejected += 1,
        }
    }

    // Should have passed ~10,000 (token bucket allows capacity + micro-refill)
    assert!(
        passed >= 10000,
        "Expected at least 10000 passed, got {}",
        passed
    );
    // Should have rejected some — 2x capacity ensures the bucket drains
    assert!(
        rejected > 0,
        "Expected some rejections after draining bucket, passed={} rejected={}",
        passed,
        rejected
    );
}

#[tokio::test]
async fn test_rate_limiting_tps_zero_limit() {
    // Zero TPS should be rejected at construction time
    let config = json!({
        "requests_per_second": 0,
        "limit_by": "ip"
    });
    let result = RateLimiting::new(&rate_limiting_config(config), PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("must be greater than zero"));
}

#[tokio::test]
async fn test_rate_limiting_combined_tps_and_per_minute() {
    // Both per-second AND per-minute limits — both must pass
    let config = json!({
        "requests_per_second": 5,
        "requests_per_minute": 10,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    // First 5 pass (within per-second burst)
    for _ in 0..5 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    // 6th rejected by per-second limit
    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_window_1s_uses_token_bucket() {
    // window_seconds: 1 → ≤5s threshold → should use token bucket
    let config = json!({
        "window_seconds": 1,
        "max_requests": 3,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    for _ in 0..3 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_window_5s_uses_token_bucket() {
    // window_seconds: 5 → boundary, ≤5s → token bucket
    let config = json!({
        "window_seconds": 5,
        "max_requests": 10,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    for _ in 0..10 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_rate_limiting_window_6s_uses_sliding_window() {
    // window_seconds: 6 → >5s → sliding window (exact counting)
    let config = json!({
        "window_seconds": 6,
        "max_requests": 3,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();

    for _ in 0..3 {
        let result = plugin.on_request_received(&mut ctx).await;
        assert_continue(result);
    }

    let result = plugin.on_request_received(&mut ctx).await;
    assert_reject(result, Some(429));
}

// ─── Expose Headers Tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_expose_headers_disabled_by_default() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "ip"
    });
    let plugin = make_rate_limiter(config);
    assert!(plugin.modifies_request_headers());
}

#[tokio::test]
async fn test_expose_headers_enabled() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "ip",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);
    assert!(plugin.modifies_request_headers());
}

#[tokio::test]
async fn test_expose_headers_on_success_response() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Rate info should be stored in metadata
    assert_eq!(ctx.metadata.get("ratelimit_limit").unwrap(), "5");
    assert_eq!(ctx.metadata.get("ratelimit_remaining").unwrap(), "4");
    assert_eq!(ctx.metadata.get("ratelimit_window").unwrap(), "60");
    // The limiter key/identity must never be stored as metadata — it would be
    // injected onto the downstream response and disclose internal identity.
    assert!(!ctx.metadata.contains_key("ratelimit_identity"));

    // after_proxy should inject headers into response
    let mut response_headers: HashMap<String, String> = HashMap::new();
    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_continue(result);

    assert_eq!(response_headers.get("x-ratelimit-limit").unwrap(), "5");
    assert_eq!(response_headers.get("x-ratelimit-remaining").unwrap(), "4");
    assert_eq!(response_headers.get("x-ratelimit-window").unwrap(), "60");
    // x-ratelimit-identity must never be reflected to the client.
    assert!(!response_headers.contains_key("x-ratelimit-identity"));
}

#[tokio::test]
async fn test_expose_headers_on_success_request_to_backend() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // before_proxy should inject headers into request to backend
    let mut request_headers: HashMap<String, String> = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert_continue(result);

    assert_eq!(request_headers.get("x-ratelimit-limit").unwrap(), "5");
    assert_eq!(request_headers.get("x-ratelimit-remaining").unwrap(), "4");
    // The limiter identity is no longer exposed on the upstream request either.
    assert!(!request_headers.contains_key("x-ratelimit-identity"));
}

#[tokio::test]
async fn test_expose_headers_on_rejection() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    // Use up the limit
    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);

    // Next request should be rejected WITH rate limit headers
    let mut ctx2 = create_test_context();
    let result = plugin.on_request_received(&mut ctx2).await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "1");
            assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "0");
            assert_eq!(headers.get("x-ratelimit-window").unwrap(), "60");
            // The 429 response must not echo the limiter identity to the client.
            assert!(!headers.contains_key("x-ratelimit-identity"));
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

#[tokio::test]
async fn test_expose_headers_disabled_no_headers_on_rejection() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "ip",
        "expose_headers": false
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    plugin.on_request_received(&mut ctx).await;

    let mut ctx2 = create_test_context();
    let result = plugin.on_request_received(&mut ctx2).await;
    match result {
        PluginResult::Reject { headers, .. } => {
            assert!(
                headers.is_empty(),
                "Headers should be empty when expose_headers is false"
            );
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_expose_headers_disabled_no_headers_on_success() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "ip",
        "expose_headers": false
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    plugin.on_request_received(&mut ctx).await;

    // No metadata should be stored
    assert!(!ctx.metadata.contains_key("ratelimit_limit"));

    // after_proxy should not inject anything
    let mut response_headers: HashMap<String, String> = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(response_headers.is_empty());
}

#[tokio::test]
async fn test_strips_spoofed_identity_header_before_backend() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "ip",
        "expose_headers": false
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    plugin.on_request_received(&mut ctx).await;

    let mut request_headers: HashMap<String, String> = HashMap::new();
    request_headers.insert(
        "X-RateLimit-Identity".to_string(),
        "consumer:spoofed".to_string(),
    );
    request_headers.insert(
        "x-ratelimit-identity".to_string(),
        "spiffe:spoofed".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert_continue(result);
    assert!(
        !request_headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("x-ratelimit-identity")),
        "spoofed identity header must be stripped before backend: {request_headers:?}"
    );
}

#[tokio::test]
async fn test_strips_backend_identity_header_before_client() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 10,
        "limit_by": "ip",
        "expose_headers": false
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    plugin.on_request_received(&mut ctx).await;

    let mut response_headers: HashMap<String, String> = HashMap::new();
    response_headers.insert(
        "X-RateLimit-Identity".to_string(),
        "backend-user".to_string(),
    );
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_continue(result);
    assert!(
        !response_headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("x-ratelimit-identity")),
        "backend identity header must be stripped before client: {response_headers:?}"
    );
    assert_eq!(
        response_headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

/// Regression test for finding #56: with limit_by=consumer the limiter key is
/// `consumer:<username>`, which is the gateway's internal notion of the caller
/// identity. It must NEVER be reflected back to the downstream client (nor the
/// upstream request) via x-ratelimit-identity, even when expose_headers=true.
/// The standard, non-sensitive x-ratelimit-* headers must still be emitted.
#[tokio::test]
async fn test_expose_headers_consumer_identity_not_leaked() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "consumer",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    let consumer = create_test_consumer();
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(consumer));

    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    // The consumer identity must not be retained as metadata (it would otherwise
    // be injected onto the response by after_proxy).
    assert!(!ctx.metadata.contains_key("ratelimit_identity"));
    // Standard rate-limit metadata still present.
    assert_eq!(ctx.metadata.get("ratelimit_limit").unwrap(), "5");

    // Downstream client response: identity must be absent, standard headers kept.
    let mut response_headers: HashMap<String, String> = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(
        !response_headers.contains_key("x-ratelimit-identity"),
        "consumer identity leaked to downstream client: {response_headers:?}"
    );
    assert_eq!(response_headers.get("x-ratelimit-limit").unwrap(), "5");
    assert_eq!(response_headers.get("x-ratelimit-remaining").unwrap(), "4");
    assert_eq!(response_headers.get("x-ratelimit-window").unwrap(), "60");

    // Upstream request to the backend must not carry the identity either.
    let mut request_headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(
        !request_headers.contains_key("x-ratelimit-identity"),
        "consumer identity leaked to upstream request: {request_headers:?}"
    );
    assert_eq!(request_headers.get("x-ratelimit-limit").unwrap(), "5");
}

/// Regression test for finding #56 (SPIFFE variant): with limit_by=spiffe the
/// limiter key is `spiffe:<peer SVID>`, the peer workload's verbatim SPIFFE id.
/// It must NEVER be reflected back to the client (nor the upstream request).
#[tokio::test]
async fn test_expose_headers_spiffe_identity_not_leaked() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "spiffe_identity",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    let mut ctx = create_test_context();
    ctx.peer_spiffe_id = Some(SpiffeId::new("spiffe://example.test/ns/app/sa/api").unwrap());

    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    assert!(!ctx.metadata.contains_key("ratelimit_identity"));

    let mut response_headers: HashMap<String, String> = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(
        !response_headers.contains_key("x-ratelimit-identity"),
        "peer SVID leaked to downstream client: {response_headers:?}"
    );
    assert_eq!(response_headers.get("x-ratelimit-limit").unwrap(), "5");

    let mut request_headers: HashMap<String, String> = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut request_headers).await;
    assert!(
        !request_headers.contains_key("x-ratelimit-identity"),
        "peer SVID leaked to upstream request: {request_headers:?}"
    );
}

/// Regression test for finding #56 (429 path): the rejection response must not
/// echo the consumer limiter identity even though expose_headers=true.
#[tokio::test]
async fn test_expose_headers_rejection_consumer_identity_not_leaked() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 1,
        "limit_by": "consumer",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    // First request for the consumer consumes the single allowed slot.
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(create_test_consumer()));
    assert_continue(plugin.authorize(&mut ctx).await);

    // Second request for the same consumer is rejected.
    let mut ctx2 = create_test_context();
    ctx2.identified_consumer = Some(Arc::new(create_test_consumer()));
    let result = plugin.authorize(&mut ctx2).await;
    match result {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 429);
            assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "1");
            assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "0");
            assert!(
                !headers.contains_key("x-ratelimit-identity"),
                "consumer identity leaked on 429 response: {headers:?}"
            );
        }
        _ => panic!("Expected Reject, got {result:?}"),
    }
}

#[tokio::test]
async fn test_expose_headers_remaining_decrements() {
    let config = json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    // Request 1: remaining should be 4
    let mut ctx1 = create_test_context();
    plugin.on_request_received(&mut ctx1).await;
    assert_eq!(ctx1.metadata.get("ratelimit_remaining").unwrap(), "4");

    // Request 2: remaining should be 3
    let mut ctx2 = create_test_context();
    plugin.on_request_received(&mut ctx2).await;
    assert_eq!(ctx2.metadata.get("ratelimit_remaining").unwrap(), "3");

    // Request 3: remaining should be 2
    let mut ctx3 = create_test_context();
    plugin.on_request_received(&mut ctx3).await;
    assert_eq!(ctx3.metadata.get("ratelimit_remaining").unwrap(), "2");
}

#[tokio::test]
async fn test_expose_headers_reports_tightest_window() {
    // per-second limit of 3 and per-minute limit of 100.
    // After 2 requests, per-second remaining=1 is tighter than per-minute remaining=98.
    let config = json!({
        "requests_per_second": 3,
        "requests_per_minute": 100,
        "limit_by": "ip",
        "expose_headers": true
    });
    let plugin = make_rate_limiter(config);

    let mut ctx1 = create_test_context();
    plugin.on_request_received(&mut ctx1).await;

    let mut ctx2 = create_test_context();
    plugin.on_request_received(&mut ctx2).await;

    // Tightest window should be per-second (remaining=1 < remaining=98)
    assert_eq!(ctx2.metadata.get("ratelimit_limit").unwrap(), "3");
    assert_eq!(ctx2.metadata.get("ratelimit_remaining").unwrap(), "1");
    assert_eq!(ctx2.metadata.get("ratelimit_window").unwrap(), "1");
}

// ─── Shared synthetic/rejection finalizer (issue #2306) ─────────────────

fn assert_standard_ratelimit_headers(
    headers: &HashMap<String, String>,
    limit: &str,
    remaining: &str,
) {
    assert_eq!(
        headers.get("x-ratelimit-limit").map(String::as_str),
        Some(limit),
        "expected x-ratelimit-limit={limit}, got {headers:?}"
    );
    assert_eq!(
        headers.get("x-ratelimit-remaining").map(String::as_str),
        Some(remaining),
        "expected x-ratelimit-remaining={remaining}, got {headers:?}"
    );
    assert_eq!(
        headers.get("x-ratelimit-window").map(String::as_str),
        Some("60"),
        "expected x-ratelimit-window=60, got {headers:?}"
    );
    assert!(
        !headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("x-ratelimit-identity")),
        "x-ratelimit-identity must never reach the client: {headers:?}"
    );
}

#[test]
fn test_applies_after_proxy_on_reject_for_synthetic_decoration() {
    let plugin = make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    }));
    assert!(
        plugin.applies_after_proxy_on_reject(),
        "rate_limiting must opt into the shared rejection/synthetic after_proxy path"
    );
}

/// Issue #2306: H1/H2 and the shared H3 path all decorate gateway-generated
/// responses through `apply_reject_after_proxy_and_synthetic_body_hooks`.
#[test]
fn test_h1_h2_and_shared_h3_reach_reject_synthetic_finalizer() {
    let h1_h2 = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/server.rs");

    assert!(
        h1_h2.contains("apply_reject_after_proxy_and_synthetic_body_hooks("),
        "H1/H2 reject/synthetic path must use the shared finalizer"
    );
    assert!(
        h3.contains("apply_reject_after_proxy_and_synthetic_body_hooks("),
        "H3 reject/synthetic path must use the shared finalizer"
    );
}

/// Admitted + counted request whose later plugin returns a synthetic 2xx must
/// still receive the same `x-ratelimit-*` headers as a backend response.
#[tokio::test]
async fn test_expose_headers_on_admitted_synthetic_2xx_via_shared_finalizer() {
    let plugin = Arc::new(make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    }))) as Arc<dyn Plugin>;

    let mut ctx = create_test_context();
    assert_continue(plugin.on_request_received(&mut ctx).await);
    assert_eq!(ctx.metadata.get("ratelimit_limit").unwrap(), "5");
    assert_eq!(ctx.metadata.get("ratelimit_remaining").unwrap(), "4");

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    headers.insert(
        "x-ratelimit-identity".to_string(),
        "spoofed-identity".to_string(),
    );
    let body = "mock-ok";
    let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
        std::slice::from_ref(&plugin),
        &mut ctx,
        PluginResult::Reject {
            status_code: 200,
            body: body.to_string(),
            headers,
        },
    )
    .await;

    match finalized {
        PluginResult::RejectBinary {
            status_code,
            body: final_body,
            headers: final_headers,
        } => {
            assert_eq!(status_code, 200, "finalizer must not change status");
            assert_eq!(
                final_body.as_ref(),
                body.as_bytes(),
                "finalizer must not change body"
            );
            assert_standard_ratelimit_headers(&final_headers, "5", "4");
        }
        other => panic!("Expected finalized RejectBinary, got {other:?}"),
    }
}

/// Admitted + counted request rejected by a later plugin must still expose the
/// counted budget on the client-visible 4xx.
#[tokio::test]
async fn test_expose_headers_on_later_plugin_4xx_via_shared_finalizer() {
    let plugin = Arc::new(make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    }))) as Arc<dyn Plugin>;

    let mut ctx = create_test_context();
    assert_continue(plugin.on_request_received(&mut ctx).await);

    let body = r#"{"error":"forbidden"}"#;
    let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
        std::slice::from_ref(&plugin),
        &mut ctx,
        PluginResult::Reject {
            status_code: 403,
            body: body.to_string(),
            headers: HashMap::new(),
        },
    )
    .await;

    match finalized {
        PluginResult::RejectBinary {
            status_code,
            body: final_body,
            headers: final_headers,
        } => {
            assert_eq!(status_code, 403, "finalizer must not change status");
            assert_eq!(
                final_body.as_ref(),
                body.as_bytes(),
                "finalizer must not change body"
            );
            assert_standard_ratelimit_headers(&final_headers, "5", "4");
        }
        other => panic!("Expected finalized RejectBinary, got {other:?}"),
    }
}

/// Even with expose_headers=false, the reject-path after_proxy still strips a
/// spoofed identity header from gateway-generated responses.
#[tokio::test]
async fn test_strips_identity_on_synthetic_path_when_expose_headers_disabled() {
    let plugin = Arc::new(make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": false
    }))) as Arc<dyn Plugin>;

    let mut ctx = create_test_context();
    assert_continue(plugin.on_request_received(&mut ctx).await);
    assert!(!ctx.metadata.contains_key("ratelimit_limit"));

    let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
        std::slice::from_ref(&plugin),
        &mut ctx,
        PluginResult::Reject {
            status_code: 200,
            body: "ok".to_string(),
            headers: HashMap::from([
                ("content-type".to_string(), "text/plain".to_string()),
                (
                    "X-RateLimit-Identity".to_string(),
                    "backend-user".to_string(),
                ),
            ]),
        },
    )
    .await;

    match finalized {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("x-ratelimit-identity")),
                "identity must be stripped on synthetic responses: {headers:?}"
            );
            assert!(
                !headers
                    .keys()
                    .any(|key| key.to_ascii_lowercase().starts_with("x-ratelimit-")),
                "expose_headers=false must not inject telemetry: {headers:?}"
            );
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("text/plain")
            );
        }
        other => panic!("Expected finalized RejectBinary, got {other:?}"),
    }
}

/// Requests that never reached the rate-limit check have no metadata; the
/// finalizer must not invent `x-ratelimit-*` values even when expose_headers is on.
#[tokio::test]
async fn test_expose_headers_absent_metadata_skips_synthetic_injection() {
    let plugin = Arc::new(make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    }))) as Arc<dyn Plugin>;

    // Never call on_request_received / authorize — no rate-limit metadata.
    let mut ctx = create_test_context();
    assert!(!ctx.metadata.contains_key("ratelimit_limit"));

    let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
        std::slice::from_ref(&plugin),
        &mut ctx,
        PluginResult::Reject {
            status_code: 200,
            body: "ok".to_string(),
            headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
        },
    )
    .await;

    match finalized {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers
                    .keys()
                    .any(|key| key.to_ascii_lowercase().starts_with("x-ratelimit-")),
                "must not synthesize rate-limit headers without metadata: {headers:?}"
            );
        }
        other => panic!("Expected finalized RejectBinary, got {other:?}"),
    }
}

/// gRPC reject normalization preserves standard rate-limit telemetry headers
/// (they are part of the supported gRPC response-header contract) while still
/// stripping `x-ratelimit-identity`.
#[tokio::test]
async fn test_expose_headers_survive_grpc_reject_normalization() {
    let plugin = Arc::new(make_rate_limiter(json!({
        "window_seconds": 60,
        "max_requests": 5,
        "limit_by": "ip",
        "expose_headers": true
    }))) as Arc<dyn Plugin>;

    let mut ctx = create_test_context();
    assert_continue(plugin.on_request_received(&mut ctx).await);

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert(
        "X-RateLimit-Identity".to_string(),
        "consumer:spoofed".to_string(),
    );
    let finalized = ferrum_edge::_test_support::finalize_plugin_rejection_for_test(
        std::slice::from_ref(&plugin),
        &mut ctx,
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"forbidden"}"#.to_string(),
            headers,
        },
    )
    .await;

    let PluginResult::RejectBinary {
        status_code,
        body,
        headers: decorated,
    } = finalized
    else {
        panic!("Expected finalized RejectBinary");
    };
    assert_standard_ratelimit_headers(&decorated, "5", "4");

    let normalized = ferrum_edge::_test_support::normalize_reject_response(
        hyper::StatusCode::from_u16(status_code).expect("valid status"),
        &body,
        &decorated,
        true,
    );
    assert_eq!(normalized.http_status, hyper::StatusCode::OK);
    assert_eq!(normalized.grpc_status, Some(7)); // PERMISSION_DENIED from 403
    assert_standard_ratelimit_headers(&normalized.headers, "5", "4");
    assert_eq!(
        normalized.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
}

// ── Redis failure policy (GHSA-87rq-v4hx-8rcq) ────────────────────────────
//
// `sync_mode: "redis"` is chosen because a budget must hold *across* gateway
// processes. Silently continuing on per-process counters during an outage (or
// against an endpoint the client cannot enforce against, such as a Cluster)
// multiplies the configured limit by the number of reachable data planes, so
// the degraded behavior is an explicit, validated policy that defaults closed.

fn redis_rate_limit_config(extra: Value) -> Value {
    let mut config = json!({
        "limit_by": "ip",
        "limits": [{ "scope": "default", "requests_per_minute": 10 }],
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:6379/0",
        // Long enough that no background recovery dial happens during a test.
        "redis_health_check_interval_seconds": 3600
    });
    let (Some(object), Some(extra)) = (config.as_object_mut(), extra.as_object()) else {
        return config;
    };
    for (key, value) in extra {
        object.insert(key.clone(), value.clone());
    }
    config
}

#[test]
fn redis_failure_policy_defaults_to_fail_closed_for_every_consumer() {
    use ferrum_edge::_test_support::{RedisFailurePolicy, rate_limit_redis_failure_policy};

    let default_config = redis_rate_limit_config(json!({}));
    let policy = rate_limit_redis_failure_policy("rate_limiting", &default_config)
        .expect("valid redis config");
    assert_eq!(
        policy,
        Some(RedisFailurePolicy::FailClosed),
        "an unspecified redis_failure_policy must not silently degrade to per-process budgets"
    );

    let explicit = rate_limit_redis_failure_policy(
        "rate_limiting",
        &redis_rate_limit_config(json!({ "redis_failure_policy": "local_fallback" })),
    )
    .expect("valid redis config");
    assert_eq!(
        explicit,
        Some(RedisFailurePolicy::LocalFallback),
        "per-process fallback must require an explicit operator opt-in"
    );

    // A local-only policy has no centralized store to lose.
    let local = rate_limit_redis_failure_policy(
        "rate_limiting",
        &rate_limiting_config(json!({ "limit_by": "ip", "requests_per_minute": 10 })),
    )
    .expect("valid local config");
    assert_eq!(local, None);
}

#[test]
fn redis_failure_policy_is_validated_in_local_mode_and_rejects_unknown_values() {
    use ferrum_edge::_test_support::rate_limit_redis_failure_policy;

    let bad = rate_limit_redis_failure_policy(
        "rate_limiting",
        &redis_rate_limit_config(json!({ "redis_failure_policy": "fail_open" })),
    )
    .expect_err("unknown policy value must fail admission");
    assert!(bad.contains("redis_failure_policy"), "diagnostic: {bad}");

    let wrong_type = rate_limit_redis_failure_policy(
        "rate_limiting",
        &redis_rate_limit_config(json!({ "redis_failure_policy": true })),
    )
    .expect_err("non-string policy must fail admission");
    assert!(wrong_type.contains("redis_failure_policy"));

    // Validated even while sync_mode is local: a later toggle to redis must not
    // activate a value admission never checked.
    let latent = rate_limiting_config(json!({
        "limit_by": "ip",
        "requests_per_minute": 10,
        "redis_failure_policy": "nonsense"
    }));
    RateLimiting::new(&latent, PluginHttpClient::default())
        .err()
        .expect("latent redis_failure_policy must be validated in local mode");
}

/// Every affected consumer must accept the key, so an operator can express the
/// policy uniformly instead of discovering that one plugin silently rejects it.
#[test]
fn redis_failure_policy_is_accepted_by_every_rate_limit_consumer() {
    use ferrum_edge::_test_support::{RedisFailurePolicy, rate_limit_redis_failure_policy};

    let redis_fields = |extra: Value| {
        let mut base = json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_health_check_interval_seconds": 3600,
            "redis_failure_policy": "local_fallback"
        });
        let (Some(object), Some(extra)) = (base.as_object_mut(), extra.as_object()) else {
            return base;
        };
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
        base
    };

    let cases = [
        (
            "rate_limiting",
            redis_fields(json!({
                "limit_by": "ip",
                "limits": [{ "scope": "default", "requests_per_minute": 10 }]
            })),
        ),
        (
            "graphql",
            redis_fields(json!({
                "type_rate_limits": { "query": { "max_requests": 5, "window_seconds": 60 } }
            })),
        ),
        (
            "grpc_method_router",
            redis_fields(json!({
                "method_rate_limits": {
                    "/pkg.Svc/M": { "max_requests": 5, "window_seconds": 60 }
                }
            })),
        ),
        (
            "udp_rate_limiting",
            redis_fields(json!({ "datagrams_per_second": 10 })),
        ),
        (
            "ai_rate_limiter",
            redis_fields(json!({ "token_limit": 100, "window_seconds": 60 })),
        ),
        (
            "ws_rate_limiting",
            redis_fields(json!({ "frames_per_second": 10, "burst_size": 10 })),
        ),
    ];

    for (plugin, config) in cases {
        let policy = rate_limit_redis_failure_policy(plugin, &config)
            .unwrap_or_else(|error| panic!("{plugin} must accept redis_failure_policy: {error}"));
        assert_eq!(
            policy,
            Some(RedisFailurePolicy::LocalFallback),
            "{plugin} must honor the configured redis_failure_policy"
        );
    }
}

/// The defining behavior: while the centralized store cannot be consulted, a
/// fail-closed policy refuses instead of admitting on a budget only this
/// process can see. `503` (not `429`) because the caller is not over its limit
/// — the limit is unprovable — and no rate-limit headers are advertised.
#[tokio::test]
async fn fail_closed_policy_refuses_while_redis_is_unavailable() {
    use ferrum_edge::_test_support::rate_limiting_refusal_under_redis_outage;

    let refusal = rate_limiting_refusal_under_redis_outage(
        &redis_rate_limit_config(json!({ "expose_headers": true })),
        "ip:203.0.113.7",
    )
    .await
    .expect("valid redis config")
    .expect("fail_closed must refuse rather than admit on per-process state");

    assert_eq!(refusal.0, 503, "an unprovable budget is not a 429");
    assert!(
        refusal.1.contains("temporarily unavailable"),
        "body: {}",
        refusal.1
    );
    assert!(
        !refusal.1.contains("redis") && !refusal.1.contains("Redis"),
        "the refusal must not disclose the enforcement backend: {}",
        refusal.1
    );
}

/// The availability escape hatch still works — but only when asked for.
#[tokio::test]
async fn local_fallback_policy_admits_while_redis_is_unavailable() {
    use ferrum_edge::_test_support::rate_limiting_refusal_under_redis_outage;

    let refusal = rate_limiting_refusal_under_redis_outage(
        &redis_rate_limit_config(json!({ "redis_failure_policy": "local_fallback" })),
        "ip:203.0.113.7",
    )
    .await
    .expect("valid redis config");

    assert!(
        refusal.is_none(),
        "local_fallback must admit on per-process state, got {refusal:?}"
    );
}

// ── Composed limiters and the single public header set (issue #5003) ──────
//
// `x-ratelimit-limit` / `-remaining` / `-window` are one fixed public contract,
// but a route may carry several `rate_limiting` instances and every instance
// opts into the shared rejection finalizer. Composition therefore has to name
// one authoritative verdict — the refusing limiter, or the tightest budget when
// all of them admitted — instead of whichever `after_proxy` happened to run
// last.

fn composed_limiter(requests_per_minute: u64, expose_headers: bool) -> Arc<dyn Plugin> {
    Arc::new(make_rate_limiter(json!({
        "limit_by": "ip",
        "expose_headers": expose_headers,
        "requests_per_minute": requests_per_minute,
    }))) as Arc<dyn Plugin>
}

fn meta<'a>(ctx: &'a RequestContext, key: &str) -> Option<&'a str> {
    ctx.metadata.get(key).map(String::as_str)
}

/// Assert the refusal status without consuming the result: `PluginResult` is
/// not `Clone`, and the finalizer needs the original value.
fn expect_reject(result: PluginResult, expected_status: u16) -> PluginResult {
    match &result {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(*status_code, expected_status);
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
    result
}

/// Run the shared rejection finalizer over `plugins` and return its headers.
async fn finalized_rejection_headers(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    rejection: PluginResult,
) -> HashMap<String, String> {
    use ferrum_edge::_test_support::finalize_plugin_rejection_for_test;

    let finalized = finalize_plugin_rejection_for_test(plugins, ctx, rejection).await;
    match finalized {
        PluginResult::RejectBinary { headers, .. } => headers,
        other => panic!("Expected finalized RejectBinary, got {other:?}"),
    }
}

fn assert_no_ratelimit_headers(headers: &HashMap<String, String>) {
    assert!(
        !headers
            .keys()
            .any(|key| key.to_ascii_lowercase().starts_with("x-ratelimit-")),
        "no rate-limit telemetry may describe this response: {headers:?}"
    );
}

/// The refusing limiter's 429 telemetry must survive the finalizer, not be
/// overwritten by a sibling that admitted the very same request.
#[tokio::test]
async fn composed_limiters_publish_the_refusing_budget_on_a_429() {
    let generous = composed_limiter(100, true);
    let strict = composed_limiter(1, true);
    let plugins = [Arc::clone(&generous), Arc::clone(&strict)];

    // Request 1 consumes the strict limiter's only slot.
    let mut first = create_test_context();
    assert_continue(generous.on_request_received(&mut first).await);
    assert_continue(strict.on_request_received(&mut first).await);

    // Request 2: the generous limiter admits and stages `remaining: 98`, then
    // the strict limiter refuses.
    let mut ctx = create_test_context();
    assert_continue(generous.on_request_received(&mut ctx).await);
    assert_eq!(meta(&ctx, "ratelimit_remaining"), Some("98"));
    let rejection = expect_reject(strict.on_request_received(&mut ctx).await, 429);

    let finalized = finalized_rejection_headers(&plugins, &mut ctx, rejection).await;
    assert_standard_ratelimit_headers(&finalized, "1", "0");
}

/// Refusal wins across the two enforcement phases too: an IP limiter admits in
/// `on_request_received`, and a consumer limiter then refuses in `authorize`.
#[tokio::test]
async fn a_consumer_limiter_refusal_outranks_an_admitted_ip_budget() {
    let by_ip = composed_limiter(100, true);
    let by_consumer = Arc::new(make_rate_limiter(json!({
        "limit_by": "consumer",
        "expose_headers": true,
        "requests_per_minute": 1,
    }))) as Arc<dyn Plugin>;
    let plugins = [Arc::clone(&by_ip), Arc::clone(&by_consumer)];

    let mut first = create_test_context();
    assert_continue(by_ip.on_request_received(&mut first).await);
    assert_continue(by_consumer.authorize(&mut first).await);

    let mut ctx = create_test_context();
    assert_continue(by_ip.on_request_received(&mut ctx).await);
    let rejection = expect_reject(by_consumer.authorize(&mut ctx).await, 429);

    let finalized = finalized_rejection_headers(&plugins, &mut ctx, rejection).await;
    assert_standard_ratelimit_headers(&finalized, "1", "0");
}

/// A refusing limiter configured not to expose headers publishes nothing — and
/// that verdict also retires the budget a sibling staged for the same request.
#[tokio::test]
async fn a_refusing_limiter_that_hides_headers_retires_a_sibling_budget() {
    let generous = composed_limiter(100, true);
    let strict = composed_limiter(1, false);
    let plugins = [Arc::clone(&generous), Arc::clone(&strict)];

    let mut first = create_test_context();
    assert_continue(generous.on_request_received(&mut first).await);
    assert_continue(strict.on_request_received(&mut first).await);

    let mut ctx = create_test_context();
    assert_continue(generous.on_request_received(&mut ctx).await);
    assert_eq!(meta(&ctx, "ratelimit_remaining"), Some("98"));
    let rejection = expect_reject(strict.on_request_received(&mut ctx).await, 429);

    let finalized = finalized_rejection_headers(&plugins, &mut ctx, rejection).await;
    assert_no_ratelimit_headers(&finalized);
}

/// A fail-closed `503` is not a budget verdict. An earlier sibling's admitted
/// telemetry must not be published as the unavailable limiter's answer.
#[tokio::test]
async fn an_admitted_sibling_budget_is_not_published_on_a_fail_closed_503() {
    use ferrum_edge::_test_support::rate_limiting_mark_redis_unavailable_for_test;

    let generous = composed_limiter(100, true);
    let centralized = make_rate_limiter(redis_rate_limit_config(json!({
        "expose_headers": true,
        // Nothing listens on port 1; the client is then forced unavailable so
        // the outage is deterministic rather than dial-timing dependent.
        "redis_url": "redis://127.0.0.1:1/0",
    })));
    assert!(
        rate_limiting_mark_redis_unavailable_for_test(&centralized),
        "sync_mode=redis must build a client that can be marked unavailable"
    );
    let centralized = Arc::new(centralized) as Arc<dyn Plugin>;
    let plugins = [Arc::clone(&generous), Arc::clone(&centralized)];

    let mut ctx = create_test_context();
    assert_continue(generous.on_request_received(&mut ctx).await);
    assert_eq!(meta(&ctx, "ratelimit_remaining"), Some("99"));
    let rejection = expect_reject(centralized.on_request_received(&mut ctx).await, 503);

    let finalized = finalized_rejection_headers(&plugins, &mut ctx, rejection).await;
    assert_no_ratelimit_headers(&finalized);
}

/// With every limiter admitting, the tightest budget is published — the same
/// rule one instance already applies across its own windows — and the answer
/// does not depend on the order the instances run in.
#[tokio::test]
async fn composed_admitted_limiters_publish_the_tightest_budget_in_either_order() {
    let generous = composed_limiter(100, true);
    let strict = composed_limiter(5, true);
    let mut ctx = create_test_context();
    assert_continue(generous.on_request_received(&mut ctx).await);
    assert_continue(strict.on_request_received(&mut ctx).await);
    assert_eq!(meta(&ctx, "ratelimit_limit"), Some("5"));
    assert_eq!(meta(&ctx, "ratelimit_remaining"), Some("4"));

    let generous_reversed = composed_limiter(100, true);
    let strict_reversed = composed_limiter(5, true);
    let mut reversed = create_test_context();
    assert_continue(strict_reversed.on_request_received(&mut reversed).await);
    assert_continue(generous_reversed.on_request_received(&mut reversed).await);
    assert_eq!(
        meta(&reversed, "ratelimit_limit"),
        Some("5"),
        "plugin order must not decide which budget the client sees"
    );
    assert_eq!(meta(&reversed, "ratelimit_remaining"), Some("4"));
}
