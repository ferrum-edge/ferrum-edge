//! Capacity admission for shared local/Redis-fallback rate limiters
//! (GHSA-3xxf-5m26-c8pv).
//!
//! Hard cardinality is enforced by atomic reservation on admission. Cleanup
//! may reclaim idle keys but must never delete still-active budgets. Existing
//! keys continue at capacity; previously unseen local/fallback keys fail
//! closed. Redis-healthy admission remains centralized and uncapped locally.

use ferrum_edge::_test_support::RateLimitCleanupHarness;
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitWindowSpec,
    RedisFailurePolicy,
};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn http_op() -> DynamicRateLimitOp {
    DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1_000,
        duration: Duration::from_secs(60),
    }])
}

fn local_backend() -> RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> {
    RateLimitBackend::from_plugin_config(
        "rate_limiting",
        &json!({}),
        &PluginHttpClient::default(),
        DynamicHttpRateLimitAlgorithm::new(),
    )
    .expect("local backend")
}

fn failover_backend() -> RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> {
    // Point at a closed port so Redis is unavailable and admission lands in
    // the local fallback map (the Redis-fallback consumer path).
    //
    // `redis_failure_policy: "local_fallback"` is stated rather than inherited.
    // It is `rate_limiting`'s own default (issue #5519) — the other five
    // rate-limit plugins still default to `fail_closed`, which refuses during
    // an outage before the fallback map is ever consulted — so pinning it here
    // keeps this fixture exercising local capacity admission no matter which
    // way the default moves.
    RateLimitBackend::from_plugin_config(
        "rate_limiting",
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:9/0",
            "redis_health_check_interval_seconds": 1,
            "redis_failure_policy": "local_fallback"
        }),
        &PluginHttpClient::default(),
        DynamicHttpRateLimitAlgorithm::new(),
    )
    .expect("failover backend")
}

#[test]
fn active_consumed_keys_survive_capacity_pressure() {
    let backend = local_backend();
    let op = http_op();
    let now = Instant::now();
    let max_entries = 3usize;

    for idx in 0..max_entries {
        let key = format!("active:{idx}");
        let outcome = backend
            .check_local_at_with_capacity(key.clone(), &op, now, max_entries)
            .expect("admit within cap");
        assert!(outcome.allowed);
        // Consume remaining budget so the key is non-zero usage.
        for _ in 0..8 {
            let _ = backend.check_local_at_with_capacity(key.clone(), &op, now, max_entries);
        }
        assert!(backend.contains_local_key(&key));
    }
    assert_eq!(backend.tracked_keys_count(), max_entries);

    backend.enforce_capacity(1, now);
    assert_eq!(backend.tracked_keys_count(), max_entries);
    for idx in 0..max_entries {
        assert!(backend.contains_local_key(&format!("active:{idx}")));
    }
}

#[test]
fn unseen_keys_deny_at_capacity_while_existing_retain_budgets() {
    let backend = local_backend();
    let op = http_op();
    let now = Instant::now();
    let max_entries = 2usize;

    assert!(
        backend
            .check_local_at_with_capacity("keep-a".into(), &op, now, max_entries)
            .expect("admit")
            .allowed
    );
    assert!(
        backend
            .check_local_at_with_capacity("keep-b".into(), &op, now, max_entries)
            .expect("admit")
            .allowed
    );
    assert!(
        backend
            .check_local_at_with_capacity("new".into(), &op, now, max_entries)
            .is_none()
    );
    assert_eq!(backend.tracked_keys_count(), 2);
    assert!(backend.contains_local_key(&"keep-a".to_string()));
    assert!(backend.contains_local_key(&"keep-b".to_string()));
    assert!(!backend.contains_local_key(&"new".to_string()));

    // Existing keys continue to charge against retained budgets.
    let _again = backend
        .check_local_at_with_capacity("keep-a".into(), &op, now, max_entries)
        .expect("existing key continues");
    assert!(backend.contains_local_key(&"keep-a".to_string()));
    assert_eq!(backend.tracked_keys_count(), 2);
}

#[test]
fn stale_keys_prune_then_new_key_admits() {
    let backend = local_backend();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 100,
        duration: Duration::from_secs(1),
    }]);
    let t0 = Instant::now();
    let max_entries = 2usize;

    assert!(
        backend
            .check_local_at_with_capacity("stale-a".into(), &op, t0, max_entries)
            .is_some()
    );
    assert!(
        backend
            .check_local_at_with_capacity("stale-b".into(), &op, t0, max_entries)
            .is_some()
    );
    assert!(
        backend
            .check_local_at_with_capacity("blocked".into(), &op, t0, max_entries)
            .is_none()
    );

    // Token-bucket idle threshold is 2× window (== 2s). Advance past that.
    let later = t0 + Duration::from_secs(3);
    backend.prune_stale_at(later);
    assert_eq!(backend.tracked_keys_count(), 0);
    assert!(
        backend
            .check_local_at_with_capacity("fresh".into(), &op, later, max_entries)
            .expect("slot freed by stale prune")
            .allowed
    );
}

#[tokio::test]
async fn redis_fallback_path_denies_new_local_keys_at_capacity() {
    let backend = failover_backend();
    let op = http_op();
    let max_entries = 2usize;

    // Pin the opt-in: if this fixture ever drifts back to the fail-closed
    // default, the refusals below would be enforcement-unavailable denials
    // rather than the capacity denials this test exists to prove.
    assert_eq!(
        backend.redis_failure_policy(),
        Some(RedisFailurePolicy::LocalFallback),
        "capacity coverage must run on the explicit local-fallback opt-in"
    );

    // First checks fail Redis and populate local fallback.
    let first = backend
        .check_with_redis_key_and_local_capacity(
            "fb-a".to_string(),
            || "redis:fb-a".to_string(),
            &op,
            max_entries,
        )
        .await
        .expect("admit fallback a");
    assert!(first.allowed);
    let second = backend
        .check_with_redis_key_and_local_capacity(
            "fb-b".to_string(),
            || "redis:fb-b".to_string(),
            &op,
            max_entries,
        )
        .await
        .expect("admit fallback b");
    assert!(second.allowed);
    assert!(
        backend
            .check_with_redis_key_and_local_capacity(
                "fb-new".to_string(),
                || "redis:fb-new".to_string(),
                &op,
                max_entries,
            )
            .await
            .is_none()
    );
    assert_eq!(backend.tracked_keys_count(), 2);
    assert!(backend.contains_local_key(&"fb-a".to_string()));
    assert!(backend.contains_local_key(&"fb-b".to_string()));

    // The capacity denial above carries no outcome, so its provenance has to
    // travel beside it. A Redis-backed policy hitting the local key cap while
    // serving the fallback budget is an outage symptom, not client behaviour,
    // and must be attributed with `ratelimit_local_fallback` like every other
    // fallback decision.
    let denied = backend
        .check_with_redis_key_and_local_capacity_attributed(
            "fb-new".to_string(),
            || "redis:fb-new".to_string(),
            &op,
            max_entries,
        )
        .await;
    assert!(denied.outcome.is_none(), "still a capacity denial");
    assert!(
        denied.local_fallback,
        "the decision itself must report that it was served on the fallback budget"
    );

    // The backend-level observability signal still answers its own question.
    assert!(
        backend.local_fallback_active(),
        "a Redis-backed policy whose store is unreachable is serving the fallback budget"
    );
    assert!(
        !local_backend().local_fallback_active(),
        "a local-only policy has no centralized store to lose"
    );
    let local_denied = local_backend()
        .check_with_redis_key_and_local_capacity_attributed(
            "only".to_string(),
            || "redis:only".to_string(),
            &op,
            0,
        )
        .await;
    assert!(local_denied.outcome.is_none());
    assert!(
        !local_denied.local_fallback,
        "a local-only policy's capacity denial is not a degraded-enforcement refusal"
    );
}

#[test]
fn plugin_parity_active_keys_survive_and_unseen_deny() {
    let h = RateLimitCleanupHarness::new();
    let now = Instant::now();
    let cap = 2usize;

    assert!(h.seed_rate_limiting_with_cap("rl:a", now, cap));
    assert!(h.seed_rate_limiting_with_cap("rl:b", now, cap));
    assert!(!h.seed_rate_limiting_with_cap("rl:c", now, cap));
    h.rate_limiting_apply_branch(now, true, 1);
    assert_eq!(h.rate_limiting_tracked(), Some(2));
    assert!(h.rate_limiting_contains("rl:a"));
    assert!(h.rate_limiting_contains("rl:b"));

    assert!(h.seed_ai_with_cap("ai:a", now, cap));
    assert!(h.seed_ai_with_cap("ai:b", now, cap));
    assert!(!h.seed_ai_with_cap("ai:c", now, cap));
    h.ai_apply_branch(now, true, 1);
    assert_eq!(h.ai_tracked(), Some(2));
    assert!(h.ai_contains("ai:a"));

    assert!(h.seed_graphql_with_cap("gql:a", now, cap));
    assert!(h.seed_graphql_with_cap("gql:b", now, cap));
    assert!(!h.seed_graphql_with_cap("gql:c", now, cap));
    h.graphql_apply_branch(now, true, 1);
    assert_eq!(h.graphql_tracked(), Some(2));
    assert!(h.graphql_contains("gql:a"));

    assert!(h.seed_grpc_with_cap("grpc:a", now, cap));
    assert!(h.seed_grpc_with_cap("grpc:b", now, cap));
    assert!(!h.seed_grpc_with_cap("grpc:c", now, cap));
    h.grpc_apply_branch(now, true, 1);
    assert_eq!(h.grpc_tracked(), Some(2));
    assert!(h.grpc_contains("grpc:a"));

    assert!(h.seed_ws_with_cap(1, now, cap));
    assert!(h.seed_ws_with_cap(2, now, cap));
    assert!(!h.seed_ws_with_cap(3, now, cap));
    h.ws_apply_branch(now, true, 1);
    assert_eq!(h.ws_tracked(), Some(2));
    assert!(h.ws_contains(1));

    let epoch = h.udp_epoch_base();
    assert!(h.seed_udp_with_cap("10.0.0.1", epoch, cap));
    assert!(h.seed_udp_with_cap("10.0.0.2", epoch, cap));
    assert!(!h.seed_udp_with_cap("10.0.0.3", epoch, cap));
    let _ = h.maybe_evict_udp_at_with_cap(epoch, 1);
    assert_eq!(h.udp_tracked(), Some(2));
    assert!(h.udp_contains("10.0.0.1"));
}

#[test]
fn steady_capacity_admission_skips_all_shard_len() {
    let backend = local_backend();
    let op = http_op();
    let now = Instant::now();
    for idx in 0..8 {
        let _ = backend.check_local_at_with_capacity(format!("k:{idx}"), &op, now, 64);
    }
    let before = backend.all_shard_len_calls_for_test();
    for _ in 0..2_000 {
        let _ = backend.check_local_at_with_capacity("k:0".into(), &op, now, 64);
        let _ = backend.tracked_keys_count();
    }
    assert_eq!(
        backend.all_shard_len_calls_for_test(),
        before,
        "steady capacity-aware admission must not call DashMap::len()"
    );
}

#[tokio::test]
async fn udp_capacity_deny_preserves_existing_client_budgets() {
    use ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting;
    use ferrum_edge::plugins::{
        Plugin, StreamBytesKind, UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
    };

    let plugin = UdpRateLimiting::new_with_http_client(
        &json!({"datagrams_per_second": 1_000_000, "window_seconds": 60}),
        PluginHttpClient::default(),
    )
    .expect("udp plugin");

    for idx in 0..8u8 {
        let ip: std::net::IpAddr = format!("198.51.100.{idx}")
            .parse()
            .expect("test client IP parses");
        let client_addr = std::net::SocketAddr::new(ip, 5353);
        let ctx = UdpDatagramContext {
            client_ip: ferrum_edge::proxy::udp_proxy::udp_session_client_ip(client_addr),
            client_ip_addr: ferrum_edge::proxy::udp_proxy::udp_session_client_addr(client_addr),
            proxy_id: Arc::from("proxy-1"),
            proxy_name: Some(Arc::from("test-proxy")),
            listen_port: 5353,
            datagram_size: 64,
            direction: UdpDatagramDirection::ClientToBackend,
            payload: &[],
            payload_kind: StreamBytesKind::PlaintextWire,
            metadata_sink: None,
        };
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    assert_eq!(plugin.tracked_keys_count(), Some(8));
}
