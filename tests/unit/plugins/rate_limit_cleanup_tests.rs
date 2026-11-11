//! Controllable-time coverage for shared rate-limit consumer cleanup wrappers (#2316).
//!
//! These tests invoke each plugin's sampled/cooldown cleanup path through
//! `_test_support` hooks — not `LocalLimiter::prune_stale_at` directly — so a
//! wrapper that skips or mis-schedules its prune fails. Cleanup under capacity
//! pressure must reclaim idle keys only; live budgets survive
//! (GHSA-3xxf-5m26-c8pv).

use ferrum_edge::_test_support::RateLimitCleanupHarness;
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::utils::rate_limit::{DynamicHttpRateLimitAlgorithm, RateLimitBackend};
use serde_json::json;
use std::time::{Duration, Instant};

#[test]
fn udp_sampled_cooldown_path_prunes_stale_preserves_active_below_cap() {
    let h = RateLimitCleanupHarness::new();
    let epoch = h.udp_epoch_base();

    h.seed_udp("10.0.0.1", epoch);
    h.seed_udp("10.0.0.2", epoch);
    // Idle threshold is max(window_seconds * 2, 10) == 10s for window=1.
    let active_at = epoch + Duration::from_secs(11);
    h.seed_udp("10.0.0.3", active_at);
    assert_eq!(h.udp_tracked(), Some(3));

    // Cooldown still open: armed sample must not scan.
    h.arm_udp_periodic();
    h.block_udp_cooldown_at(active_at);
    let _ = h.maybe_evict_udp_at(active_at);
    assert_eq!(h.udp_tracked(), Some(3));

    // Clear cooldown and hit the sampled periodic path.
    h.arm_udp_periodic();
    let _ = h.maybe_evict_udp_at(active_at);
    assert_eq!(h.udp_tracked(), Some(1));
    assert!(h.udp_contains("10.0.0.3"));
    assert!(!h.udp_contains("10.0.0.1"));
    assert!(!h.udp_contains("10.0.0.2"));
}

#[test]
fn udp_over_cap_path_keeps_strict_admission_without_live_eviction() {
    let h = RateLimitCleanupHarness::new();
    let epoch = h.udp_epoch_base();
    h.seed_udp("10.0.0.1", epoch);
    h.seed_udp("10.0.0.2", epoch);
    h.seed_udp("10.0.0.3", epoch);
    assert_eq!(h.udp_tracked(), Some(3));

    // A just-recorded sweep blocks another full-map scan, but the over-cap
    // result must remain true so on_udp_datagram rejects an unseen IP in O(1).
    let now = epoch + Duration::from_secs(1);
    h.block_udp_cooldown_at(now);
    assert!(h.maybe_evict_udp_at_with_cap(now, 1));
    assert_eq!(h.udp_tracked(), Some(3));

    // The next second admits exactly one reclaim scan. Active keys survive;
    // over-cap admission remains closed for previously unseen keys.
    let next = now + Duration::from_secs(1);
    assert!(h.maybe_evict_udp_at_with_cap(next, 1));
    assert_eq!(h.udp_tracked(), Some(3));
    assert!(h.udp_contains("10.0.0.1"));
    assert!(h.udp_contains("10.0.0.2"));
    assert!(h.udp_contains("10.0.0.3"));
    assert!(!h.seed_udp_with_cap("10.0.0.4", next, 1));

    // New active entries in the same second cannot retrigger another scan.
    // Uncapped test seeds model legacy/repair pressure only.
    h.seed_udp("10.0.0.4", next);
    h.seed_udp("10.0.0.5", next);
    let before = h.udp_tracked();
    assert!(h.maybe_evict_udp_at_with_cap(next, 1));
    assert_eq!(h.udp_tracked(), before);
}

#[test]
fn rate_limiting_wrapper_prunes_stale_and_preserves_active_over_cap() {
    let h = RateLimitCleanupHarness::new();
    let t0 = Instant::now();
    h.seed_rate_limiting("ip:1", t0);
    h.seed_rate_limiting("ip:2", t0);
    let active_at = t0 + Duration::from_secs(3);
    h.seed_rate_limiting("ip:3", active_at);
    assert_eq!(h.rate_limiting_tracked(), Some(3));

    h.arm_rate_limiting_periodic();
    h.block_rate_limiting_cooldown_at(active_at);
    h.maybe_evict_rate_limiting_at(active_at);
    assert_eq!(h.rate_limiting_tracked(), Some(3));

    h.arm_rate_limiting_periodic();
    h.maybe_evict_rate_limiting_at(active_at);
    assert_eq!(h.rate_limiting_tracked(), Some(1));
    assert!(h.rate_limiting_contains("ip:3"));
    assert!(!h.rate_limiting_contains("ip:1"));
    assert!(!h.rate_limiting_contains("ip:2"));

    h.seed_rate_limiting("ip:a", active_at);
    h.seed_rate_limiting("ip:b", active_at);
    h.seed_rate_limiting("ip:c", active_at);
    h.rate_limiting_prune_stale(active_at);
    assert_eq!(h.rate_limiting_tracked(), Some(4));
    assert!(h.rate_limiting_contains("ip:3"));
    assert!(h.rate_limiting_contains("ip:a"));
    assert!(!h.seed_rate_limiting_with_cap("ip:new", active_at, 1));
}

#[test]
fn ai_wrapper_prunes_stale_and_preserves_active_over_cap() {
    let h = RateLimitCleanupHarness::new();
    let t0 = Instant::now();
    h.seed_ai("consumer:a", t0);
    h.seed_ai("consumer:b", t0);
    let active_at = t0 + Duration::from_secs(2);
    h.seed_ai("consumer:c", active_at);
    assert_eq!(h.ai_tracked(), Some(3));

    h.arm_ai_periodic();
    h.maybe_evict_ai_at(active_at);
    assert_eq!(h.ai_tracked(), Some(1));
    assert!(h.ai_contains("consumer:c"));
    assert!(!h.ai_contains("consumer:a"));
    assert!(!h.ai_contains("consumer:b"));

    h.seed_ai("consumer:x", active_at);
    h.seed_ai("consumer:y", active_at);
    h.ai_prune_stale(active_at);
    assert_eq!(h.ai_tracked(), Some(3));
    assert!(h.ai_contains("consumer:c"));
    assert!(!h.seed_ai_with_cap("consumer:new", active_at, 1));
}

#[test]
fn graphql_wrapper_prunes_stale_and_preserves_active_over_cap() {
    let h = RateLimitCleanupHarness::new();
    let t0 = Instant::now();
    h.seed_graphql("gql:1", t0);
    h.seed_graphql("gql:2", t0);
    let active_at = t0 + Duration::from_secs(3);
    h.seed_graphql("gql:3", active_at);
    assert_eq!(h.graphql_tracked(), Some(3));

    h.arm_graphql_periodic();
    h.maybe_evict_graphql_at(active_at);
    assert_eq!(h.graphql_tracked(), Some(1));
    assert!(h.graphql_contains("gql:3"));
    assert!(!h.graphql_contains("gql:1"));
    assert!(!h.graphql_contains("gql:2"));

    h.seed_graphql("gql:a", active_at);
    h.seed_graphql("gql:b", active_at);
    h.graphql_prune_stale(active_at);
    assert_eq!(h.graphql_tracked(), Some(3));
    assert!(h.graphql_contains("gql:3"));
    assert!(!h.seed_graphql_with_cap("gql:new", active_at, 1));
}

#[test]
fn grpc_wrapper_prunes_stale_and_preserves_active_over_cap() {
    let h = RateLimitCleanupHarness::new();
    let t0 = Instant::now();
    h.seed_grpc("grpc:1", t0);
    h.seed_grpc("grpc:2", t0);
    let active_at = t0 + Duration::from_secs(3);
    h.seed_grpc("grpc:3", active_at);
    assert_eq!(h.grpc_tracked(), Some(3));

    h.arm_grpc_periodic();
    h.maybe_evict_grpc_at(active_at);
    assert_eq!(h.grpc_tracked(), Some(1));
    assert!(h.grpc_contains("grpc:3"));
    assert!(!h.grpc_contains("grpc:1"));
    assert!(!h.grpc_contains("grpc:2"));

    h.seed_grpc("grpc:a", active_at);
    h.seed_grpc("grpc:b", active_at);
    h.grpc_prune_stale(active_at);
    assert_eq!(h.grpc_tracked(), Some(3));
    assert!(h.grpc_contains("grpc:3"));
    assert!(!h.seed_grpc_with_cap("grpc:new", active_at, 1));
}

#[test]
fn ws_sampled_cooldown_path_prunes_stale_preserves_active_below_cap() {
    let h = RateLimitCleanupHarness::new();
    let t0 = Instant::now();
    h.seed_ws(1, t0);
    h.seed_ws(2, t0);
    // Token-bucket activity window is 2× (burst / fps) == 2s.
    let active_at = t0 + Duration::from_secs(3);
    h.seed_ws(3, active_at);
    assert_eq!(h.ws_tracked(), Some(3));

    h.arm_ws_periodic();
    h.block_ws_cooldown_at(active_at);
    let _ = h.maybe_evict_ws_at(active_at);
    assert_eq!(h.ws_tracked(), Some(3));

    h.arm_ws_periodic();
    let _ = h.maybe_evict_ws_at(active_at);
    assert_eq!(h.ws_tracked(), Some(1));
    assert!(h.ws_contains(3));
    assert!(!h.ws_contains(1));
    assert!(!h.ws_contains(2));

    h.seed_ws(10, active_at);
    h.seed_ws(11, active_at);
    h.ws_prune_stale(active_at);
    assert_eq!(h.ws_tracked(), Some(3));
    assert!(h.ws_contains(3));
    assert!(!h.seed_ws_with_cap(12, active_at, 1));
}

#[test]
fn rate_limit_backend_local_and_failover_expose_below_cap_prune() {
    let local: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({}),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("local backend");
    assert!(matches!(local, RateLimitBackend::Local(_)));

    let failover: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:9/0",
                "redis_health_check_interval_seconds": 1
            }),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    assert!(matches!(failover, RateLimitBackend::Failover(_)));

    // Both backend variants accept prune_stale_at without requiring an
    // over-cap map (the historical below-cap no-op).
    let now = Instant::now();
    local.prune_stale_at(now);
    failover.prune_stale_at(now);
    assert_eq!(local.tracked_keys_count(), 0);
    assert_eq!(failover.tracked_keys_count(), 0);
}
