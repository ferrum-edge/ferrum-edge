//! Tests for load balancer module

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::load_balancer::{
    HealthContext, LoadBalancer, LoadBalancerCache, target_host_port_key, target_key,
};
use std::collections::HashMap;

const TEST_UPSTREAM: &str = "test-upstream";

/// Helper to build a HealthContext for tests that only need active unhealthy filtering.
fn active_health_ctx(active: &DashMap<String, u64>) -> HealthContext<'_> {
    HealthContext {
        active_unhealthy: active,
        proxy_passive: None,
        max_ejection_percent: None,
    }
}
use std::sync::atomic::{AtomicI64, Ordering};

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{}", i),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn make_weighted_targets() -> Vec<UpstreamTarget> {
    vec![
        UpstreamTarget {
            host: "heavy".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 5,
            tags: HashMap::new(),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "light".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        },
    ]
}

#[test]
fn test_round_robin_distributes_evenly() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let mut counts = HashMap::new();
    for _ in 0..300 {
        let sel = lb.select("", None).unwrap();
        assert!(!sel.is_fallback);
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    assert_eq!(counts.len(), 3);
    for count in counts.values() {
        assert_eq!(*count, 100);
    }
}

#[test]
fn test_weighted_round_robin_respects_weights() {
    let targets = make_weighted_targets();
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let mut counts = HashMap::new();
    for _ in 0..600 {
        let sel = lb.select("", None).unwrap();
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    let heavy = counts.get("heavy").copied().unwrap_or(0);
    let light = counts.get("light").copied().unwrap_or(0);
    // heavy should get ~5x more than light
    assert!(heavy > light * 3, "heavy={} light={}", heavy, light);
}

#[test]
fn test_consistent_hash_same_key_same_target() {
    let targets = make_targets(5);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        None,
    );

    let first = lb.select("user-123", None).unwrap();
    for _ in 0..100 {
        let sel = lb.select("user-123", None).unwrap();
        assert_eq!(sel.target.host, first.target.host);
    }
}

#[test]
fn test_least_connections_prefers_least_loaded() {
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastConnections,
        &targets,
        None,
    );

    // Simulate 5 connections to host0
    for _ in 0..5 {
        lb.active_connections
            .entry(target_host_port_key(&targets[0]))
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    // Next selection should prefer host1
    let sel = lb.select("", None).unwrap();
    assert_eq!(sel.target.host, "host1");
}

#[test]
fn test_unhealthy_targets_filtered() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host0:8080", TEST_UPSTREAM), 0);

    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
        assert!(
            !sel.is_fallback,
            "Should not be fallback when healthy targets exist"
        );
        seen.insert(sel.target.host.clone());
    }

    assert!(!seen.contains("host0"));
    assert!(seen.contains("host1"));
    assert!(seen.contains("host2"));
}

#[test]
fn test_all_unhealthy_falls_back_to_all() {
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host0:8080", TEST_UPSTREAM), 0);
    unhealthy.insert(format!("{}::host1:8080", TEST_UPSTREAM), 0);

    // Should still return a target (fallback) and mark it as degraded
    let sel = lb.select("", Some(&active_health_ctx(&unhealthy)));
    assert!(sel.is_some());
    assert!(
        sel.unwrap().is_fallback,
        "All-unhealthy selection should be marked as fallback"
    );
}

#[test]
fn test_select_excluding_skips_target() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let exclude = targets[0].clone();
    for _ in 0..100 {
        let t = lb.select_excluding("", &exclude, None).unwrap();
        assert_ne!(t.host, "host0");
    }
}

#[test]
fn test_empty_targets() {
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::RoundRobin, &[], None);
    assert!(lb.select("", None).is_none());
}

#[test]
fn test_load_balancer_cache() {
    let config = GatewayConfig {
        version: "1".to_string(),
        upstreams: vec![Upstream {
            id: "us1".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            name: Some("test".into()),
            targets: make_targets(2),
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_strict: false,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            dispatch_port_override_fallback: None,
            api_spec_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..Default::default()
    };

    let cache = LoadBalancerCache::new(&config);
    let t = cache.select_target("us1", "", None);
    assert!(t.is_some());

    let t = cache.select_target("nonexistent", "", None);
    assert!(t.is_none());
}

// ─── Least Latency Tests ────────────────────────────────────────────────────

#[test]
fn test_least_latency_warmup_uses_round_robin() {
    // During the warm-up phase (< 5 samples per target), least-latency
    // should distribute traffic via round-robin to collect baselines.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Record only 2 samples for host0 — not enough for warm-up to complete
    for _ in 0..2 {
        lb.record_latency(&targets[0], 1000);
    }

    // All targets should still get traffic (round-robin during warm-up)
    let mut counts = HashMap::new();
    for _ in 0..300 {
        let sel = lb.select("", None).unwrap();
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    // All 3 targets should have received traffic
    assert_eq!(
        counts.len(),
        3,
        "All targets should get traffic during warm-up"
    );
    for count in counts.values() {
        assert_eq!(
            *count, 100,
            "Traffic should be evenly distributed during warm-up"
        );
    }
}

#[test]
fn test_least_latency_prefers_lowest_latency_after_warmup() {
    // After warm-up completes, traffic should go to the lowest-latency target.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Complete warm-up for all targets with distinct latencies:
    // host0: 10ms (10000μs), host1: 1ms (1000μs), host2: 5ms (5000μs)
    let latencies_us = [10_000u64, 1_000, 5_000];
    for (i, &latency) in latencies_us.iter().enumerate() {
        for _ in 0..10 {
            lb.record_latency(&targets[i], latency);
        }
    }

    // After warm-up, all selections should prefer host1 (lowest latency)
    let mut counts = HashMap::new();
    for _ in 0..100 {
        let sel = lb.select("", None).unwrap();
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    let host1_count = counts.get("host1").copied().unwrap_or(0);
    assert_eq!(
        host1_count, 100,
        "All traffic should go to lowest-latency target (host1), got {:?}",
        counts
    );
}

#[test]
fn test_least_latency_ewma_adapts_to_changes() {
    // EWMA should adapt when a target's latency changes, eventually
    // shifting traffic to the new lowest-latency target.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Phase 1: host0 is fast (1ms), host1 is slow (10ms)
    for _ in 0..10 {
        lb.record_latency(&targets[0], 1_000); // 1ms
        lb.record_latency(&targets[1], 10_000); // 10ms
    }

    // Verify host0 is preferred
    let sel = lb.select("", None).unwrap();
    assert_eq!(
        sel.target.host, "host0",
        "host0 should be preferred when it's faster"
    );

    // Phase 2: host0 becomes slow (50ms), host1 becomes fast (1ms)
    // Need enough samples for EWMA to cross over
    for _ in 0..30 {
        lb.record_latency(&targets[0], 50_000); // 50ms
        lb.record_latency(&targets[1], 1_000); // 1ms
    }

    // Now host1 should be preferred
    let sel = lb.select("", None).unwrap();
    assert_eq!(
        sel.target.host, "host1",
        "host1 should be preferred after latency shift"
    );
}

#[test]
fn test_least_latency_with_unhealthy_targets() {
    // Least-latency should respect unhealthy target filtering and select
    // the lowest-latency among healthy targets only.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // host0: 1ms (fastest), host1: 5ms, host2: 10ms
    for _ in 0..10 {
        lb.record_latency(&targets[0], 1_000);
        lb.record_latency(&targets[1], 5_000);
        lb.record_latency(&targets[2], 10_000);
    }

    // Mark host0 (fastest) as unhealthy
    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host0:8080", TEST_UPSTREAM), 0);

    // Should select host1 (next lowest latency) among healthy targets
    let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
    assert!(!sel.is_fallback);
    assert_eq!(
        sel.target.host, "host1",
        "Should prefer host1 (lowest latency among healthy), got {}",
        sel.target.host
    );
}

#[test]
fn test_least_latency_fallback_when_all_unhealthy() {
    // When all targets are unhealthy, least-latency should still select
    // a target (fallback mode) and mark it as degraded.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Record some latency data
    for _ in 0..10 {
        lb.record_latency(&targets[0], 1_000);
        lb.record_latency(&targets[1], 5_000);
    }

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host0:8080", TEST_UPSTREAM), 0);
    unhealthy.insert(format!("{}::host1:8080", TEST_UPSTREAM), 0);

    let sel = lb.select("", Some(&active_health_ctx(&unhealthy)));
    assert!(
        sel.is_some(),
        "Should return a target even when all unhealthy"
    );
    assert!(
        sel.unwrap().is_fallback,
        "Should be marked as fallback when all unhealthy"
    );
}

#[test]
fn test_least_latency_select_excluding() {
    // select_excluding should work correctly with least-latency, skipping
    // the excluded target and selecting the next-lowest-latency target.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // host0: 1ms (fastest), host1: 5ms, host2: 10ms
    for _ in 0..10 {
        lb.record_latency(&targets[0], 1_000);
        lb.record_latency(&targets[1], 5_000);
        lb.record_latency(&targets[2], 10_000);
    }

    // Exclude host0 (fastest) — should select host1 (next lowest)
    let sel = lb.select_excluding("", &targets[0], None).unwrap();
    assert_eq!(
        sel.host, "host1",
        "Should select host1 when host0 is excluded, got {}",
        sel.host
    );
}

#[test]
fn test_least_latency_record_latency_first_sample_seeds_ewma() {
    // The first latency sample should set the EWMA directly, not smooth it.
    let targets = make_targets(1);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    lb.record_latency(&targets[0], 5_000); // 5ms

    let ewma = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(ewma, 5_000, "First sample should seed EWMA directly");

    let count = lb
        .latency_sample_count
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(count, 1, "Sample count should be 1 after first record");
}

#[test]
fn test_least_latency_ewma_smoothing() {
    // Verify that the EWMA smoothing formula works correctly.
    // EWMA = 0.3 * new + 0.7 * old (using fixed-point: 300/1000 and 700/1000)
    let targets = make_targets(1);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Seed: 10000μs
    lb.record_latency(&targets[0], 10_000);

    // Second sample: 20000μs
    // Expected EWMA = (300 * 20000 + 700 * 10000) / 1000 = (6000000 + 7000000) / 1000 = 13000
    lb.record_latency(&targets[0], 20_000);

    let ewma = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(ewma, 13_000, "EWMA should be 13000μs after second sample");

    // Third sample: 10000μs
    // Expected EWMA = (300 * 10000 + 700 * 13000) / 1000 = (3000000 + 9100000) / 1000 = 12100
    lb.record_latency(&targets[0], 10_000);

    let ewma = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(ewma, 12_100, "EWMA should be 12100μs after third sample");
}

#[test]
fn test_least_latency_reset_recovered_target() {
    // When a target recovers from unhealthy, its EWMA should be reset to the
    // current minimum, giving it a fair chance at traffic.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // host0: 50ms (slow), host1: 5ms (fast)
    for _ in 0..10 {
        lb.record_latency(&targets[0], 50_000);
        lb.record_latency(&targets[1], 5_000);
    }

    // Verify host0 has a high EWMA
    let host0_ewma_before = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert!(
        host0_ewma_before > 40_000,
        "host0 EWMA should be high before reset: {}",
        host0_ewma_before
    );

    // Reset host0 (simulating recovery from unhealthy)
    lb.reset_recovered_target_latency(&targets[0]);

    // host0's EWMA should now be near host1's (the minimum)
    let host0_ewma_after = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    let host1_ewma = lb
        .latency_ewma
        .get("host1:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(
        host0_ewma_after, host1_ewma,
        "Recovered target EWMA should match the current minimum"
    );

    // Sample count should be set to the warm-up threshold (5) so the recovered
    // target immediately participates in latency-based selection without forcing
    // the entire upstream back into round-robin warm-up mode.
    let count = lb
        .latency_sample_count
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(
        count, 5,
        "Sample count should be set to warm-up threshold after recovery"
    );
}

#[test]
fn test_least_latency_cache_record_and_select() {
    // Test the LoadBalancerCache pass-through for record_latency.
    let targets = make_targets(2);
    let config = GatewayConfig {
        version: "1".to_string(),
        upstreams: vec![Upstream {
            id: "us1".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            name: Some("test".into()),
            targets: targets.clone(),
            algorithm: LoadBalancerAlgorithm::LeastLatency,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_strict: false,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            dispatch_port_override_fallback: None,
            api_spec_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..Default::default()
    };

    let cache = LoadBalancerCache::new(&config);

    // Record latencies via the cache interface
    for _ in 0..10 {
        cache.record_latency("us1", &targets[0], 10_000); // host0: 10ms
        cache.record_latency("us1", &targets[1], 2_000); // host1: 2ms
    }

    // Should prefer host1 (lower latency)
    let sel = cache.select_target("us1", "", None).unwrap();
    assert_eq!(
        sel.target.host, "host1",
        "Cache should route to lowest-latency target"
    );
}

#[test]
fn test_least_latency_no_data_falls_back_to_round_robin() {
    // When latency_ewma has been initialized but no samples recorded (all UNSET),
    // warm-up round-robin should be used.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // No latency data recorded — should use round-robin
    let mut counts = HashMap::new();
    for _ in 0..100 {
        let sel = lb.select("", None).unwrap();
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    assert_eq!(
        counts.len(),
        2,
        "Both targets should receive traffic with no latency data"
    );
    assert_eq!(
        counts.get("host0").copied().unwrap_or(0),
        50,
        "Traffic should be evenly distributed with no latency data"
    );
}

#[test]
fn test_least_latency_empty_targets() {
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &[],
        None,
    );
    assert!(lb.select("", None).is_none());
}

#[test]
fn test_least_latency_single_target() {
    // With a single target, least-latency should always return it.
    let targets = make_targets(1);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    for _ in 0..5 {
        lb.record_latency(&targets[0], 5_000);
    }

    for _ in 0..10 {
        let sel = lb.select("", None).unwrap();
        assert_eq!(sel.target.host, "host0");
    }
}

#[test]
fn test_least_latency_target_unhealthy_at_startup_then_recovers() {
    // If a target is unhealthy at startup, the other targets should complete
    // warm-up and enter latency-based selection without being blocked.
    // When the unhealthy target later recovers and joins the healthy pool,
    // it should NOT force the entire upstream back into round-robin warm-up,
    // and must not pin 100% of traffic via an unconditional warm-up bias.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Mark host2 as unhealthy from the start
    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host2:8080", TEST_UPSTREAM), 0);

    // Complete warm-up for host0 and host1 only (host2 is unhealthy, gets no traffic)
    // host0: 10ms, host1: 2ms
    for _ in 0..10 {
        lb.record_latency(&targets[0], 10_000);
        lb.record_latency(&targets[1], 2_000);
    }

    // With host2 unhealthy, latency-based selection should work for host0/host1
    let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
    assert_eq!(
        sel.target.host, "host1",
        "Should prefer host1 (lowest latency among healthy targets)"
    );

    // Now host2 recovers — remove from unhealthy set
    unhealthy.remove(&format!("{}::host2:8080", TEST_UPSTREAM));

    // host2 has 0 samples, but host0/host1 are warmed up. Bounded exploration
    // gives the late joiner a minority share; majority stays on warmed peers.
    let n = 200;
    let mut host2_hits = 0usize;
    let mut host1_hits = 0usize;
    for _ in 0..n {
        let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
        if sel.target.host == "host2" {
            host2_hits += 1;
        } else if sel.target.host == "host1" {
            host1_hits += 1;
        }
    }
    assert!(
        host2_hits > 0 && host2_hits < n / 2,
        "recovered late joiner gets bounded exploration, not a pin (hits={host2_hits})"
    );
    assert!(
        host1_hits > n / 2,
        "warmed lowest-latency target should keep the majority share"
    );

    // After host2 gets enough samples (simulate warm-up completing), the
    // algorithm should use its real EWMA for selection.
    // Give host2 a latency higher than host1 so host1 wins again.
    for _ in 0..10 {
        lb.record_latency(&targets[2], 8_000); // 8ms > host1's 2ms
    }

    let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
    assert_eq!(
        sel.target.host, "host1",
        "After host2 warms up with higher latency, host1 should be preferred again"
    );
}

#[test]
fn test_least_latency_late_joiner_does_not_disrupt_routing() {
    // When a new target joins (e.g., added via config reload or recovered from
    // unhealthy), the existing latency-based routing should continue uninterrupted.
    // The new target receives bounded exploration, not an unconditional preference.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Complete warm-up: host0: 20ms, host1: 5ms
    for _ in 0..10 {
        lb.record_latency(&targets[0], 20_000);
        lb.record_latency(&targets[1], 5_000);
    }

    // Verify latency-based selection works (host1 preferred)
    let sel = lb.select("", None).unwrap();
    assert_eq!(sel.target.host, "host1");

    // Now simulate host0's sample count being reset (as if it were a late joiner)
    // by directly setting it below the threshold
    lb.latency_sample_count
        .get("host0:8080")
        .unwrap()
        .store(0, Ordering::Relaxed);

    let n = 200;
    let mut host0_hits = 0usize;
    let mut host1_hits = 0usize;
    for _ in 0..n {
        let sel = lb.select("", None).unwrap();
        if sel.target.host == "host0" {
            host0_hits += 1;
        } else {
            host1_hits += 1;
        }
    }
    assert!(
        host0_hits > 0 && host0_hits < n / 2,
        "late joiner gets bounded exploration (hits={host0_hits})"
    );
    assert!(
        host1_hits > n / 2,
        "warmed preferred target keeps majority share"
    );

    // After host0 re-warms with its real (higher) latency, host1 should win again.
    for _ in 0..10 {
        lb.record_latency(&targets[0], 20_000); // 20ms > host1's 5ms
    }

    let sel = lb.select("", None).unwrap();
    assert_eq!(
        sel.target.host, "host1",
        "After late joiner warms up with higher latency, host1 should be preferred"
    );
}

#[test]
fn test_least_latency_unsampled_target_gets_bounded_exploration_not_pin() {
    // Mixed warm-up must explore unsampled targets without pinning all traffic.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    // Warm up host0 and host1 with low latencies (1.5ms and 2ms).
    for _ in 0..10 {
        lb.record_latency(&targets[0], 1_500); // 1.5ms
        lb.record_latency(&targets[1], 2_000); // 2ms
    }

    let n = 200;
    let mut host2_hits = 0usize;
    let mut host0_hits = 0usize;
    for _ in 0..n {
        let sel = lb.select("", None).unwrap();
        match sel.target.host.as_str() {
            "host2" => host2_hits += 1,
            "host0" => host0_hits += 1,
            _ => {}
        }
    }
    assert!(
        host2_hits > 0 && host2_hits < n,
        "unsampled host2 must receive some exploration without pinning all traffic"
    );
    assert!(
        host0_hits > host2_hits,
        "warmed lowest-EWMA target should outpace unsampled exploration"
    );

    let host0_ewma = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert!(
        host0_ewma >= 1_000,
        "host0 EWMA should be at least 1000 us, got {}",
        host0_ewma
    );
}

#[test]
fn test_least_latency_exploration_reaches_multiple_unsampled_targets() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    for _ in 0..10 {
        lb.record_latency(&targets[0], 1_500);
    }

    let mut host1_hits = 0usize;
    let mut host2_hits = 0usize;
    for _ in 0..400 {
        let selected = lb.select("", None).unwrap();
        match selected.target.host.as_str() {
            "host1" => host1_hits += 1,
            "host2" => host2_hits += 1,
            _ => {}
        }
    }
    assert!(
        host1_hits > 0 && host2_hits > 0,
        "bounded exploration must reach every unsampled peer (host1={host1_hits}, host2={host2_hits})"
    );
}

#[test]
fn test_least_latency_failed_attempts_exit_warmup_without_pinning() {
    // A never-successful peer that accumulates failure penalties must leave
    // warm-up and stop receiving exploration-driven preference.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    for _ in 0..10 {
        lb.record_latency(&targets[0], 500);
    }
    for _ in 0..5 {
        lb.record_failed_attempt(&targets[1]);
    }

    let mut host1_hits = 0usize;
    for _ in 0..100 {
        let sel = lb.select("", None).unwrap();
        if sel.target.host == "host1" {
            host1_hits += 1;
        }
    }
    assert_eq!(
        host1_hits, 0,
        "failure-penalized target must not win steady-state selection"
    );
}

#[test]
fn test_least_latency_record_for_nonexistent_target() {
    // Recording latency for a target not in the balancer should be a no-op.
    let targets = make_targets(1);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    let phantom = UpstreamTarget {
        host: "nonexistent".into(),
        port: 9999,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    };

    // Should not panic or error
    lb.record_latency(&phantom, 5_000);

    // Original target should still work fine
    lb.record_latency(&targets[0], 1_000);
    let ewma = lb
        .latency_ewma
        .get("host0:8080")
        .unwrap()
        .load(Ordering::Relaxed);
    assert_eq!(ewma, 1_000);
}

// ─── HashOnStrategy Tests ───────────────────────────────────────────────────

use ferrum_edge::load_balancer::HashOnStrategy;

#[test]
fn test_hash_on_strategy_parse_defaults_to_ip() {
    assert_eq!(HashOnStrategy::parse(None), HashOnStrategy::Ip);
    assert_eq!(HashOnStrategy::parse(Some("")), HashOnStrategy::Ip);
    assert_eq!(HashOnStrategy::parse(Some("ip")), HashOnStrategy::Ip);
    assert_eq!(HashOnStrategy::parse(Some("unknown")), HashOnStrategy::Ip);
}

#[test]
fn test_hash_on_strategy_parse_header() {
    assert_eq!(
        HashOnStrategy::parse(Some("header:X-User-Id")),
        HashOnStrategy::Header("x-user-id".to_string())
    );
    assert_eq!(
        HashOnStrategy::parse(Some("header:x-session")),
        HashOnStrategy::Header("x-session".to_string())
    );
    // Empty header name falls back to IP
    assert_eq!(HashOnStrategy::parse(Some("header:")), HashOnStrategy::Ip);
    assert_eq!(HashOnStrategy::parse(Some("header:  ")), HashOnStrategy::Ip);
}

#[test]
fn test_hash_on_strategy_parse_cookie() {
    assert_eq!(
        HashOnStrategy::parse(Some("cookie:session")),
        HashOnStrategy::Cookie("session".to_string())
    );
    assert_eq!(
        HashOnStrategy::parse(Some("cookie:srv_id")),
        HashOnStrategy::Cookie("srv_id".to_string())
    );
    // Empty cookie name falls back to IP
    assert_eq!(HashOnStrategy::parse(Some("cookie:")), HashOnStrategy::Ip);
}

#[test]
fn test_hash_on_strategy_stored_in_load_balancer() {
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        Some("header:x-tenant".to_string()),
    );
    assert_eq!(
        lb.hash_on_strategy,
        HashOnStrategy::Header("x-tenant".to_string())
    );
}

#[test]
fn test_consistent_hash_different_keys_different_targets() {
    // With consistent hashing and enough targets, different hash keys should
    // (with high probability) map to different targets.
    let targets = make_targets(10);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        Some("header:x-user".to_string()),
    );

    let mut selected = std::collections::HashSet::new();
    for i in 0..50 {
        let key = format!("user-{}", i);
        let sel = lb.select(&key, None).unwrap();
        selected.insert(sel.target.host.clone());
    }
    // With 10 targets and 50 diverse keys, we should hit multiple different targets
    assert!(
        selected.len() > 1,
        "Expected multiple different targets, got {:?}",
        selected
    );
}

#[test]
fn test_consistent_hash_sticky_same_key_same_target() {
    let targets = make_targets(5);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        None,
    );

    // Same key should always map to the same target
    let first = lb.select("sticky-user-123", None).unwrap();
    for _ in 0..100 {
        let sel = lb.select("sticky-user-123", None).unwrap();
        assert_eq!(sel.target.host, first.target.host);
        assert_eq!(sel.target.port, first.target.port);
    }
}

#[test]
fn test_load_balancer_cache_get_hash_on_strategy() {
    let config = GatewayConfig {
        version: "1".to_string(),
        upstreams: vec![Upstream {
            id: "us1".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            name: Some("test".into()),
            targets: make_targets(2),
            algorithm: LoadBalancerAlgorithm::ConsistentHashing,
            hash_on: Some("cookie:srv".to_string()),
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_strict: false,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            dispatch_port_override_fallback: None,
            api_spec_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..Default::default()
    };

    let cache = LoadBalancerCache::new(&config);
    assert_eq!(
        cache.get_hash_on_strategy("us1"),
        HashOnStrategy::Cookie("srv".to_string())
    );
    // Non-existent upstream returns Ip default
    assert_eq!(
        cache.get_hash_on_strategy("nonexistent"),
        HashOnStrategy::Ip
    );
}

#[test]
fn test_load_balancer_cache_get_subset_hash_on_strategy() {
    use ferrum_edge::config::types::{SubsetDefinition, SubsetTrafficPolicy};

    let mut upstream = make_upstream("us-subset", make_targets(2));
    upstream.algorithm = LoadBalancerAlgorithm::ConsistentHashing;
    upstream.hash_on = Some("header:x-parent".to_string());
    upstream.subsets = Some(vec![
        SubsetDefinition {
            name: "stable".into(),
            labels: HashMap::from([("version".into(), "v1".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
                hash_on: None,
                tls: None,
                connect_timeout_ms: None,
                passive_health_check: None,
            }),
        },
        SubsetDefinition {
            name: "canary".into(),
            labels: HashMap::from([("version".into(), "v2".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
                hash_on: Some("cookie:canary-session".into()),
                tls: None,
                connect_timeout_ms: None,
                passive_health_check: None,
            }),
        },
    ]);

    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_selection_from(
            &snapshot,
            "us-subset",
            None,
            Some("stable"),
        ),
        HashOnStrategy::Header("x-parent".to_string())
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_selection_from(
            &snapshot,
            "us-subset",
            None,
            Some("canary"),
        ),
        HashOnStrategy::Cookie("canary-session".to_string())
    );
}

// ─── LoadBalancerCache apply_delta Tests ─────────────────────────────────────

fn make_upstream(id: &str, targets: Vec<UpstreamTarget>) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("upstream-{}", id)),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn port_override_lanes_use_target_policy_port_not_dial_port() {
    let mut upstream = make_upstream(
        "u1",
        vec![
            UpstreamTarget {
                host: "10.0.0.1".into(),
                port: 8080,
                service_port_policy_key: Some(80),
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
            UpstreamTarget {
                host: "10.0.0.1".into(),
                port: 8080,
                service_port_policy_key: Some(81),
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
        ],
    );
    upstream.port_overrides = HashMap::from([
        (
            80,
            UpstreamPortOverride {
                algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
                ..UpstreamPortOverride::default()
            },
        ),
        (
            81,
            UpstreamPortOverride {
                algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
                ..UpstreamPortOverride::default()
            },
        ),
    ]);
    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();

    assert!(LoadBalancerCache::has_port_override_state_from(
        &snapshot, "u1", 80
    ));
    assert!(LoadBalancerCache::has_port_override_state_from(
        &snapshot, "u1", 81
    ));

    let p80 =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "", 80, None).unwrap();
    let p81 =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "", 81, None).unwrap();

    assert_eq!(p80.target.port, 8080);
    assert_eq!(p81.target.port, 8080);
    assert_eq!(p80.target.service_port_policy_key, Some(80));
    assert_eq!(p81.target.service_port_policy_key, Some(81));
}

#[test]
fn port_override_retry_exclusion_uses_policy_port_identity() {
    let mut upstream = make_upstream(
        "u1",
        vec![
            UpstreamTarget {
                host: "10.0.0.1".into(),
                port: 8080,
                service_port_policy_key: Some(80),
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
            UpstreamTarget {
                host: "10.0.0.1".into(),
                port: 8080,
                service_port_policy_key: Some(81),
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
        ],
    );
    upstream.port_overrides = HashMap::from([
        (
            80,
            UpstreamPortOverride {
                algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
                ..UpstreamPortOverride::default()
            },
        ),
        (
            81,
            UpstreamPortOverride {
                algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
                ..UpstreamPortOverride::default()
            },
        ),
    ]);
    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();
    let failed = UpstreamTarget {
        host: "10.0.0.1".into(),
        port: 8080,
        service_port_policy_key: Some(81),
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    };

    assert!(
        LoadBalancerCache::select_next_target_for_port_from(
            &snapshot, "u1", "retry", 81, &failed, None,
        )
        .is_none(),
        "the failed target is the only target in policy lane 81"
    );
    let other_lane = LoadBalancerCache::select_next_target_for_port_from(
        &snapshot, "u1", "retry", 80, &failed, None,
    )
    .expect("the sibling policy lane remains selectable");
    assert_eq!(other_lane.port, 8080);
    assert_eq!(other_lane.service_port_policy_key, Some(80));
}

#[test]
fn retry_exclusion_returns_none_when_only_alternate_is_unhealthy() {
    let targets = make_targets(2);
    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![make_upstream("u1", targets.clone())],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();
    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(target_key("u1", &targets[1]), 1);

    let retry = LoadBalancerCache::select_next_target_from(
        &snapshot,
        "u1",
        "retry",
        &targets[0],
        Some(&active_health_ctx(&unhealthy)),
    );

    assert!(
        retry.is_none(),
        "retry selection must not synthesize an unhealthy alternate fallback"
    );
}

#[test]
fn port_retry_exclusion_returns_none_when_only_alternate_is_unhealthy() {
    let targets = make_targets(2);
    let mut upstream = make_upstream("u1", targets.clone());
    upstream.port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..UpstreamPortOverride::default()
        },
    );
    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();
    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(target_key("u1", &targets[1]), 1);

    let retry = LoadBalancerCache::select_next_target_for_port_from(
        &snapshot,
        "u1",
        "retry",
        8080,
        &targets[0],
        Some(&active_health_ctx(&unhealthy)),
    );

    assert!(
        retry.is_none(),
        "port-scoped retry selection must not synthesize an unhealthy alternate fallback"
    );
}

#[test]
fn test_apply_delta_add_upstream() {
    let config = GatewayConfig::default();
    let cache = LoadBalancerCache::new(&config);

    // Initially no upstreams
    assert!(cache.select_target("u1", "", None).is_none());

    let added = vec![make_upstream("u1", make_targets(2))];
    let new_config = GatewayConfig {
        upstreams: added.clone(),
        ..Default::default()
    };
    cache.apply_delta(&new_config, &added, &[], &[]);

    // Now u1 should be available
    let sel = cache.select_target("u1", "", None);
    assert!(sel.is_some(), "Upstream u1 should be selectable after add");
}

#[test]
fn test_apply_delta_remove_upstream() {
    let u1 = make_upstream("u1", make_targets(2));
    let config = GatewayConfig {
        upstreams: vec![u1],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);

    // u1 exists
    assert!(cache.select_target("u1", "", None).is_some());

    let new_config = GatewayConfig::default();
    cache.apply_delta(&new_config, &[], &["u1".to_string()], &[]);

    // u1 should be gone
    assert!(
        cache.select_target("u1", "", None).is_none(),
        "Upstream u1 should be gone after removal"
    );
}

#[test]
fn test_apply_delta_modify_upstream_targets() {
    let u1 = make_upstream("u1", make_targets(2));
    let config = GatewayConfig {
        upstreams: vec![u1],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);

    // Modify u1 to have a single target on port 9999
    let new_target = UpstreamTarget {
        host: "new-backend".into(),
        port: 9999,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    };
    let modified_u1 = make_upstream("u1", vec![new_target]);
    let new_config = GatewayConfig {
        upstreams: vec![modified_u1.clone()],
        ..Default::default()
    };
    cache.apply_delta(&new_config, &[], &[], &[modified_u1]);

    let sel = cache.select_target("u1", "", None).unwrap();
    assert_eq!(sel.target.host, "new-backend");
    assert_eq!(sel.target.port, 9999);
}

#[test]
fn test_apply_delta_mixed_add_remove_modify() {
    let u1 = make_upstream("u1", make_targets(2));
    let u2 = make_upstream("u2", make_targets(1));
    let config = GatewayConfig {
        upstreams: vec![u1, u2],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);

    // Verify both exist
    assert!(cache.select_target("u1", "", None).is_some());
    assert!(cache.select_target("u2", "", None).is_some());

    // Add u3, remove u1, modify u2
    let u3 = make_upstream("u3", make_targets(3));
    let modified_u2 = Upstream {
        algorithm: LoadBalancerAlgorithm::Random,
        ..make_upstream("u2", make_targets(1))
    };
    let new_config = GatewayConfig {
        upstreams: vec![modified_u2.clone(), u3.clone()],
        ..Default::default()
    };
    cache.apply_delta(&new_config, &[u3], &["u1".to_string()], &[modified_u2]);

    assert!(
        cache.select_target("u1", "", None).is_none(),
        "u1 should be removed"
    );
    assert!(
        cache.select_target("u2", "", None).is_some(),
        "u2 should still exist (modified)"
    );
    assert!(
        cache.select_target("u3", "", None).is_some(),
        "u3 should be added"
    );
}

#[test]
fn test_apply_delta_empty_is_noop() {
    let u1 = make_upstream("u1", make_targets(2));
    let config = GatewayConfig {
        upstreams: vec![u1],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);

    // Empty delta should be a no-op
    cache.apply_delta(&config, &[], &[], &[]);

    assert!(
        cache.select_target("u1", "", None).is_some(),
        "u1 should still exist after empty delta"
    );
}

#[test]
fn test_apply_delta_preserves_unaffected_upstreams() {
    let u1 = make_upstream("u1", make_targets(2));
    let u2 = make_upstream("u2", make_targets(3));
    let config = GatewayConfig {
        upstreams: vec![u1, u2],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);

    // Only add u3 — u1 and u2 should be preserved
    let u3 = make_upstream("u3", make_targets(1));
    let new_config = GatewayConfig {
        upstreams: vec![
            make_upstream("u1", make_targets(2)),
            make_upstream("u2", make_targets(3)),
            u3.clone(),
        ],
        ..Default::default()
    };
    cache.apply_delta(&new_config, &[u3], &[], &[]);

    assert!(cache.select_target("u1", "", None).is_some());
    assert!(cache.select_target("u2", "", None).is_some());
    assert!(cache.select_target("u3", "", None).is_some());
}

// ─── Random Algorithm Tests ─────────────────────────────────────────────────

#[test]
fn test_random_selects_from_all_targets() {
    let targets = make_targets(5);
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::Random, &targets, None);

    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        let sel = lb.select("", None).unwrap();
        assert!(!sel.is_fallback);
        seen.insert(sel.target.host.clone());
    }
    // With 500 selections across 5 targets, we should hit all of them
    assert_eq!(
        seen.len(),
        5,
        "Random should distribute across all targets, got {:?}",
        seen
    );
}

#[test]
fn test_random_filters_unhealthy() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::Random, &targets, None);

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host0:8080", TEST_UPSTREAM), 0);

    for _ in 0..100 {
        let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
        assert_ne!(
            sel.target.host, "host0",
            "Unhealthy target should be skipped"
        );
    }
}

#[test]
fn test_random_all_unhealthy_falls_back() {
    let targets = make_targets(2);
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::Random, &targets, None);

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(format!("{}::host0:8080", TEST_UPSTREAM), 0);
    unhealthy.insert(format!("{}::host1:8080", TEST_UPSTREAM), 0);

    let sel = lb.select("", Some(&active_health_ctx(&unhealthy)));
    assert!(sel.is_some(), "Should return a fallback target");
    assert!(sel.unwrap().is_fallback, "Should be marked as fallback");
}

#[test]
fn test_random_empty_targets() {
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::Random, &[], None);
    assert!(lb.select("", None).is_none());
}

#[test]
fn test_random_single_target() {
    let targets = make_targets(1);
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::Random, &targets, None);

    for _ in 0..50 {
        let sel = lb.select("", None).unwrap();
        assert_eq!(sel.target.host, "host0");
    }
}

// ─── WRR Weight=0 Tests ─────────────────────────────────────────────────────

#[test]
fn test_wrr_all_zero_weights_falls_back_to_round_robin() {
    let targets = vec![
        UpstreamTarget {
            host: "a".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 0,
            tags: HashMap::new(),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "b".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 0,
            tags: HashMap::new(),
            locality: None,
            path: None,
        },
    ];
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let mut counts = HashMap::new();
    for _ in 0..100 {
        let sel = lb.select("", None).unwrap();
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    // With all-zero weights, should round-robin evenly
    assert_eq!(counts.len(), 2);
    assert_eq!(counts.get("a").copied().unwrap_or(0), 50);
    assert_eq!(counts.get("b").copied().unwrap_or(0), 50);
}

#[test]
fn test_wrr_mixed_zero_and_nonzero_weights() {
    let targets = vec![
        UpstreamTarget {
            host: "weighted".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 10,
            tags: HashMap::new(),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "zero".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 0,
            tags: HashMap::new(),
            locality: None,
            path: None,
        },
    ];
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let mut counts = HashMap::new();
    for _ in 0..100 {
        let sel = lb.select("", None).unwrap();
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }

    // Weight-0 target should get zero or negligible traffic
    let weighted_count = counts.get("weighted").copied().unwrap_or(0);
    assert_eq!(
        weighted_count,
        100,
        "All traffic should go to the weighted target, got weighted={} zero={}",
        weighted_count,
        counts.get("zero").copied().unwrap_or(0)
    );
}

// ─── select_excluding for Multiple Algorithms ───────────────────────────────

#[test]
fn test_select_excluding_consistent_hash() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        None,
    );

    let exclude = targets[0].clone();
    for _ in 0..50 {
        let t = lb.select_excluding("user-1", &exclude, None).unwrap();
        assert_ne!(t.host, "host0", "Excluded target should never be returned");
    }
}

#[test]
fn test_select_excluding_least_connections() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastConnections,
        &targets,
        None,
    );

    let exclude = targets[1].clone();
    for _ in 0..50 {
        let t = lb.select_excluding("", &exclude, None).unwrap();
        assert_ne!(t.host, "host1");
    }
}

#[test]
fn test_select_excluding_wrr() {
    let targets = make_weighted_targets();
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    // Exclude "heavy" — should only return "light"
    let exclude = targets[0].clone();
    for _ in 0..20 {
        let t = lb.select_excluding("", &exclude, None).unwrap();
        assert_eq!(t.host, "light");
    }
}

#[test]
fn test_select_excluding_random() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(TEST_UPSTREAM, LoadBalancerAlgorithm::Random, &targets, None);

    let exclude = targets[2].clone();
    for _ in 0..100 {
        let t = lb.select_excluding("", &exclude, None).unwrap();
        assert_ne!(t.host, "host2");
    }
}

#[test]
fn test_select_excluding_only_target_returns_none() {
    let targets = make_targets(1);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let result = lb.select_excluding("", &targets[0], None);
    assert!(
        result.is_none(),
        "Excluding the only target should return None"
    );
}

// ─── Consistent Hashing with Unhealthy Targets ─────────────────────────────

#[test]
fn test_consistent_hash_with_unhealthy_target() {
    let targets = make_targets(5);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::ConsistentHashing,
        &targets,
        None,
    );

    // Get initial selection for a key
    let initial = lb.select("test-key", None).unwrap();

    // Mark a different target as unhealthy
    let unhealthy: DashMap<String, u64> = DashMap::new();
    let unhealthy_host = if initial.target.host == "host0" {
        "host1"
    } else {
        "host0"
    };
    unhealthy.insert(format!("{}::{}:8080", TEST_UPSTREAM, unhealthy_host), 0);

    // Same key should still map to same target (healthy target unchanged)
    let after = lb
        .select("test-key", Some(&active_health_ctx(&unhealthy)))
        .unwrap();
    assert_eq!(
        initial.target.host, after.target.host,
        "Consistent hash should be stable when selected target is still healthy"
    );
}

// ─── Passive Health Context Tests ───────────────────────────────────────────

#[test]
fn test_passive_health_filters_targets() {
    use ferrum_edge::config::types::PassiveHealthCheck;
    use ferrum_edge::health_check::HealthChecker;

    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    // Use HealthChecker to create passive state via report_response
    let checker = HealthChecker::new();
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Mark host1 as passively unhealthy
    checker.report_response(
        "test-proxy",
        "test-upstream",
        &targets[1],
        500,
        false,
        Some(&config),
    );

    let active: DashMap<String, u64> = DashMap::new();
    let proxy_passive = checker.passive_health.get("test-proxy").map(|e| e.clone());

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive,
        max_ejection_percent: None,
    };

    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select("", Some(&ctx)).unwrap();
        seen.insert(sel.target.host.clone());
    }

    assert!(
        !seen.contains("host1"),
        "Passively unhealthy target should be filtered"
    );
    assert!(seen.contains("host0"));
    assert!(seen.contains("host2"));
}

// ─── Ejection Cap Tests ──────────────────────────────────────────────────────

#[test]
fn ejection_cap_readmits_when_too_many_passively_ejected() {
    use ferrum_edge::config::types::PassiveHealthCheck;
    use ferrum_edge::health_check::HealthChecker;

    // 4 targets, max_ejection_percent = 50 → at most 2 ejected
    let targets = make_targets(4);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let checker = HealthChecker::new();
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Eject 3 targets (host0, host1, host2) — exceeds 50% cap (max 2)
    checker.report_response(
        "test-proxy",
        "test-upstream",
        &targets[0],
        500,
        false,
        Some(&config),
    );
    checker.report_response(
        "test-proxy",
        "test-upstream",
        &targets[1],
        500,
        false,
        Some(&config),
    );
    checker.report_response(
        "test-proxy",
        "test-upstream",
        &targets[2],
        500,
        false,
        Some(&config),
    );
    let proxy_passive = checker.passive_health.get("test-proxy").map(|e| e.clone());
    let proxy_passive = proxy_passive.expect("passive state should be created");
    proxy_passive.unhealthy.insert(
        target_host_port_key(&targets[0]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 100,
            recover_at_ms: 100,
            auto_recover: false,
            upstream_id: TEST_UPSTREAM.to_string(),
            host: targets[0].host.clone(),
            port: targets[0].port,
        },
    );
    proxy_passive.unhealthy.insert(
        target_host_port_key(&targets[1]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 200,
            recover_at_ms: 200,
            auto_recover: false,
            upstream_id: TEST_UPSTREAM.to_string(),
            host: targets[1].host.clone(),
            port: targets[1].port,
        },
    );
    proxy_passive.unhealthy.insert(
        target_host_port_key(&targets[2]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 300,
            recover_at_ms: 300,
            auto_recover: false,
            upstream_id: TEST_UPSTREAM.to_string(),
            host: targets[2].host.clone(),
            port: targets[2].port,
        },
    );

    let active: DashMap<String, u64> = DashMap::new();

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: Some(proxy_passive),
        max_ejection_percent: Some(50),
    };

    // With cap=50%, only 2 of 4 targets can be ejected.
    // The earliest ejection (host0) should be re-admitted first.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let sel = lb.select("", Some(&ctx)).unwrap();
        seen.insert(sel.target.host.clone());
    }

    assert_eq!(
        seen,
        std::collections::HashSet::from(["host0".to_string(), "host3".to_string()]),
        "host0 should be re-admitted and host3 was never ejected"
    );
    assert!(
        seen.contains("host3"),
        "host3 was never ejected and should be available"
    );
}

#[test]
fn ejection_cap_zero_percent_readmits_all() {
    use ferrum_edge::config::types::PassiveHealthCheck;
    use ferrum_edge::health_check::HealthChecker;

    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    let checker = HealthChecker::new();
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };

    // Eject all 3 targets
    for t in &targets {
        checker.report_response("test-proxy", "test-upstream", t, 500, false, Some(&config));
    }

    let active: DashMap<String, u64> = DashMap::new();
    let proxy_passive = checker.passive_health.get("test-proxy").map(|e| e.clone());

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive,
        max_ejection_percent: Some(0), // 0% cap → no ejections allowed
    };

    // All targets should be re-admitted
    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select("", Some(&ctx)).unwrap();
        assert!(
            !sel.is_fallback,
            "Should not be fallback when cap re-admits all"
        );
        seen.insert(sel.target.host.clone());
    }

    assert_eq!(
        seen.len(),
        3,
        "All 3 targets should be available with 0% ejection cap"
    );
}

#[test]
fn ejection_cap_does_not_affect_active_health_ejections() {
    use ferrum_edge::config::types::PassiveHealthCheck;
    use ferrum_edge::health_check::HealthChecker;

    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    // Actively eject host0 (genuine unreachable — not subject to cap)
    let active: DashMap<String, u64> = DashMap::new();
    let key = ferrum_edge::load_balancer::target_key(TEST_UPSTREAM, &targets[0]);
    active.insert(key, 1);

    // Passively eject host1
    let checker = HealthChecker::new();
    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };
    checker.report_response(
        "test-proxy",
        "test-upstream",
        &targets[1],
        500,
        false,
        Some(&config),
    );

    let proxy_passive = checker.passive_health.get("test-proxy").map(|e| e.clone());

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive,
        max_ejection_percent: Some(100), // 100% cap for passive → host1 stays ejected
    };

    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select("", Some(&ctx)).unwrap();
        seen.insert(sel.target.host.clone());
    }

    // host0 actively ejected, host1 passively ejected
    assert!(
        !seen.contains("host0"),
        "Actively ejected target should remain ejected regardless of cap"
    );
    assert!(
        !seen.contains("host1"),
        "Passively ejected target within cap should stay ejected"
    );
    assert!(seen.contains("host2"));
}

/// PASSTHROUGH (loadBalancer.simple=PASSTHROUGH) must size the passive
/// `max_ejection_percent` cap against the SAME candidate pool the orig-dst
/// match is scoped to — NOT the whole upstream. Otherwise ejections OUTSIDE
/// the selected subset/port pool dilute the cap and can readmit (or keep
/// ejected) the matched in-pool orig-dst target against the outlier policy.
///
/// Regression for the F5.7 finding: the match was subset-scoped but the health
/// computation used the whole upstream. Here the in-subset orig-dst target is
/// passively ejected; the assertion is that out-of-pool ejections do NOT change
/// whether it is dialed. With a 1-target subset and a 25% cap, the in-pool
/// target stays ejected (`ceil(1*25/100)=1`, one ejection within cap → 0
/// readmit) regardless of how many out-of-pool targets are ejected. Under the
/// old whole-upstream cap (`ceil(4*25/100)=1`), ejecting the 3 out-of-pool
/// targets too (4 > 1) would readmit the earliest — the matched in-pool target
/// — flipping the result to a dial.
#[test]
fn passthrough_ejection_cap_scoped_to_candidate_pool_not_whole_upstream() {
    use ferrum_edge::config::types::{PassiveHealthCheck, SubsetDefinition};
    use ferrum_edge::health_check::HealthChecker;

    // idx0 is the only v1 (in-pool) target; idx1..=3 are v2 (out-of-pool).
    // IP-literal hosts so orig-dst matching can fire.
    let mut t0 = UpstreamTarget {
        host: "10.0.0.1".into(),
        port: 8080,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    };
    t0.tags.insert("version".into(), "v1".into());
    let targets = {
        let mut v = vec![t0];
        for i in 2..=4u8 {
            let mut t = UpstreamTarget {
                host: format!("10.0.0.{i}"),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            };
            t.tags.insert("version".into(), "v2".into());
            v.push(t);
        }
        v
    };
    let subsets = vec![
        SubsetDefinition {
            name: "v1".into(),
            labels: HashMap::from([("version".into(), "v1".into())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "v2".into(),
            labels: HashMap::from([("version".into(), "v2".into())]),
            traffic_policy: None,
        },
    ];
    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::Passthrough,
        &targets,
        None,
        Some(&subsets),
    );

    let config = PassiveHealthCheck {
        unhealthy_status_codes: vec![500],
        unhealthy_threshold: 1,
        unhealthy_window_seconds: 60,
        healthy_after_seconds: 30,
        max_ejection_percent: None,
        gateway_error_codes: None,
        split_external_local_origin_errors: None,
    };
    let active: DashMap<String, u64> = DashMap::new();
    let in_pool: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();

    // Helper: passthrough-select the in-subset orig-dst with the given passive
    // ejections (host:port → ejected_at_ms) and a 25% cap scoped to subset v1.
    let dial_decision = |ejected: &[(&UpstreamTarget, u64)]| -> bool {
        let checker = HealthChecker::new();
        for (t, _) in ejected {
            checker.report_response("test-proxy", "test-upstream", t, 500, false, Some(&config));
        }
        let proxy_passive = checker
            .passive_health
            .get("test-proxy")
            .map(|e| e.clone())
            .expect("passive state should be created");
        // Deterministic ejection timestamps (earliest = the in-pool target).
        for (t, ts) in ejected {
            proxy_passive.unhealthy.insert(
                target_host_port_key(t),
                ferrum_edge::health_check::PassiveEjection {
                    ejected_at_ms: *ts,
                    recover_at_ms: *ts,
                    auto_recover: false,
                    upstream_id: "test-upstream".to_string(),
                    host: t.host.clone(),
                    port: t.port,
                },
            );
        }
        let ctx = HealthContext {
            active_unhealthy: &active,
            proxy_passive: Some(proxy_passive),
            max_ejection_percent: Some(25),
        };
        lb.select_passthrough(in_pool, None, Some("v1"), Some(&ctx))
            .is_some()
    };

    // Only the in-pool target ejected (earliest ts): with the pool-scoped cap it
    // stays ejected → not dialed.
    let only_in_pool = dial_decision(&[(&targets[0], 100)]);
    // Additionally eject all 3 out-of-pool targets (later ts). Pool-scoped, the
    // v1 pool is unchanged (still just the ejected in-pool target) → identical.
    let plus_out_of_pool = dial_decision(&[
        (&targets[0], 100),
        (&targets[1], 200),
        (&targets[2], 300),
        (&targets[3], 400),
    ]);

    assert!(
        !only_in_pool,
        "in-pool orig-dst ejected within the subset cap must not be dialed"
    );
    assert_eq!(
        only_in_pool, plus_out_of_pool,
        "ejections OUTSIDE the candidate pool must NOT change whether the \
         in-pool orig-dst target is dialed (cap denominator is the candidate \
         pool, not the whole upstream)"
    );
}

// ─── Subset Routing Tests ────────────────────────────────────────────────────

fn make_tagged_targets() -> Vec<UpstreamTarget> {
    vec![
        UpstreamTarget {
            host: "v1-a".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::from([("version".to_string(), "v1".to_string())]),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "v1-b".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::from([("version".to_string(), "v1".to_string())]),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "v2-a".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::from([("version".to_string(), "v2".to_string())]),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "v2-b".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::from([
                ("version".to_string(), "v2".to_string()),
                ("region".to_string(), "us-east".to_string()),
            ]),
            locality: None,
            path: None,
        },
    ]
}

#[test]
fn subset_routing_selects_only_matching_targets() {
    use ferrum_edge::config::types::SubsetDefinition;

    let targets = make_tagged_targets();
    let subsets = vec![
        SubsetDefinition {
            name: "stable".into(),
            labels: HashMap::from([("version".into(), "v1".into())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "canary".into(),
            labels: HashMap::from([("version".into(), "v2".into())]),
            traffic_policy: None,
        },
    ];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    // Select from "stable" subset — should only return v1-a and v1-b
    let mut seen_stable = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select_from_subset("", "stable", None).unwrap();
        seen_stable.insert(sel.target.host.clone());
    }
    assert_eq!(seen_stable.len(), 2);
    assert!(seen_stable.contains("v1-a"));
    assert!(seen_stable.contains("v1-b"));

    // Select from "canary" subset — should only return v2-a and v2-b
    let mut seen_canary = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select_from_subset("", "canary", None).unwrap();
        seen_canary.insert(sel.target.host.clone());
    }
    assert_eq!(seen_canary.len(), 2);
    assert!(seen_canary.contains("v2-a"));
    assert!(seen_canary.contains("v2-b"));
}

#[test]
fn subset_traffic_policy_overrides_parent_algorithm() {
    use ferrum_edge::config::types::{SubsetDefinition, SubsetTrafficPolicy};

    let targets = make_tagged_targets();
    let subsets = vec![SubsetDefinition {
        name: "canary".into(),
        labels: HashMap::from([("version".into(), "v2".into())]),
        traffic_policy: Some(SubsetTrafficPolicy {
            load_balancer_algorithm: Some(LoadBalancerAlgorithm::LeastConnections),
            hash_on: None,
            tls: None,
            connect_timeout_ms: None,
            passive_health_check: None,
        }),
    }];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    lb.active_connections
        .entry(target_host_port_key(&targets[2]))
        .or_insert_with(|| AtomicI64::new(0))
        .store(10, Ordering::Relaxed);

    for _ in 0..20 {
        let sel = lb.select_from_subset("", "canary", None).unwrap();
        assert_eq!(
            sel.target.host, "v2-b",
            "subset traffic policy should use least-connections instead of parent round-robin"
        );
    }
}

#[test]
fn subset_routing_multi_label_selector() {
    use ferrum_edge::config::types::SubsetDefinition;

    let targets = make_tagged_targets();
    let subsets = vec![SubsetDefinition {
        name: "v2-east".into(),
        labels: HashMap::from([
            ("version".into(), "v2".into()),
            ("region".into(), "us-east".into()),
        ]),
        traffic_policy: None,
    }];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    // Only v2-b has both version=v2 and region=us-east
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let sel = lb.select_from_subset("", "v2-east", None).unwrap();
        seen.insert(sel.target.host.clone());
    }
    assert_eq!(seen.len(), 1);
    assert!(seen.contains("v2-b"));
}

#[test]
fn subset_routing_undefined_subset_returns_none() {
    use ferrum_edge::config::types::SubsetDefinition;

    let targets = make_tagged_targets();
    let subsets = vec![SubsetDefinition {
        name: "stable".into(),
        labels: HashMap::from([("version".into(), "v1".into())]),
        traffic_policy: None,
    }];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    assert!(
        lb.select_from_subset("", "nonexistent", None).is_none(),
        "Undefined subset must not silently route to the full upstream"
    );
}

#[test]
fn subset_routing_intersects_with_health() {
    use ferrum_edge::config::types::SubsetDefinition;

    let targets = make_tagged_targets();
    let subsets = vec![SubsetDefinition {
        name: "stable".into(),
        labels: HashMap::from([("version".into(), "v1".into())]),
        traffic_policy: None,
    }];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    // Mark v1-a as actively unhealthy
    let active: DashMap<String, u64> = DashMap::new();
    let key = target_host_port_key(&targets[0]); // v1-a:8080
    let full_key = format!("{}::{}", TEST_UPSTREAM, key);
    active.insert(full_key, 1);

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    // "stable" subset has v1-a and v1-b, but v1-a is unhealthy
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let sel = lb.select_from_subset("", "stable", Some(&ctx)).unwrap();
        seen.insert(sel.target.host.clone());
    }
    assert_eq!(seen.len(), 1);
    assert!(
        seen.contains("v1-b"),
        "Only healthy subset targets should be selected"
    );
}

#[test]
fn subset_routing_all_unhealthy_returns_none() {
    use ferrum_edge::config::types::SubsetDefinition;

    let targets = make_tagged_targets();
    let subsets = vec![SubsetDefinition {
        name: "stable".into(),
        labels: HashMap::from([("version".into(), "v1".into())]),
        traffic_policy: None,
    }];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    // Mark both v1-a and v1-b as actively unhealthy
    let active: DashMap<String, u64> = DashMap::new();
    for t in &targets[0..2] {
        let key = format!("{}::{}", TEST_UPSTREAM, target_host_port_key(t));
        active.insert(key, 1);
    }

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    assert!(
        lb.select_from_subset("", "stable", Some(&ctx)).is_none(),
        "All subset targets unhealthy must not route to the parent upstream"
    );
}

#[test]
fn subset_retry_does_not_fall_back_to_parent_upstream() {
    use ferrum_edge::config::types::SubsetDefinition;

    let targets = make_tagged_targets();
    let subsets = vec![SubsetDefinition {
        name: "v2-east".into(),
        labels: HashMap::from([
            ("version".into(), "v2".into()),
            ("region".into(), "us-east".into()),
        ]),
        traffic_policy: None,
    }];

    let lb = LoadBalancer::with_subsets(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
        Some(&subsets),
    );

    let selected = lb
        .select_from_subset("", "v2-east", None)
        .expect("single subset target exists");
    assert_eq!(selected.target.host, "v2-b");

    assert!(
        lb.select_excluding_from_subset("", "v2-east", &selected.target, None)
            .is_none(),
        "Retry must stay inside the configured subset instead of falling back to parent"
    );
}

#[test]
fn subset_no_subsets_defined_select_from_subset_returns_none() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    );

    assert!(
        lb.select_from_subset("", "anything", None).is_none(),
        "Unknown subset without definitions must not route to the full upstream"
    );
}

#[test]
fn apply_delta_preserves_subset_indices() {
    use ferrum_edge::config::types::SubsetDefinition;

    let mut upstream = make_upstream("u1", make_tagged_targets());
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "canary".into(),
        labels: HashMap::from([("version".into(), "v2".into())]),
        traffic_policy: None,
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream.clone()],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);

    let mut modified = upstream.clone();
    modified.name = Some("renamed".into());
    let new_config = GatewayConfig {
        upstreams: vec![modified.clone()],
        ..Default::default()
    };
    cache.apply_delta(&new_config, &[], &[], &[modified]);

    let snapshot = cache.load();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let sel = LoadBalancerCache::select_target_subset_from(&snapshot, "u1", "", "canary", None)
            .unwrap();
        seen.insert(sel.target.host.clone());
    }
    assert_eq!(
        seen,
        std::collections::HashSet::from(["v2-a".to_string(), "v2-b".to_string()])
    );
}

#[test]
fn update_targets_preserves_existing_subsets() {
    use ferrum_edge::config::types::SubsetDefinition;

    let mut upstream = make_upstream("u1", make_tagged_targets());
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "canary".into(),
        labels: HashMap::from([("version".into(), "v2".into())]),
        traffic_policy: None,
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..Default::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let mut refreshed = make_tagged_targets();
    refreshed.push(UpstreamTarget {
        host: "v2-c".into(),
        port: 8080,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::from([("version".to_string(), "v2".to_string())]),
        locality: None,
        path: None,
    });

    cache.update_targets("u1", refreshed, LoadBalancerAlgorithm::RoundRobin, None);

    let snapshot = cache.load();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..90 {
        let sel = LoadBalancerCache::select_target_subset_from(&snapshot, "u1", "", "canary", None)
            .unwrap();
        seen.insert(sel.target.host.clone());
    }
    assert_eq!(
        seen,
        std::collections::HashSet::from([
            "v2-a".to_string(),
            "v2-b".to_string(),
            "v2-c".to_string()
        ])
    );
}

// ─── LeastLatency warm-up / passive recovery (#2942) ────────────────────────

#[test]
fn least_latency_persistent_failure_does_not_pin_all_traffic() {
    // Warm target A with real samples; never-sampled failing target B must not
    // win every selection (bounded exploration + failure accounting).
    let targets = make_targets(2);
    let lb = LoadBalancer::new(
        TEST_UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    for _ in 0..5 {
        lb.record_latency(&targets[0], 10_000); // 10ms
    }

    // Simulate persistent failure on B without ever recording a success sample.
    // Even without failures recorded, bounded exploration must not pin 100%.
    let n = 200;
    let mut b_hits = 0usize;
    for _ in 0..n {
        let sel = lb.select("", None).unwrap();
        if sel.target.host == "host1" {
            b_hits += 1;
        }
    }
    assert!(
        b_hits < n,
        "unsampled target must not pin all {n} selections (got {b_hits})"
    );
    assert!(
        b_hits > 0,
        "healthy late-joiner / unsampled peer still receives bounded exploration"
    );

    // After enough failure penalties, B exits warm-up with a poor EWMA and
    // should receive ~0 steady-state traffic vs warmed A.
    for _ in 0..5 {
        lb.record_failed_attempt(&targets[1]);
    }
    let mut b_hits_after = 0usize;
    for _ in 0..100 {
        let sel = lb.select("", None).unwrap();
        if sel.target.host == "host1" {
            b_hits_after += 1;
        }
    }
    assert_eq!(
        b_hits_after, 0,
        "after failure penalties, persistently failing target must not win steady-state selection"
    );
}

#[test]
fn least_latency_passive_recovery_does_not_restore_warmup_bias() {
    use ferrum_edge::config::types::{HealthCheckConfig, PassiveHealthCheck};
    use ferrum_edge::health_check::HealthChecker;
    use std::sync::Arc;

    let targets = make_targets(2);
    let config = GatewayConfig {
        upstreams: vec![Upstream {
            id: TEST_UPSTREAM.into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            name: Some("ll".into()),
            targets: targets.clone(),
            algorithm: LoadBalancerAlgorithm::LeastLatency,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: Some(HealthCheckConfig {
                active: None,
                passive: Some(PassiveHealthCheck {
                    unhealthy_threshold: 1,
                    healthy_after_seconds: 1,
                    ..PassiveHealthCheck::default()
                }),
            }),
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            source_locality: None,
            locality_lb_strict: false,
            locality_lb_setting: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            resolved_subset_tls: HashMap::new(),
            dispatch_port_override_fallback: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        ..Default::default()
    };

    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let mut checker = HealthChecker::new();
    checker.set_load_balancer_cache(Arc::clone(&lb_cache));

    // Warm A; leave B unsampled, then eject+recover B via passive timer path.
    let inner = lb_cache.load();
    let balancer = inner.balancers().get(TEST_UPSTREAM).unwrap();
    for _ in 0..5 {
        balancer.record_latency(&targets[0], 10_000);
    }

    let pasv = PassiveHealthCheck {
        unhealthy_threshold: 1,
        healthy_after_seconds: 1,
        ..PassiveHealthCheck::default()
    };
    checker.report_response("p1", TEST_UPSTREAM, &targets[1], 500, false, Some(&pasv));
    assert!(
        checker
            .passive_health
            .get("p1")
            .unwrap()
            .unhealthy
            .contains_key("host1:8080")
    );

    {
        let ps = checker.passive_health.get("p1").unwrap();
        ps.unhealthy.get_mut("host1:8080").unwrap().recover_at_ms = 1;
    }
    checker.recover_due_passive_ejections();
    assert!(
        !checker
            .passive_health
            .get("p1")
            .unwrap()
            .unhealthy
            .contains_key("host1:8080")
    );

    // Post-recovery: B must participate as a warmed peer (sample count seeded),
    // not as biased-best warm-up. With no real latency yet it shares A's min EWMA
    // seed — selections should not be 100% B.
    let mut b_hits = 0usize;
    let n = 100;
    for _ in 0..n {
        let sel = balancer.select("", None).unwrap();
        if sel.target.host == "host1" {
            b_hits += 1;
        }
    }
    assert!(
        b_hits < n,
        "passive recovery must not restore unconditional warm-up preference for B (hits={b_hits})"
    );
}
