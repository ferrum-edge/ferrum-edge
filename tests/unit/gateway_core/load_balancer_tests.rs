//! Tests for load balancer module

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use ferrum_edge::load_balancer::{
    HealthContext, LoadBalancer, LoadBalancerCache, target_host_port_key,
};
use std::collections::HashMap;

const TEST_UPSTREAM: &str = "test-upstream";

/// Helper to build a HealthContext for tests that only need active unhealthy filtering.
fn active_health_ctx(active: &DashMap<String, u64>) -> HealthContext<'_> {
    HealthContext {
        active_unhealthy: active,
        proxy_passive: None,
    }
}
use std::sync::atomic::{AtomicI64, Ordering};

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{}", i),
            port: 8080,
            weight: 1,
            tags: HashMap::new(),
            path: None,
        })
        .collect()
}

fn make_weighted_targets() -> Vec<UpstreamTarget> {
    vec![
        UpstreamTarget {
            host: "heavy".into(),
            port: 8080,
            weight: 5,
            tags: HashMap::new(),
            path: None,
        },
        UpstreamTarget {
            host: "light".into(),
            port: 8080,
            weight: 1,
            tags: HashMap::new(),
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
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
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
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
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
    // it should NOT force the entire upstream back into round-robin warm-up.
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

    // host2 has 0 samples, but host0/host1 are warmed up.
    // The algorithm should NOT regress to round-robin for all traffic.
    // Instead, host2 should be slightly favored (min EWMA - 1) to get
    // traffic and establish a real baseline.
    let sel = lb.select("", Some(&active_health_ctx(&unhealthy))).unwrap();
    assert_eq!(
        sel.target.host, "host2",
        "Recovered host2 should be slightly favored as a late joiner to establish baseline, got {}",
        sel.target.host
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
    // The new target should get a fair share via optimistic EWMA estimation.
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

    // The algorithm should NOT fall back to pure round-robin.
    // host0 (unwarmed) gets min EWMA - 1, so it should be slightly favored
    // to establish its real baseline.
    let sel = lb.select("", None).unwrap();
    assert_eq!(
        sel.target.host, "host0",
        "Late joiner (host0) should be slightly favored to establish baseline"
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
        weight: 1,
        tags: HashMap::new(),
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
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
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
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
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
        weight: 1,
        tags: HashMap::new(),
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
            weight: 0,
            tags: HashMap::new(),
            path: None,
        },
        UpstreamTarget {
            host: "b".into(),
            port: 8080,
            weight: 0,
            tags: HashMap::new(),
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
            weight: 10,
            tags: HashMap::new(),
            path: None,
        },
        UpstreamTarget {
            host: "zero".into(),
            port: 8080,
            weight: 0,
            tags: HashMap::new(),
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
    };

    // Mark host1 as passively unhealthy
    checker.report_response("test-proxy", &targets[1], 500, false, Some(&config));

    let active: DashMap<String, u64> = DashMap::new();
    let proxy_passive = checker.passive_health.get("test-proxy").map(|e| e.clone());

    let ctx = HealthContext {
        active_unhealthy: &active,
        proxy_passive,
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
