//! Concurrent WRR fairness, recovery, lane isolation, cardinality, and
//! multi-fingerprint cache regression coverage for issue #2413.
//!
//! Throughput against single-lane schedule serialization is gated by the hosted
//! Criterion microbenchmark + `.github/scripts/verify_wrr_selection_benchmark.py`
//! (mandatory parallel-speedup floors on 32/129-target fixtures; the skewed
//! 4-target fixture is a secondary Arc-hotspot / serial-ratio signal), not by
//! wall-clock assertions in this ordinary unit suite.

use dashmap::DashMap;
use ferrum_edge::config::types::{
    LoadBalancerAlgorithm, SubsetDefinition, SubsetTrafficPolicy, UpstreamTarget,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancer, target_key};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

const UPSTREAM: &str = "wrr-concurrency";

fn active_health_ctx(active: &DashMap<String, u64>) -> HealthContext<'_> {
    HealthContext {
        active_unhealthy: active,
        proxy_passive: None,
        max_ejection_percent: None,
    }
}

fn weighted_targets(weights: &[u32]) -> Vec<UpstreamTarget> {
    weights
        .iter()
        .enumerate()
        .map(|(i, &weight)| UpstreamTarget {
            host: format!("host{i}"),
            port: 8080,
            service_port_policy_key: None,
            weight,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn tagged_target(host: &str, version: &str, weight: u32) -> UpstreamTarget {
    UpstreamTarget {
        host: host.into(),
        port: 8080,
        service_port_policy_key: None,
        weight,
        tags: HashMap::from([("version".to_string(), version.to_string())]),
        locality: None,
        path: None,
    }
}

#[test]
fn wrr_source_no_longer_guards_lane_state_with_mutex_vec() {
    let source = std::fs::read_to_string("src/load_balancer.rs")
        .expect("load_balancer.rs must be readable from crate root");
    assert!(
        source.contains("struct WrrLaneState"),
        "expected contention-bounded WrrLaneState"
    );
    assert!(
        source.contains("struct WrrSchedule"),
        "steady-state WRR must use precomputed WrrSchedule values"
    );
    assert!(
        source.contains("WRR_SCHEDULE_CACHE_SLOTS"),
        "steady-state WRR must retain a bounded multi-fingerprint schedule cache"
    );
    assert!(
        source.contains("WRR_COUNTER_SHARDS"),
        "steady-state WRR must shard selection counters to avoid single-line contention"
    );
    assert!(
        source.contains("WRR_SMOOTH_BUILD_MAX_WORK"),
        "smooth-WRR construction must declare an explicit work budget"
    );
    assert!(
        source.contains("CachePadded"),
        "WRR counter shards must be cache-line padded"
    );
    assert!(
        !source.contains("invalidate: AtomicBool"),
        "racy invalidate boolean must not return; schedules are fingerprint-pure"
    );
    assert!(
        source.contains("try_lock"),
        "schedule publish must use try_lock so misses stay contention-bounded"
    );
    assert!(
        source.contains("WRR_MISS_PUBLISH_SAMPLE"),
        "full-cache schedule replacement must be rate-sampled"
    );
    assert!(
        source.contains("pick_wrr_miss_fallback_bitset")
            && source.contains("pick_wrr_miss_fallback_vec"),
        "cache misses must have an allocation-free candidate-scan fallback"
    );
    assert!(
        source.contains("is_lottery_only") || source.contains("LotteryOnly"),
        "oversized smooth builds must publish a lottery-only sentinel"
    );
    assert!(
        source.contains("resolve_wrr_vec_candidate") && source.contains("binary_search_by_key"),
        "Vec schedule hits must resolve original indices with binary search"
    );
    assert!(
        !source.contains("build a local schedule")
            && !source.contains("Contending missers build a local"),
        "contending missers must not allocate ephemeral smooth-WRR schedules"
    );
}

#[test]
fn wrr_concurrent_fairness_matches_configured_weights() {
    let targets = weighted_targets(&[5, 1, 2]);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    let thread_count = 8usize;
    let per_thread = 3_000usize;
    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let lb = Arc::clone(&lb);
        handles.push(thread::spawn(move || {
            let mut local = HashMap::new();
            for _ in 0..per_thread {
                let sel = lb.select("", None).expect("selection");
                *local.entry(sel.target.host.clone()).or_insert(0u64) += 1;
            }
            local
        }));
    }

    let mut counts = HashMap::new();
    for handle in handles {
        for (host, count) in handle.join().expect("worker") {
            *counts.entry(host).or_insert(0u64) += count;
        }
    }

    let total = (thread_count * per_thread) as f64;
    let host0 = *counts.get("host0").unwrap_or(&0) as f64 / total;
    let host1 = *counts.get("host1").unwrap_or(&0) as f64 / total;
    let host2 = *counts.get("host2").unwrap_or(&0) as f64 / total;
    // Ideal shares: 5/8, 1/8, 2/8.
    assert!(
        (host0 - 0.625).abs() < 0.05,
        "host0 share {host0} outside tolerance"
    );
    assert!(
        (host1 - 0.125).abs() < 0.05,
        "host1 share {host1} outside tolerance"
    );
    assert!(
        (host2 - 0.250).abs() < 0.05,
        "host2 share {host2} outside tolerance"
    );
}

#[test]
fn wrr_unhealthy_targets_excluded_and_recovered_targets_rejoin() {
    let targets = weighted_targets(&[3, 1]);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert(target_key(UPSTREAM, &targets[0]), 1);

    for _ in 0..50 {
        let sel = lb
            .select("", Some(&active_health_ctx(&unhealthy)))
            .expect("selection");
        assert_eq!(sel.target.host, "host1");
        assert!(!sel.is_fallback);
    }

    unhealthy.clear();
    lb.reset_recovered_target_latency(&targets[0]);

    let mut seen_heavy = false;
    for _ in 0..40 {
        let sel = lb.select("", None).expect("selection");
        if sel.target.host == "host0" {
            seen_heavy = true;
            break;
        }
    }
    assert!(
        seen_heavy,
        "recovered heavy target must re-enter WRR rotation"
    );
}

#[test]
fn wrr_subset_lanes_are_isolated_under_concurrency() {
    let targets = vec![
        tagged_target("v1-a", "v1", 5),
        tagged_target("v1-b", "v1", 1),
        tagged_target("v2-a", "v2", 1),
        tagged_target("v2-b", "v2", 5),
    ];
    let subsets = vec![
        SubsetDefinition {
            name: "v1".into(),
            labels: HashMap::from([("version".into(), "v1".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
                hash_on: None,
                tls: None,
                connect_timeout_ms: None,
                h2_upgrade_policy: None,
                max_retries: None,
                http1_max_pending_requests: None,
                http_idle_timeout_ms: None,
                h2_max_concurrent_streams: None,
                passive_health_check: None,
            }),
        },
        SubsetDefinition {
            name: "v2".into(),
            labels: HashMap::from([("version".into(), "v2".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
                hash_on: None,
                tls: None,
                connect_timeout_ms: None,
                h2_upgrade_policy: None,
                max_retries: None,
                http1_max_pending_requests: None,
                http_idle_timeout_ms: None,
                h2_max_concurrent_streams: None,
                passive_health_check: None,
            }),
        },
    ];
    let lb = Arc::new(LoadBalancer::with_subsets(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
        Some(&subsets),
    ));

    let v1_counts = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let v2_counts = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let mut handles = Vec::new();
    for lane in ["v1", "v2"] {
        for _ in 0..4 {
            let lb = Arc::clone(&lb);
            let v1_counts = Arc::clone(&v1_counts);
            let v2_counts = Arc::clone(&v2_counts);
            handles.push(thread::spawn(move || {
                for _ in 0..2_000 {
                    let sel = lb
                        .select_from_subset("", lane, None)
                        .expect("subset selection");
                    match (lane, sel.target.host.as_str()) {
                        ("v1", "v1-a") => {
                            v1_counts.0.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v1", "v1-b") => {
                            v1_counts.1.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v2", "v2-a") => {
                            v2_counts.0.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v2", "v2-b") => {
                            v2_counts.1.fetch_add(1, Ordering::Relaxed);
                        }
                        ("v1", other) => panic!("v1 lane leaked {other}"),
                        ("v2", other) => panic!("v2 lane leaked {other}"),
                        _ => unreachable!(),
                    }
                }
            }));
        }
    }
    for handle in handles {
        handle.join().expect("worker");
    }

    let v1_a = v1_counts.0.load(Ordering::Relaxed) as f64;
    let v1_b = v1_counts.1.load(Ordering::Relaxed) as f64;
    let v2_a = v2_counts.0.load(Ordering::Relaxed) as f64;
    let v2_b = v2_counts.1.load(Ordering::Relaxed) as f64;
    assert!(
        v1_a / (v1_a + v1_b) > 0.7,
        "v1 lane should prefer weight-5 target"
    );
    assert!(
        v2_b / (v2_a + v2_b) > 0.7,
        "v2 lane should prefer weight-5 target"
    );
}

#[test]
fn wrr_cardinality_paths_preserve_weights_for_small_and_large_sets() {
    for n in [2usize, 8, 64, 129] {
        let weights: Vec<u32> = (0..n).map(|i| if i == 0 { 5 } else { 1 }).collect();
        let targets = weighted_targets(&weights);
        let lb = LoadBalancer::new(
            UPSTREAM,
            LoadBalancerAlgorithm::WeightedRoundRobin,
            &targets,
            None,
        );

        let samples = (n * 200).max(2_000);
        let mut heavy = 0u64;
        for _ in 0..samples {
            let sel = lb.select("", None).expect("selection");
            if sel.target.host == "host0" {
                heavy += 1;
            }
        }
        let share = heavy as f64 / samples as f64;
        let ideal = 5.0 / (5.0 + (n as f64 - 1.0));
        assert!(
            (share - ideal).abs() < 0.08,
            "n={n}: heavy share {share} vs ideal {ideal}"
        );
    }
}

#[test]
fn wrr_exactly_128_healthy_targets_do_not_alias_an_invalid_cache_slot() {
    // A full 128-target bitset is u128::MAX. It must be treated as a real
    // healthy-set key, not as an uninitialized-slot sentinel.
    let targets = weighted_targets(&vec![1; 128]);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    for _ in 0..256 {
        lb.select("", None)
            .expect("all-healthy 128-target WRR selection");
    }
}

#[test]
fn wrr_alternating_fingerprints_keep_independent_selection_counters() {
    // Each exclusion leaves a two-target, equal-weight schedule. A shared lane
    // counter would make the alternating calls observe a fixed parity and pin
    // each fingerprint to only one backend forever.
    let targets = weighted_targets(&[1, 1, 1]);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );
    let mut exclude_last_counts = HashMap::<String, usize>::new();
    let mut exclude_first_counts = HashMap::<String, usize>::new();

    for _ in 0..200 {
        let first_lane = lb
            .select_excluding("", &targets[2], None)
            .expect("exclude last target");
        *exclude_last_counts
            .entry(first_lane.host.clone())
            .or_default() += 1;

        let second_lane = lb
            .select_excluding("", &targets[0], None)
            .expect("exclude first target");
        *exclude_first_counts
            .entry(second_lane.host.clone())
            .or_default() += 1;
    }

    assert_eq!(exclude_last_counts.get("host0"), Some(&100));
    assert_eq!(exclude_last_counts.get("host1"), Some(&100));
    assert_eq!(exclude_first_counts.get("host1"), Some(&100));
    assert_eq!(exclude_first_counts.get("host2"), Some(&100));
}

#[test]
fn wrr_vec_path_alternating_exclusions_remain_correct() {
    // >128 targets exercise exact ordered-membership cache keys.
    let n = 129usize;
    let weights: Vec<u32> = (0..n).map(|i| if i < 4 { 3 } else { 1 }).collect();
    let targets = weighted_targets(&weights);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));

    for _ in 0..32 {
        let t = lb
            .select_excluding("", &targets[0], None)
            .expect("exclude 0");
        assert_ne!(t.host, "host0");
        let t = lb
            .select_excluding("", &targets[1], None)
            .expect("exclude 1");
        assert_ne!(t.host, "host1");
    }
    let threads = 6usize;
    let per_thread = 200usize;
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let lb = Arc::clone(&lb);
        let exclude = if tid % 2 == 0 {
            targets[0].clone()
        } else {
            targets[1].clone()
        };
        let forbidden = exclude.host.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let t = lb
                    .select_excluding("", &exclude, None)
                    .expect("vec exclusion");
                assert_ne!(t.host, forbidden);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }
}

#[test]
fn wrr_fingerprint_churn_beyond_cache_capacity_amortizes_publishes() {
    // WRR_SCHEDULE_CACHE_SLOTS is 8. Rotating exclusions over 9 equal-weight
    // targets yields capacity+1 distinct healthy-set fingerprints. Sustained
    // cycling must not publish/rebuild a smooth schedule on every miss, and
    // selections must stay on eligible positive-weight targets only.
    const CACHE_SLOTS: usize = 8;
    const TARGETS: usize = CACHE_SLOTS + 1;
    let weights = vec![1u32; TARGETS];
    let targets = weighted_targets(&weights);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let cycles = 200usize;
    let mut selections = 0u64;
    for _ in 0..cycles {
        for exclude in &targets {
            let sel = lb
                .select_excluding("", exclude, None)
                .expect("capacity+1 churn selection");
            assert_ne!(
                sel.host, exclude.host,
                "miss fallback must not select the excluded target"
            );
            assert!(
                targets.iter().any(|t| t.host == sel.host && t.weight > 0),
                "selection must be an eligible positive-weight target"
            );
            selections += 1;
        }
    }

    let (publishes, fallbacks) = lb.wrr_parent_schedule_counters();
    assert!(
        fallbacks > 0,
        "capacity+1 fingerprint churn must exercise the allocation-free miss path"
    );
    // Cold-fill can publish up to CACHE_SLOTS schedules; afterward publishes are
    // rate-sampled (WRR_MISS_PUBLISH_SAMPLE = 64). Even a loose bound stays far
    // below one publish per selection.
    let max_publishes = (CACHE_SLOTS as u64) + selections / 32 + 1;
    assert!(
        publishes <= max_publishes,
        "publishes={publishes} exceeded amortized bound {max_publishes} for {selections} selections"
    );
    assert!(
        publishes * 10 < selections,
        "publishes={publishes} must remain << selections={selections}"
    );
}

#[test]
fn wrr_vec_path_fingerprint_churn_beyond_cache_capacity_amortizes_publishes() {
    // Same capacity+1 amortization contract on the >128-target Vec cache keys.
    const CACHE_SLOTS: usize = 8;
    let n = 129usize;
    let weights = vec![1u32; n];
    let targets = weighted_targets(&weights);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    // Use the first CACHE_SLOTS+1 targets as rotating exclusions so fingerprints
    // thrash the bounded schedule cache without depending on passive health.
    let churn_excludes = &targets[..CACHE_SLOTS + 1];
    let cycles = 80usize;
    let mut selections = 0u64;
    for _ in 0..cycles {
        for exclude in churn_excludes {
            let sel = lb
                .select_excluding("", exclude, None)
                .expect("vec capacity+1 churn selection");
            assert_ne!(sel.host, exclude.host);
            assert!(sel.weight > 0);
            selections += 1;
        }
    }

    let (publishes, fallbacks) = lb.wrr_parent_schedule_counters();
    assert!(
        fallbacks > 0,
        "vec churn must use allocation-free miss fallback"
    );
    let max_publishes = (CACHE_SLOTS as u64) + selections / 32 + 1;
    assert!(
        publishes <= max_publishes,
        "vec publishes={publishes} exceeded amortized bound {max_publishes} for {selections} selections"
    );
    assert!(publishes * 10 < selections);
}

#[test]
fn wrr_oversized_schedule_caches_lottery_sentinel_without_rebuild_churn() {
    // 200 candidates × 8192 capped steps exceeds WRR_SMOOTH_BUILD_MAX_WORK
    // (8192 × 128). The publisher must store an exact-key lottery-only sentinel
    // so repeated selections do not re-attempt the quadratic smooth build.
    let n = 200usize;
    let weights: Vec<u32> = (0..n).map(|i| if i == 0 { 65_535 } else { 1 }).collect();
    let targets = weighted_targets(&weights);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    );

    let mut heavy = 0u64;
    let samples = 400usize;
    for _ in 0..samples {
        let sel = lb.select("", None).expect("lottery-sentinel WRR selection");
        assert!(sel.target.weight > 0);
        if sel.target.host == "host0" {
            heavy += 1;
        }
    }

    let (publishes, _fallbacks) = lb.wrr_parent_schedule_counters();
    assert_eq!(
        publishes, 1,
        "exact-key lottery sentinel must publish once, not on every selection"
    );
    // Lottery is not exact smooth-WRR, but the heavy target must remain reachable
    // and dominate zero-weight exclusion (all weights here are positive).
    assert!(
        heavy > 0,
        "heavy positive-weight target must remain selectable under lottery sentinel"
    );
}

#[test]
fn wrr_all_zero_weights_round_robin_under_concurrency() {
    let targets = weighted_targets(&[0, 0, 0, 0]);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::WeightedRoundRobin,
        &targets,
        None,
    ));
    let counts = Arc::new([
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ]);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let lb = Arc::clone(&lb);
        let counts = Arc::clone(&counts);
        handles.push(thread::spawn(move || {
            for _ in 0..500 {
                let sel = lb.select("", None).expect("zero-weight RR");
                let idx: usize = sel
                    .target
                    .host
                    .trim_start_matches("host")
                    .parse()
                    .expect("host index");
                counts[idx].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }
    let total: u64 = counts.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    assert_eq!(total, 8 * 500);
    for (i, c) in counts.iter().enumerate() {
        let share = c.load(Ordering::Relaxed) as f64 / total as f64;
        assert!(
            (share - 0.25).abs() < 0.08,
            "zero-weight host{i} share {share} outside fairness band"
        );
    }
}
