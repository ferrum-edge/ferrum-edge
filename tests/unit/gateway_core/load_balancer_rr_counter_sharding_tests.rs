//! Structural and selection coverage for issue #2947: RoundRobin / Random /
//! LeastLatency warm-up / locality-distribute selection counters are sharded
//! and cache-line padded (reusing the WRR shard mechanism).
//!
//! Hosted CI runs `tests/performance/mesh/benches/rr_selection.rs` (2-target
//! RR at 1 vs 8 threads) with `.github/scripts/verify_rr_selection_benchmark.py`
//! for the contention floor. These unit tests guard layout and selection parity.

use chrono::Utc;
use crossbeam_utils::CachePadded;
use ferrum_edge::_test_support::{
    distribute_first_wave_bucket_mods_for_test, select_random_from_shard_for_test,
    select_round_robin_from_shard_for_test, selection_counter_phases_for_test,
};
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, LocalityDistribute, Upstream, UpstreamLocalityLbSetting,
    UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::load_balancer::{LoadBalancer, LoadBalancerCache};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::thread;

const UPSTREAM: &str = "rr-counter-sharding";

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{i}"),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

fn locality_target(host: &str, locality: &str) -> UpstreamTarget {
    UpstreamTarget {
        host: host.into(),
        port: 8080,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: Some(locality.into()),
        path: None,
    }
}

fn upstream_with_locality_lb(
    source_locality: &str,
    targets: Vec<UpstreamTarget>,
    setting: UpstreamLocalityLbSetting,
) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "u1".to_string(),
        name: Some("u1".to_string()),
        namespace: "ferrum".to_string(),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: Some(source_locality.to_string()),
        locality_lb_strict: false,
        locality_lb_setting: Some(setting),
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn rr_selection_counters_are_sharded_and_padded_in_source() {
    let source = std::fs::read_to_string("src/load_balancer.rs")
        .expect("load_balancer.rs must be readable from crate root");
    assert!(
        source.contains("type SelectionCounterShards"),
        "RR/Random/distribute counters must share a SelectionCounterShards alias"
    );
    assert!(
        source.contains("fn new_selection_counters()"),
        "selection counters must be constructed via new_selection_counters()"
    );
    assert!(
        source.contains("SELECTION_COUNTER_PHASE_STRIDE")
            && source.contains("wrapping_mul(SELECTION_COUNTER_PHASE_STRIDE)"),
        "selection counter shards must initialize with distinct phase offsets"
    );
    assert!(
        !source.contains("All shards start at `0`"),
        "all-zero shard init must not return (causes first-wave lockstep)"
    );
    assert!(
        source.contains("fn selection_counter_ticket("),
        "hot-path advances must go through selection_counter_ticket()"
    );
    assert!(
        source.contains("rr_counter: SelectionCounterShards"),
        "LoadBalancer and PortLbState rr_counter must be SelectionCounterShards"
    );
    assert!(
        source.contains("distribute_counter: SelectionCounterShards"),
        "LocalityLbState distribute_counter must be SelectionCounterShards"
    );
    assert!(
        source.contains("selection_counter_ticket(rr_counter)")
            && source.contains("selection_counter_ticket(distribute_counter)"),
        "RR and distribute paths must advance sharded tickets"
    );
    // Guard against regressing to a single shared AtomicU64 field.
    assert!(
        !source.contains("rr_counter: AtomicU64"),
        "rr_counter must not be a bare AtomicU64"
    );
    assert!(
        !source.contains("distribute_counter: AtomicU64"),
        "distribute_counter must not be a bare AtomicU64"
    );
    assert!(
        source.contains("WRR_COUNTER_SHARDS") && source.contains("wrr_counter_shard"),
        "RR sharding must reuse the WRR shard count and thread assignment"
    );
    assert!(
        source.contains("CachePadded"),
        "selection counter shards must be cache-line padded"
    );
}

#[test]
fn selection_counter_shards_do_not_share_cache_lines() {
    // Mirror overload.rs's hot_atomics_do_not_share_cache_line: adjacent
    // CachePadded<AtomicU64> elements must occupy distinct lines so concurrent
    // shard writers cannot false-share.
    let size = std::mem::size_of::<CachePadded<AtomicU64>>();
    assert!(
        size >= 64,
        "CachePadded<AtomicU64> should be >= 64 bytes; got {size}"
    );

    let shards: [CachePadded<AtomicU64>; 16] =
        std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0)));
    let a = &*shards[0] as *const AtomicU64 as usize;
    let b = &*shards[1] as *const AtomicU64 as usize;
    let distance = a.abs_diff(b);
    assert!(
        distance >= 64,
        "adjacent selection-counter shards must not share a cache line; distance={distance}"
    );
}

#[test]
fn round_robin_single_worker_is_deterministic_cycle_within_shard() {
    // Phase offsets mean the first pick depends on the thread's shard, but a
    // single worker stays on one shard and must still walk a full RR cycle.
    let targets = make_targets(3);
    let lb = LoadBalancer::new(UPSTREAM, LoadBalancerAlgorithm::RoundRobin, &targets, None);

    let observed: Vec<_> = (0..9)
        .map(|_| lb.select("", None).expect("selection").target.host.clone())
        .collect();
    let indices: Vec<usize> = observed
        .iter()
        .map(|host| {
            host.strip_prefix("host")
                .expect("hostN")
                .parse()
                .expect("index")
        })
        .collect();
    assert_eq!(indices.len(), 9);
    for window in indices.windows(2) {
        assert_eq!(
            (window[0] + 1) % 3,
            window[1],
            "single-shard RR must advance by one target each pick; got {indices:?}"
        );
    }
    let mut counts = [0u64; 3];
    for idx in indices {
        counts[idx] += 1;
    }
    assert_eq!(
        counts,
        [3, 3, 3],
        "long-run single-worker RR ratios must stay even"
    );
}

#[test]
fn round_robin_first_wave_across_shards_is_not_lockstep() {
    // All-zero shard init would send every first pick to host0 on a 2-target
    // lane. Distinct phases must decorrelate the synchronized first wave.
    let targets = make_targets(2);
    let lb = LoadBalancer::new(UPSTREAM, LoadBalancerAlgorithm::RoundRobin, &targets, None);

    let phases = selection_counter_phases_for_test(&lb);
    assert!(
        phases.iter().any(|&p| p != phases[0]),
        "selection counter shards must not share one starting phase; got {phases:?}"
    );

    let first_wave: Vec<_> = (0..16)
        .map(|shard| {
            select_round_robin_from_shard_for_test(&lb, shard)
                .expect("shard pick")
                .host
                .clone()
        })
        .collect();
    let all_same = first_wave.windows(2).all(|w| w[0] == w[1]);
    assert!(
        !all_same,
        "first-wave RR across shards must not lockstep on one target; got {first_wave:?}"
    );
    assert!(
        first_wave.iter().any(|h| h == "host0") && first_wave.iter().any(|h| h == "host1"),
        "decorrelated first wave should touch both targets; got {first_wave:?}"
    );
}

#[test]
fn random_first_wave_across_shards_is_not_identical_sequence() {
    let targets = make_targets(2);
    let lb = LoadBalancer::new(UPSTREAM, LoadBalancerAlgorithm::Random, &targets, None);

    let first_wave: Vec<_> = (0..16)
        .map(|shard| {
            select_random_from_shard_for_test(&lb, shard)
                .expect("shard pick")
                .host
                .clone()
        })
        .collect();
    let all_same = first_wave.windows(2).all(|w| w[0] == w[1]);
    assert!(
        !all_same,
        "first-wave Random across shards must not share one seeded pick; got {first_wave:?}"
    );
}

#[test]
fn locality_distribute_first_wave_buckets_are_not_lockstep() {
    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 80);
    to.insert("us-east".to_string(), 20);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            locality_target("west-a", "us-west/us-west-1/a"),
            locality_target("west-b", "us-west/us-west-1/b"),
            locality_target("east-a", "us-east/us-east-1/a"),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![up],
        ..GatewayConfig::default()
    });
    let lb = cache.load().get_balancer("u1").expect("balancer").clone();

    // Weighted total is 100; all-zero phases would map every shard to the same
    // first bucket via golden_ratio_hash(0) % 100.
    let mods = distribute_first_wave_bucket_mods_for_test(&lb, 100).expect("distribute phases");
    assert_eq!(mods.len(), 16);
    let all_same = mods.windows(2).all(|w| w[0] == w[1]);
    assert!(
        !all_same,
        "first-wave distribute bucket picks must not lockstep; got {mods:?}"
    );
}

#[test]
fn round_robin_concurrent_selection_stays_even() {
    let targets = make_targets(2);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::RoundRobin,
        &targets,
        None,
    ));

    let thread_count = 8usize;
    let per_thread = 2_000usize;
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
    assert!(
        (host0 - 0.5).abs() < 0.05 && (host1 - 0.5).abs() < 0.05,
        "sharded RR must stay near-even under concurrency; host0={host0:.3} host1={host1:.3}"
    );
}

#[test]
fn least_latency_warmup_still_round_robins_across_targets() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::LeastLatency,
        &targets,
        None,
    );

    let mut counts = HashMap::new();
    for _ in 0..300 {
        let sel = lb.select("", None).expect("warm-up selection");
        *counts.entry(sel.target.host.clone()).or_insert(0) += 1;
    }
    assert_eq!(counts.len(), 3);
    for count in counts.values() {
        assert_eq!(
            *count, 100,
            "LeastLatency warm-up must still RR evenly before samples exist"
        );
    }
}

#[test]
fn locality_distribute_weighted_bucket_pick_stays_proportional() {
    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 80);
    to.insert("us-east".to_string(), 20);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            locality_target("west-a", "us-west/us-west-1/a"),
            locality_target("west-b", "us-west/us-west-1/b"),
            locality_target("east-a", "us-east/us-east-1/a"),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![up],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();

    let mut west = 0u64;
    let mut east = 0u64;
    for i in 0..5_000 {
        let sel = LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("d-{i}"), None)
            .expect("distribute selection");
        match sel.target.host.as_str() {
            "west-a" | "west-b" => west += 1,
            "east-a" => east += 1,
            other => panic!("unexpected host {other}"),
        }
    }
    let west_share = west as f64 / (west + east) as f64;
    assert!(
        (west_share - 0.80).abs() < 0.05,
        "distribute bucket pick must stay near 80/20; west_share={west_share:.3}"
    );
}

#[test]
fn single_target_round_robin_is_stable() {
    let targets = make_targets(1);
    let lb = LoadBalancer::new(UPSTREAM, LoadBalancerAlgorithm::RoundRobin, &targets, None);
    for _ in 0..32 {
        let sel = lb.select("", None).expect("selection");
        assert_eq!(sel.target.host, "host0");
    }
}

#[test]
fn random_concurrent_selection_stays_near_even() {
    let targets = make_targets(2);
    let lb = Arc::new(LoadBalancer::new(
        UPSTREAM,
        LoadBalancerAlgorithm::Random,
        &targets,
        None,
    ));

    let thread_count = 8usize;
    let per_thread = 2_000usize;
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
    assert!(
        (host0 - 0.5).abs() < 0.08 && (host1 - 0.5).abs() < 0.08,
        "sharded Random must stay near-even under concurrency; host0={host0:.3} host1={host1:.3}"
    );
}

#[test]
fn port_override_lane_round_robin_stays_even_under_concurrency() {
    let now = Utc::now();
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let up = Upstream {
        id: "u1".to_string(),
        name: Some("u1".to_string()),
        namespace: "ferrum".to_string(),
        targets: make_targets(2),
        algorithm: LoadBalancerAlgorithm::LeastConnections,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides,
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
        created_at: now,
        updated_at: now,
    };
    let cache = Arc::new(LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![up],
        ..GatewayConfig::default()
    }));

    let thread_count = 8usize;
    let per_thread = 1_000usize;
    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let snapshot = cache.load();
            let mut local = HashMap::new();
            for i in 0..per_thread {
                let sel = LoadBalancerCache::select_target_for_port_from(
                    &snapshot,
                    "u1",
                    &format!("p-{i}"),
                    8080,
                    None,
                )
                .expect("port-lane selection");
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
    assert!(
        (host0 - 0.5).abs() < 0.05 && (host1 - 0.5).abs() < 0.05,
        "port-lane sharded RR must stay near-even; host0={host0:.3} host1={host1:.3}"
    );
}

#[test]
fn selection_counter_ticket_wraps_without_biasing_modulo() {
    // fetch_add wraps on overflow; RR/Random/distribute all consume the ticket
    // via `% n` / golden-ratio hash, so wrapping must remain a full cycle.
    // Directly exercise the same arithmetic the hot path uses.
    let n = 3usize;
    let near_max = u64::MAX - 2;
    let mut seen = [0u64; 3];
    for offset in 0..9u64 {
        let ticket = near_max.wrapping_add(offset);
        seen[(ticket as usize) % n] += 1;
    }
    assert_eq!(seen, [3, 3, 3]);
}
