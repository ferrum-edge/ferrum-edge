use std::collections::HashMap;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm, PassiveHealthCheck, Proxy,
    ResolvedSubsetTrafficPolicy, SubsetDefinition, SubsetTrafficPolicy, Upstream,
    UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::{
    HashOnStrategy, HealthContext, LoadBalancerCache, target_host_port_key, target_key,
};

fn target(host: &str, port: u16) -> UpstreamTarget {
    weighted_target(host, port, 1)
}

/// Assert `sequence` is a contiguous RoundRobin walk over `ordered_targets`.
///
/// Selection-counter shards start at distinct golden-ratio phase offsets, so
/// the absolute first bucket depends on the calling thread's shard assignment.
/// Within one shard the walk remains deterministic: each pick advances one step
/// through the configured target order (wrapping).
fn assert_contiguous_round_robin(sequence: &[String], ordered_targets: &[&str]) {
    assert!(
        !sequence.is_empty(),
        "round-robin sequence must not be empty"
    );
    let n = ordered_targets.len();
    assert!(n > 0, "ordered target list must not be empty");
    let start = ordered_targets
        .iter()
        .position(|host| *host == sequence[0].as_str())
        .unwrap_or_else(|| {
            panic!("sequence {sequence:?} must start on one of {ordered_targets:?}")
        });
    for (offset, host) in sequence.iter().enumerate() {
        let expected = ordered_targets[(start + offset) % n];
        assert_eq!(
            host.as_str(),
            expected,
            "expected contiguous RR over {ordered_targets:?} starting at index {start}, got {sequence:?}"
        );
    }
    if sequence.len() > 1 && n > 1 {
        assert_ne!(
            sequence[0], sequence[1],
            "round-robin must advance within a shard; got {sequence:?}"
        );
    }
}

fn weighted_target(host: &str, port: u16, weight: u32) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn tagged_target(host: &str, port: u16, tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: tags
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
        locality: None,
        path: None,
    }
}

fn upstream_with_overrides(
    algorithm: LoadBalancerAlgorithm,
    targets: Vec<UpstreamTarget>,
    port_overrides: HashMap<u16, UpstreamPortOverride>,
) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "u1".to_string(),
        namespace: "ferrum".to_string(),
        name: Some("u1".to_string()),
        targets,
        algorithm,
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
    }
}

#[test]
fn initial_dispatch_port_override_requires_all_targets_on_overridden_port() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());

    let mixed = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 9090)],
        port_overrides.clone(),
    );
    let mixed_config = GatewayConfig {
        upstreams: vec![mixed],
        ..GatewayConfig::default()
    };
    let mixed_cache = LoadBalancerCache::new(&mixed_config);
    let mixed_snapshot = mixed_cache.load();

    assert_eq!(
        LoadBalancerCache::initial_dispatch_port_override_from(&mixed_snapshot, "u1"),
        0,
        "mixed-port upstreams must wait until a concrete target is selected"
    );

    let uniform = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080)],
        port_overrides,
    );
    let uniform_config = GatewayConfig {
        upstreams: vec![uniform],
        ..GatewayConfig::default()
    };
    let uniform_cache = LoadBalancerCache::new(&uniform_config);
    let uniform_snapshot = uniform_cache.load();

    assert_eq!(
        LoadBalancerCache::initial_dispatch_port_override_from(&uniform_snapshot, "u1"),
        8080,
        "single-port upstreams can use the port override before selection"
    );
}

#[test]
fn port_wrr_zero_weight_fallback_uses_port_counter() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
            ..Default::default()
        },
    );
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![
            weighted_target("a", 8080, 0),
            weighted_target("b", 8080, 0),
            weighted_target("c", 8080, 0),
        ],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let control_cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let control_snapshot = control_cache.load();

    for _ in 0..2 {
        LoadBalancerCache::select_target_from(&snapshot, "u1", "parent", None)
            .expect("parent selection");
    }

    let port_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "port", 8080, None)
                .expect("port selection")
                .target
                .host
                .clone()
        })
        .collect();

    let control_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(
                &control_snapshot,
                "u1",
                "port",
                8080,
                None,
            )
            .expect("control port selection")
            .target
            .host
            .clone()
        })
        .collect();

    assert_eq!(
        port_sequence, control_sequence,
        "parent selections must not advance the independent per-port WRR lane"
    );
    assert_ne!(
        port_sequence[0], port_sequence[1],
        "the zero-weight per-port lane must still advance round-robin"
    );
}

#[test]
fn port_least_latency_warmup_fallback_uses_port_counter() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::LeastLatency),
            ..Default::default()
        },
    );
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080), target("c", 8080)],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let control_cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let control_snapshot = control_cache.load();

    for _ in 0..2 {
        LoadBalancerCache::select_target_from(&snapshot, "u1", "parent", None)
            .expect("parent selection");
    }

    let port_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "port", 8080, None)
                .expect("port selection")
                .target
                .host
                .clone()
        })
        .collect();

    let control_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(
                &control_snapshot,
                "u1",
                "port",
                8080,
                None,
            )
            .expect("control port selection")
            .target
            .host
            .clone()
        })
        .collect();

    assert_eq!(
        port_sequence, control_sequence,
        "parent selections must not advance the independent per-port LeastLatency warm-up lane"
    );
    assert_contiguous_round_robin(&port_sequence, &["a", "b", "c"]);
}

#[test]
fn port_wrr_vec_zero_weight_fallback_uses_port_counter() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
            ..Default::default()
        },
    );
    let targets: Vec<UpstreamTarget> = (0..129)
        .map(|idx| weighted_target(&format!("h{idx}"), 8080, 0))
        .collect();
    let upstream =
        upstream_with_overrides(LoadBalancerAlgorithm::RoundRobin, targets, port_overrides);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let control_cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let control_snapshot = control_cache.load();

    LoadBalancerCache::select_target_from(&snapshot, "u1", "parent", None)
        .expect("parent selection");
    let selected =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "port", 8080, None)
            .expect("port selection");
    let control =
        LoadBalancerCache::select_target_for_port_from(&control_snapshot, "u1", "port", 8080, None)
            .expect("control port selection");

    assert_eq!(
        selected.target.host, control.target.host,
        "parent-lane selection must not advance the independent port WRR lane"
    );
}

#[test]
fn port_subset_fully_unhealthy_intersection_returns_none() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![
            tagged_target("a", 8080, &[("version", "v1")]),
            tagged_target("b", 8080, &[("version", "v1")]),
            tagged_target("c", 9090, &[("version", "v1")]),
        ],
        port_overrides,
    );
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "v1".to_string(),
        labels: HashMap::from([("version".to_string(), "v1".to_string())]),
        traffic_policy: None,
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert("u1::a:8080".to_string(), 0);
    active_unhealthy.insert("u1::b:8080".to_string(), 0);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_for_port_subset_from(
        &snapshot,
        "u1",
        "key",
        8080,
        "v1",
        Some(&health),
    );

    assert!(
        selection.is_none(),
        "retry must not escape to healthy subset targets outside the selected port"
    );
}

#[test]
fn port_subset_vec_fallback_filters_intersection_for_large_upstreams() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let targets: Vec<UpstreamTarget> = (0..129)
        .map(|idx| {
            let port = if idx % 3 == 0 { 8080 } else { 9090 };
            let version = if idx % 5 == 0 { "v1" } else { "v2" };
            tagged_target(&format!("h{idx}"), port, &[("version", version)])
        })
        .collect();
    let mut upstream =
        upstream_with_overrides(LoadBalancerAlgorithm::RoundRobin, targets, port_overrides);
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "v1".to_string(),
        labels: HashMap::from([("version".to_string(), "v1".to_string())]),
        traffic_policy: None,
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let selection = LoadBalancerCache::select_target_for_port_subset_from(
        &snapshot, "u1", "key", 8080, "v1", None,
    )
    .expect("large-target port subset selection");
    assert_eq!(selection.target.port, 8080);
    assert_eq!(
        selection.target.tags.get("version").map(String::as_str),
        Some("v1")
    );

    let retry = LoadBalancerCache::select_next_target_for_port_subset_from(
        &snapshot,
        "u1",
        "retry",
        8080,
        "v1",
        selection.target.as_ref(),
        None,
    )
    .expect("large-target port subset retry selection");
    assert_eq!(retry.port, 8080);
    assert_eq!(retry.tags.get("version").map(String::as_str), Some("v1"));
    assert_ne!(
        retry.host, selection.target.host,
        "retry should exclude the original target while staying in the port/subset intersection"
    );
}

#[test]
fn hash_on_only_port_override_preserves_subset_algorithm_with_port_hash_key() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            hash_on: Some("cookie:port-affinity".to_string()),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![
            tagged_target("a", 8080, &[("version", "v1")]),
            tagged_target("b", 8080, &[("version", "v1")]),
            tagged_target("c", 9090, &[("version", "v1")]),
            tagged_target("d", 8080, &[("version", "v2")]),
        ],
        port_overrides,
    );
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "v1".to_string(),
        labels: HashMap::from([("version".to_string(), "v1".to_string())]),
        traffic_policy: Some(SubsetTrafficPolicy {
            load_balancer_algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
            hash_on: Some("header:x-subset".to_string()),
            tls: None,
            connect_timeout_ms: None,
            passive_health_check: None,
        }),
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::effective_algorithm_from(&snapshot, "u1", Some(8080), Some("v1")),
        Some(LoadBalancerAlgorithm::ConsistentHashing),
        "a hash_on-only port override must not replace the subset algorithm"
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_selection_from(
            &snapshot,
            "u1",
            Some(8080),
            Some("v1"),
        ),
        HashOnStrategy::Cookie("port-affinity".to_string()),
        "an explicit per-port hash_on must override the subset hash key"
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_selection_from(
            &snapshot,
            "u1",
            None,
            Some("v1"),
        ),
        HashOnStrategy::Header("x-subset".to_string()),
        "subset-only selection still uses the subset hash key"
    );
}

#[test]
fn port_retry_selection_does_not_escape_selected_port() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let targets = vec![
        target("a", 8080),
        target("b", 8080),
        target("c", 9090),
        target("d", 8080),
    ];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &targets[0]), 0);
    active_unhealthy.insert(target_key("u1", &targets[3]), 0);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_next_target_for_port_from(
        &snapshot,
        "u1",
        "key",
        8080,
        &targets[1],
        Some(&health),
    );

    assert!(
        selection.is_none(),
        "retry selection must not escape the selected port or pick an unhealthy same-port target"
    );

    active_unhealthy.remove(&target_key("u1", &targets[3]));
    let selection = LoadBalancerCache::select_next_target_for_port_from(
        &snapshot,
        "u1",
        "key",
        8080,
        &targets[1],
        Some(&health),
    )
    .expect("healthy same-port retry selection");

    assert_eq!(
        selection.port, 8080,
        "retry selection for a port override must not escape to another destination port"
    );
    assert_eq!(selection.host, "d");
}

fn proxy_for_upstream() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "p1",
        "backend_host": "svc.local",
        "backend_port": 8080,
        "upstream_id": "u1",
    }))
    .expect("test proxy should deserialize")
}

/// A proxy bound to a DestinationRule subset (sets `upstream_subset`).
fn proxy_for_upstream_subset(subset: &str) -> Proxy {
    let mut proxy = proxy_for_upstream();
    proxy.upstream_subset = Some(subset.to_string());
    proxy
}

/// Build a resolved subset overlay carrying only an `outlierDetection` passive
/// overlay with the given ejection cap (mirrors what
/// `apply_outlier_detection_to_passive` stores per-subset on the upstream).
fn subset_passive_with_cap(max_ejection_percent: Option<u8>) -> ResolvedSubsetTrafficPolicy {
    ResolvedSubsetTrafficPolicy {
        tls: None,
        passive_health_check: Some(PassiveHealthCheck {
            unhealthy_threshold: 3,
            max_ejection_percent,
            ..PassiveHealthCheck::default()
        }),
    }
}

#[test]
fn upstream_round_robin_port_override_random_uses_port_specific_algorithm() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::Random),
            ..Default::default()
        },
    );
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let port_sequence: Vec<String> = (0..3)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "same-key", 8080, None)
                .expect("port override should select")
                .target
                .host
                .clone()
        })
        .collect();
    assert!(
        port_sequence
            .iter()
            .all(|host| matches!(host.as_str(), "a" | "b")),
        "port-specific random selection must stay on port 8080 targets: {port_sequence:?}"
    );

    let parent_sequence: Vec<String> = (0..3)
        .map(|_| {
            LoadBalancerCache::select_target_from(&snapshot, "u1", "same-key", None)
                .expect("parent LB should select")
                .target
                .host
                .clone()
        })
        .collect();
    // Parent RoundRobin walks a→b→c from the calling shard's phase offset; do
    // not assert an absolute starting bucket.
    assert_contiguous_round_robin(&parent_sequence, &["a", "b", "c"]);
}

#[test]
fn algorithm_port_override_without_hash_on_clears_upstream_hash_strategy() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::Random),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::ConsistentHashing,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    upstream.hash_on = Some("cookie:srv".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_from(&snapshot, "u1"),
        HashOnStrategy::Cookie("srv".to_string())
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 8080),
        HashOnStrategy::Ip,
        "switching a port to a non-hash algorithm should clear upstream sticky hash state"
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 9090),
        HashOnStrategy::Cookie("srv".to_string()),
        "ports without an override should keep the upstream strategy"
    );
}

#[test]
fn non_algorithm_port_override_inherits_upstream_algorithm_and_hash_strategy() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            connect_timeout_ms: Some(250),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::ConsistentHashing,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    upstream.hash_on = Some("header:x-user-id".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 8080),
        HashOnStrategy::Header("x-user-id".to_string()),
        "non-LB port overrides should inherit upstream sticky hash state"
    );

    let port_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "same-key", 8080, None)
                .expect("port selection")
                .target
                .host
                .clone()
        })
        .collect();
    assert!(
        port_sequence
            .iter()
            .all(|host| matches!(host.as_str(), "a" | "b")),
        "non-LB port overrides must still stay on the overridden port: {port_sequence:?}"
    );
    assert_eq!(
        port_sequence[0], port_sequence[1],
        "non-LB port overrides should inherit upstream consistent-hash routing"
    );
}

#[test]
fn consistent_hash_port_override_without_hash_on_preserves_upstream_hash_strategy() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    upstream.hash_on = Some("cookie:srv".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 8080),
        HashOnStrategy::Cookie("srv".to_string()),
        "a consistent-hash port override should inherit the upstream hash key when none is set"
    );
}

#[test]
fn per_port_passive_health_threshold_differs_from_upstream_level() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080)],
        port_overrides,
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: 3,
            ..PassiveHealthCheck::default()
        }),
    });
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream()],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let port_passive = config.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .and_then(|override_config| override_config.passive_health_check.as_ref())
        .expect("port passive health projected");
    assert_eq!(port_passive.unhealthy_threshold, 1);
    assert_eq!(
        config.upstreams[0]
            .health_checks
            .as_ref()
            .and_then(|hc| hc.passive.as_ref())
            .map(|passive| passive.unhealthy_threshold),
        Some(3)
    );

    let checker = HealthChecker::default();
    let selected = target("a", 8080);
    checker.report_response(
        "p1",
        "test-upstream",
        &selected,
        500,
        false,
        Some(port_passive),
    );
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created");
    assert!(
        proxy_state.unhealthy.contains_key("a:8080"),
        "port-level threshold 1 should eject after one matching failure"
    );
}

#[test]
fn port_passive_ejection_cap_uses_only_targets_on_selected_port() {
    let port_passive = PassiveHealthCheck {
        unhealthy_threshold: 1,
        max_ejection_percent: Some(50),
        ..PassiveHealthCheck::default()
    };
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(port_passive.clone()),
            ..Default::default()
        },
    );
    let targets = vec![
        target("a", 8080),
        target("b", 8080),
        target("c", 9090),
        target("d", 9090),
    ];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let checker = HealthChecker::new();
    checker.report_response(
        "p1",
        "test-upstream",
        &targets[0],
        500,
        false,
        Some(&port_passive),
    );
    checker.report_response(
        "p1",
        "test-upstream",
        &targets[1],
        500,
        false,
        Some(&port_passive),
    );
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created")
        .clone();
    proxy_state.unhealthy.insert(
        target_host_port_key(&targets[0]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 100,
            recover_at_ms: 100,
            auto_recover: false,
            upstream_id: "test-upstream".to_string(),
            host: targets[0].host.clone(),
            port: targets[0].port,
        },
    );
    proxy_state.unhealthy.insert(
        target_host_port_key(&targets[1]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 200,
            recover_at_ms: 200,
            auto_recover: false,
            upstream_id: "test-upstream".to_string(),
            host: targets[1].host.clone(),
            port: targets[1].port,
        },
    );

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: Some(proxy_state),
        max_ejection_percent: Some(50),
    };

    let selection =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "key", 8080, Some(&health))
            .expect("port selection");

    assert!(
        !selection.is_fallback,
        "one of two passively ejected port targets should be re-admitted under a 50% port cap"
    );
    assert_eq!(selection.target.host, "a");
}

#[test]
fn port_passive_ejection_cap_uses_only_targets_on_selected_port_vec_path() {
    let port_passive = PassiveHealthCheck {
        unhealthy_threshold: 1,
        max_ejection_percent: Some(50),
        ..PassiveHealthCheck::default()
    };
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(port_passive.clone()),
            ..Default::default()
        },
    );
    let mut targets = vec![target("a", 8080), target("b", 8080)];
    targets.extend((0..128).map(|idx| target(&format!("other-{idx}"), 9090)));
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let checker = HealthChecker::new();
    checker.report_response(
        "p1",
        "test-upstream",
        &targets[0],
        500,
        false,
        Some(&port_passive),
    );
    checker.report_response(
        "p1",
        "test-upstream",
        &targets[1],
        500,
        false,
        Some(&port_passive),
    );
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created")
        .clone();
    proxy_state.unhealthy.insert(
        target_host_port_key(&targets[0]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 100,
            recover_at_ms: 100,
            auto_recover: false,
            upstream_id: "test-upstream".to_string(),
            host: targets[0].host.clone(),
            port: targets[0].port,
        },
    );
    proxy_state.unhealthy.insert(
        target_host_port_key(&targets[1]),
        ferrum_edge::health_check::PassiveEjection {
            ejected_at_ms: 200,
            recover_at_ms: 200,
            auto_recover: false,
            upstream_id: "test-upstream".to_string(),
            host: targets[1].host.clone(),
            port: targets[1].port,
        },
    );

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: Some(proxy_state),
        max_ejection_percent: Some(50),
    };

    let selection =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "key", 8080, Some(&health))
            .expect("port selection");

    assert!(
        !selection.is_fallback,
        "Vec fallback should also apply the ejection cap to the selected port's target set"
    );
    assert_eq!(selection.target.host, "a");
}

#[test]
fn port_passive_override_without_max_ejection_does_not_inherit_upstream_cap() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: None,
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 9090)],
        port_overrides,
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(25),
            ..PassiveHealthCheck::default()
        }),
    });
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream()],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::max_ejection_percent_for_port_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            8080,
        ),
        None,
        "a port-level passive-health override owns the port cap even when it omits max_ejection_percent"
    );
    assert_eq!(
        LoadBalancerCache::max_ejection_percent_for_port_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            9090,
        ),
        Some(25),
        "ports without a passive override should still inherit the upstream cap"
    );
}

// ── F5.2: per-subset maxEjectionPercent cap resolution ──────────────────────

#[test]
fn subset_bound_proxy_uses_subset_max_ejection_cap_not_upstream() {
    // Upstream cap = 100%, subset 'v1' cap = 20%. A proxy bound to subset 'v1'
    // must resolve the SUBSET cap, mirroring how the thresholds are already
    // resolved per-subset by `passive_health_for_target`.
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080)],
        HashMap::new(),
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(100),
            ..PassiveHealthCheck::default()
        }),
    });
    upstream
        .resolved_subset_tls
        .insert("v1".to_string(), subset_passive_with_cap(Some(20)));

    let config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::max_ejection_percent_resolved_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            None,
        ),
        Some(20),
        "a subset-bound proxy must use the subset's ejection cap, not the upstream cap"
    );
}

#[test]
fn unsubsetted_proxy_uses_upstream_max_ejection_cap_even_when_subset_overlay_exists() {
    // The same upstream carries a subset overlay, but a proxy with no
    // `upstream_subset` must still resolve the upstream-level cap.
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080)],
        HashMap::new(),
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(100),
            ..PassiveHealthCheck::default()
        }),
    });
    upstream
        .resolved_subset_tls
        .insert("v1".to_string(), subset_passive_with_cap(Some(20)));

    let config = GatewayConfig {
        proxies: vec![proxy_for_upstream()],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::max_ejection_percent_resolved_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            None,
        ),
        Some(100),
        "an unsubsetted proxy must use the upstream cap even if a subset overlay exists"
    );
}

#[test]
fn subset_overlay_without_max_ejection_does_not_inherit_upstream_cap() {
    // Wholesale-tier invariant: a present subset overlay replaces the
    // upstream tier even when its own cap is `None` (so the cap and the
    // subset's thresholds always come from the SAME tier — never mixed).
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080)],
        HashMap::new(),
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(100),
            ..PassiveHealthCheck::default()
        }),
    });
    upstream
        .resolved_subset_tls
        .insert("v1".to_string(), subset_passive_with_cap(None));

    let config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::max_ejection_percent_resolved_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            None,
        ),
        None,
        "a subset outlierDetection overlay that omits maxEjectionPercent owns the \
         cap wholesale and must not fall back to the upstream cap"
    );
}

#[test]
fn per_port_override_wins_over_subset_max_ejection_cap() {
    // Precedence: per-port (40%) > per-subset (20%) > upstream (100%).
    // A subset-bound proxy whose dispatch lands on a port with its own
    // outlierDetection override must use the PORT cap.
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(40),
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080)],
        port_overrides,
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(100),
            ..PassiveHealthCheck::default()
        }),
    });
    upstream
        .resolved_subset_tls
        .insert("v1".to_string(), subset_passive_with_cap(Some(20)));

    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    // With a live per-port override for port 8080, the caller passes
    // `Some(8080)` — the port cap (40) wins over the subset cap (20).
    assert_eq!(
        LoadBalancerCache::max_ejection_percent_resolved_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            Some(8080),
        ),
        Some(40),
        "a per-port outlierDetection override must win over the subset cap"
    );

    // Without a port signal (`None`), the same subset-bound proxy falls to the
    // subset cap (20), proving the subset tier is between port and upstream.
    assert_eq!(
        LoadBalancerCache::max_ejection_percent_resolved_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            None,
        ),
        Some(20),
        "with no per-port signal the subset cap (not the upstream cap) is used"
    );
}

// ── F5.2 round 1: ejection cap denominator must be the SUBSET candidate pool ─

/// A subset `subset_name` whose membership is every target carrying
/// `(label_key, label_value)` in its tags, with an `outlierDetection` overlay
/// carrying `cap` — wired into BOTH `subsets` (so the LB computes subset
/// membership) and `resolved_subset_tls` (so the cap resolver reaches it).
fn upstream_with_subset_cap(
    targets: Vec<UpstreamTarget>,
    subset_name: &str,
    label_key: &str,
    label_value: &str,
    upstream_cap: Option<u8>,
    subset_cap: Option<u8>,
    port_overrides: HashMap<u16, UpstreamPortOverride>,
) -> Upstream {
    use ferrum_edge::config::types::SubsetDefinition;
    let mut upstream =
        upstream_with_overrides(LoadBalancerAlgorithm::RoundRobin, targets, port_overrides);
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: 1,
            max_ejection_percent: upstream_cap,
            ..PassiveHealthCheck::default()
        }),
    });
    upstream.subsets = Some(vec![SubsetDefinition {
        name: subset_name.to_string(),
        labels: HashMap::from([(label_key.to_string(), label_value.to_string())]),
        traffic_policy: None,
    }]);
    upstream
        .resolved_subset_tls
        .insert(subset_name.to_string(), subset_passive_with_cap(subset_cap));
    upstream
}

/// Build a passive-health context that has the given targets passive-ejected
/// (oldest-first by ascending timestamp) for proxy `p1`, under `cap`.
fn passive_ctx_ejecting<'a>(
    active_unhealthy: &'a DashMap<String, u64>,
    ejected: &[&UpstreamTarget],
    cap: Option<u8>,
) -> HealthContext<'a> {
    let checker = HealthChecker::new();
    let pasv = PassiveHealthCheck {
        unhealthy_threshold: 1,
        max_ejection_percent: cap,
        ..PassiveHealthCheck::default()
    };
    for t in ejected {
        checker.report_response("p1", "test-upstream", t, 500, false, Some(&pasv));
    }
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created")
        .clone();
    for (i, t) in ejected.iter().enumerate() {
        // Deterministic ascending eject timestamps so re-admission (oldest
        // first) is predictable.
        let ejected_at_ms = 100 + i as u64;
        proxy_state.unhealthy.insert(
            target_host_port_key(t),
            ferrum_edge::health_check::PassiveEjection {
                ejected_at_ms,
                recover_at_ms: ejected_at_ms,
                auto_recover: false,
                upstream_id: "test-upstream".to_string(),
                host: t.host.clone(),
                port: t.port,
            },
        );
    }
    HealthContext {
        active_unhealthy,
        proxy_passive: Some(proxy_state),
        max_ejection_percent: cap,
    }
}

#[test]
fn subset_ejection_cap_denominator_is_subset_pool_not_full_upstream() {
    // 10-target upstream; subset 'v1' = the 2 tagged targets. Both subset
    // targets are passive-ejected with subset cap = 50%.
    //   - BUGGY (full-upstream denominator): ceil(10*0.5)=5, 2<=5 ⇒ neither
    //     re-admitted ⇒ subset goes EMPTY (select returns None).
    //   - FIXED (subset denominator): ceil(2*0.5)=1, 2>1 ⇒ exactly 1 re-admitted
    //     ⇒ subset stays available and selectable.
    let mut targets = vec![
        tagged_target("v1-a", 8080, &[("version", "v1")]),
        tagged_target("v1-b", 8080, &[("version", "v1")]),
    ];
    targets.extend((0..8).map(|i| tagged_target(&format!("v2-{i}"), 8080, &[("version", "v2")])));

    let upstream = upstream_with_subset_cap(
        targets.clone(),
        "v1",
        "version",
        "v1",
        Some(100), // upstream cap (would not eject anyone if it were used)
        Some(50),  // subset cap — the one under test
        HashMap::new(),
    );
    let config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    // Eject BOTH subset targets; v1-a has the oldest timestamp so it is the one
    // re-admitted under the subset cap.
    let health = passive_ctx_ejecting(&active_unhealthy, &[&targets[0], &targets[1]], Some(50));

    let selection =
        LoadBalancerCache::select_target_subset_from(&snapshot, "u1", "key", "v1", Some(&health))
            .expect("subset must stay available: the 50% subset cap re-admits 1 of 2 ejected");
    assert!(
        !selection.is_fallback,
        "re-admission under the subset cap is a healthy selection, not a degraded fallback"
    );
    assert_eq!(
        selection.target.host, "v1-a",
        "the earliest-ejected subset target (v1-a) is re-admitted first"
    );

    // Sanity: the cap resolver itself returns the subset cap for this proxy.
    assert_eq!(
        LoadBalancerCache::max_ejection_percent_resolved_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            None,
        ),
        Some(50),
    );
}

#[test]
fn subset_ejection_cap_denominator_is_subset_pool_vec_fallback() {
    // Same property on the >128-target Vec fallback path: a 2-target subset
    // inside a 140-target upstream, both subset targets ejected, subset cap 50%.
    // Full-upstream denominator would be ceil(140*0.5)=70 (eject both); subset
    // denominator is ceil(2*0.5)=1 (re-admit exactly one).
    let mut targets = vec![
        tagged_target("v1-a", 8080, &[("version", "v1")]),
        tagged_target("v1-b", 8080, &[("version", "v1")]),
    ];
    targets.extend((0..140).map(|i| tagged_target(&format!("v2-{i}"), 8080, &[("version", "v2")])));

    let upstream = upstream_with_subset_cap(
        targets.clone(),
        "v1",
        "version",
        "v1",
        Some(100),
        Some(50),
        HashMap::new(),
    );
    let config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = passive_ctx_ejecting(&active_unhealthy, &[&targets[0], &targets[1]], Some(50));

    let selection =
        LoadBalancerCache::select_target_subset_from(&snapshot, "u1", "key", "v1", Some(&health))
            .expect("Vec fallback must scope the subset cap to the subset pool too");
    assert!(!selection.is_fallback);
    assert_eq!(selection.target.host, "v1-a");
}

#[test]
fn port_subset_ejection_cap_denominator_is_subset_intersect_port() {
    // Port+subset: subset 'v1' has 4 tagged targets, but only 2 sit on port
    // 8080 (the dispatch port has its own outlierDetection cap = 50%). The
    // candidate pool for a port+subset dispatch is subset∩port = 2 targets.
    //   - PRE-FIX (port denominator): port 8080 carries 6 targets, so
    //     ceil(6*0.5)=3, 2<=3 ⇒ both subset∩port targets stay ejected ⇒ None.
    //   - FIXED (subset∩port denominator): ceil(2*0.5)=1 ⇒ exactly 1 re-admitted.
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(50),
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );

    // subset∩port (2): v1 on 8080. subset-not-port (2): v1 on 9090.
    // port-not-subset (4): v2 on 8080 — make port 8080 carry 6 total.
    let mut targets = vec![
        tagged_target("v1p-a", 8080, &[("version", "v1")]),
        tagged_target("v1p-b", 8080, &[("version", "v1")]),
        tagged_target("v1q-a", 9090, &[("version", "v1")]),
        tagged_target("v1q-b", 9090, &[("version", "v1")]),
    ];
    targets.extend((0..4).map(|i| tagged_target(&format!("v2p-{i}"), 8080, &[("version", "v2")])));

    let upstream = upstream_with_subset_cap(
        targets.clone(),
        "v1",
        "version",
        "v1",
        Some(100),
        Some(100), // subset cap loose; the PORT cap (50%) is the live tier here
        port_overrides,
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    // Eject the two subset∩port targets (v1p-a oldest).
    let health = passive_ctx_ejecting(&active_unhealthy, &[&targets[0], &targets[1]], Some(50));

    let selection = LoadBalancerCache::select_target_for_port_subset_from(
        &snapshot,
        "u1",
        "key",
        8080,
        "v1",
        Some(&health),
    )
    .expect("port+subset dispatch must size its cap against subset∩port, not the whole port");
    assert!(!selection.is_fallback);
    assert_eq!(
        selection.target.host, "v1p-a",
        "earliest-ejected subset∩port target is re-admitted under the 50% cap over a 2-target pool"
    );
}

// ── F5.2 round 2: subset-retry must exclude the previous target BEFORE the cap ─
//
// The retry-exclusion selectors must drop the excluded (previously tried) target
// from the candidate pool *before* sizing the passive ejection cap. If the cap
// is computed over the full subset first and the excluded target is then cleared,
// a readmission budget spent on the excluded target leaves the actual retry
// candidate ejected — wrongly returning `None`.

#[test]
fn upstream_retry_excludes_previous_target_before_ejection_cap() {
    // No-subset retry path: all three targets are passive-ejected, cap = 34%,
    // and the retry excludes the oldest ejected target. Capping before the
    // exclusion spends the readmission on the excluded target and leaves no
    // retry candidate; excluding first readmits host-b.
    let targets = vec![
        target("host-a", 8080),
        target("host-b", 8080),
        target("host-c", 8080),
    ];
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        HashMap::new(),
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: 1,
            max_ejection_percent: Some(34),
            ..PassiveHealthCheck::default()
        }),
    });
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = passive_ctx_ejecting(
        &active_unhealthy,
        &[&targets[0], &targets[1], &targets[2]],
        Some(34),
    );

    let retry = LoadBalancerCache::select_next_target_from(
        &snapshot,
        "u1",
        "retry",
        &targets[0],
        Some(&health),
    )
    .expect("upstream retry should re-admit a remaining candidate after exclusion");

    assert_eq!(retry.host, "host-b");
    assert_ne!(retry.host, "host-a");
}

#[test]
fn port_retry_excludes_previous_target_before_ejection_cap() {
    // Same bug shape on the port-only retry path. The port override owns the
    // passive cap; retry must exclude before sizing that port candidate pool.
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(34),
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );

    let targets = vec![
        target("port-a", 8080),
        target("port-b", 8080),
        target("port-c", 8080),
        target("other-port", 9090),
    ];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = passive_ctx_ejecting(
        &active_unhealthy,
        &[&targets[0], &targets[1], &targets[2]],
        Some(34),
    );

    let retry = LoadBalancerCache::select_next_target_for_port_from(
        &snapshot,
        "u1",
        "retry",
        8080,
        &targets[0],
        Some(&health),
    )
    .expect("port retry should re-admit a remaining same-port candidate after exclusion");

    assert_eq!(retry.host, "port-b");
    assert_eq!(retry.port, 8080);
    assert_ne!(retry.host, "port-a");
}

#[test]
fn subset_retry_excludes_previous_target_before_ejection_cap() {
    // Subset 'v1' = 3 tagged targets [a, b, c], ALL passive-ejected (a oldest,
    // then b, then c), subset cap = 34%. The retry excludes 'v1-a' — the
    // earliest-ejected one, which the cap would re-admit first.
    //   - BUGGY (cap over full subset, THEN clear excluded): ceil(3*0.34)=2 ⇒
    //     re-admit 1 ⇒ that one is v1-a (oldest) ⇒ clearing v1-a afterwards
    //     empties the candidate set ⇒ returns None even though v1-b/v1-c remain.
    //   - FIXED (exclude v1-a FIRST, then cap over {v1-b, v1-c}): ceil(2*0.34)=1
    //     ⇒ re-admit 1 ⇒ v1-b (oldest remaining) is returned.
    let targets = vec![
        tagged_target("v1-a", 8080, &[("version", "v1")]),
        tagged_target("v1-b", 8080, &[("version", "v1")]),
        tagged_target("v1-c", 8080, &[("version", "v1")]),
    ];

    let upstream = upstream_with_subset_cap(
        targets.clone(),
        "v1",
        "version",
        "v1",
        Some(100), // upstream cap (loose; not the live tier)
        Some(34),  // subset cap under test
        HashMap::new(),
    );
    let config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    // Eject all three (v1-a oldest, v1-c newest).
    let health = passive_ctx_ejecting(
        &active_unhealthy,
        &[&targets[0], &targets[1], &targets[2]],
        Some(34),
    );

    let retry = LoadBalancerCache::select_next_target_subset_from(
        &snapshot,
        "u1",
        "retry",
        "v1",
        &targets[0], // exclude v1-a, the earliest-ejected candidate
        Some(&health),
    )
    .expect(
        "subset retry must re-admit a REMAINING candidate after excluding the previous target; \
         excluding before the cap prevents the budget being spent on the excluded target",
    );
    assert_eq!(
        retry.host, "v1-b",
        "the earliest-ejected REMAINING target (v1-b) is re-admitted for the retry"
    );
    assert_ne!(
        retry.host, "v1-a",
        "the excluded previous target must never be returned by the retry"
    );
}

#[test]
fn port_subset_retry_excludes_previous_target_before_ejection_cap() {
    // Same property on the port+subset retry path. subset∩port (3 on 8080) all
    // ejected, subset cap = 34%, retry excludes the earliest-ejected one.
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(34),
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );

    // subset∩port (3): v1 on 8080. Add v2 on 8080 + v1 on 9090 so neither the
    // port pool nor the bare subset pool equals the intersection.
    let mut targets = vec![
        tagged_target("v1p-a", 8080, &[("version", "v1")]),
        tagged_target("v1p-b", 8080, &[("version", "v1")]),
        tagged_target("v1p-c", 8080, &[("version", "v1")]),
        tagged_target("v1q-a", 9090, &[("version", "v1")]),
    ];
    targets.extend((0..3).map(|i| tagged_target(&format!("v2p-{i}"), 8080, &[("version", "v2")])));

    let upstream = upstream_with_subset_cap(
        targets.clone(),
        "v1",
        "version",
        "v1",
        Some(100),
        Some(100), // subset cap loose; the PORT cap (34%) is the live tier
        port_overrides,
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    // Eject the three subset∩port targets (v1p-a oldest, v1p-c newest).
    let health = passive_ctx_ejecting(
        &active_unhealthy,
        &[&targets[0], &targets[1], &targets[2]],
        Some(34),
    );

    let retry = LoadBalancerCache::select_next_target_for_port_subset_from(
        &snapshot,
        "u1",
        "retry",
        8080,
        "v1",
        &targets[0], // exclude v1p-a, the earliest-ejected subset∩port candidate
        Some(&health),
    )
    .expect(
        "port+subset retry must re-admit a REMAINING subset∩port candidate after excluding the \
         previous target, sizing the cap over the post-exclusion candidate pool",
    );
    assert_eq!(
        retry.host, "v1p-b",
        "earliest-ejected REMAINING subset∩port target (v1p-b) is re-admitted for the retry"
    );
    assert_eq!(
        retry.port, 8080,
        "retry must stay within the dispatch port's subset∩port pool"
    );
}

// ── Stream-path per-port policy tests ────────────────────────────────────────
// These tests verify the stream-family (TCP/UDP/DTLS) target-selection logic
// that was added to mirror the HTTP dispatch path's per-port policy engagement.
// The stream paths use `initial_dispatch_port_override_from` to determine
// whether a single dispatch port is resolvable, then call
// `select_target_for_port_from` (or the subset variant) when it is — falling
// back to the plain `select_target_from` otherwise.

/// A stream upstream where all targets share one port and a per-port algorithm
/// override is in effect should have its per-port algorithm engaged.
#[test]
fn stream_path_engages_per_port_algorithm_when_all_targets_on_one_port() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        9000,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let upstream = upstream_with_overrides(
        // Upstream-level uses Random; per-port 9000 overrides to RoundRobin.
        LoadBalancerAlgorithm::Random,
        vec![target("a", 9000), target("b", 9000), target("c", 9000)],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    // All targets are on port 9000 → initial_dispatch_port_override is 9000.
    let dispatch_port = LoadBalancerCache::initial_dispatch_port_override_from(&snapshot, "u1");
    assert_eq!(
        dispatch_port, 9000,
        "single-port upstream must expose its port as the initial dispatch override"
    );

    // Simulate the stream-path selection: use the per-port lane.
    let results: Vec<String> = (0..3)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(
                &snapshot,
                "u1",
                "stream-key",
                dispatch_port,
                None,
            )
            .expect("selection must succeed with healthy targets")
            .target
            .host
            .clone()
        })
        .collect();

    // RoundRobin counter is independent of the parent (Random) counter, so
    // three consecutive calls walk {a, b, c} contiguously from the calling
    // shard's phase offset (absolute start is not stable across threads).
    assert_contiguous_round_robin(&results, &["a", "b", "c"]);
}

/// A stream upstream whose targets span multiple ports must NOT engage
/// the per-port lane — the hint resolves to zero and the stream path falls
/// back to upstream-level selection (preserving pre-PR behaviour).
#[test]
fn stream_path_hint_is_zero_for_mixed_port_upstream() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(9000, UpstreamPortOverride::default());

    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 9000), target("b", 9100)], // two different ports
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let dispatch_port = LoadBalancerCache::initial_dispatch_port_override_from(&snapshot, "u1");
    assert_eq!(
        dispatch_port, 0,
        "mixed-port upstream must not resolve a pre-selection dispatch port"
    );
}

/// Pinning the port-pool confinement invariant: when a stream upstream has a
/// per-port override, explicit `select_target_for_port_from` returns only
/// targets whose port matches the requested port.  This is a PRIMITIVE-level
/// invariant that applies to both HTTP and stream selection; the stream paths
/// engage it when `initial_dispatch_port_override` is non-zero.
#[test]
fn stream_path_per_port_selection_excludes_off_port_targets() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        9000,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    // One target on port 9000 and one on 9001. Only 9000 has an override
    // entry; `initial_dispatch_port_override` returns 0 (mixed-port) so the
    // per-port lane is NOT engaged pre-selection. This test confirms the
    // invariant: the hint stays 0, and the plain select_target_from is used.
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 9000), target("b", 9001)],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let dispatch_port = LoadBalancerCache::initial_dispatch_port_override_from(&snapshot, "u1");
    assert_eq!(
        dispatch_port, 0,
        "mixed-port upstream: per-port lane must not engage pre-selection"
    );

    // Explicit per-port selection on 9000 only returns targets on that port.
    let selected =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "key", 9000, None)
            .expect("port-9000 target must be selectable");
    assert_eq!(
        selected.target.host, "a",
        "per-port selection must only return the 9000-port target"
    );
    assert_eq!(selected.target.port, 9000);
}

/// Pin the per-port LB primitive's health-context behavior: when a
/// `HealthContext` IS provided, ejected targets are excluded by the
/// `maxEjectionPercent` cap. This is the path HTTP dispatch and stream
/// selection both take.
#[test]
fn per_port_lane_filters_ejected_targets_when_health_context_provided() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        9000,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(50), // allows 1 of 2 to be ejected
                ..PassiveHealthCheck::default()
            }),
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let targets_list = vec![target("a", 9000), target("b", 9000)];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets_list.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    // Active-unhealthy keys use the upstream-scoped format "upstream_id::host:port".
    // This is how HTTP dispatch records active ejection state (via `target_key`).
    active_unhealthy.insert("u1::a:9000".to_string(), 0);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: Some(50),
    };

    let dispatch_port = LoadBalancerCache::initial_dispatch_port_override_from(&snapshot, "u1");
    assert_eq!(
        dispatch_port, 9000,
        "single-port upstream resolves dispatch port"
    );

    // Calling select_target_for_port_from WITH a health context must exclude
    // the ejected target.
    for _ in 0..4 {
        let selected = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "u1",
            "http-key",
            dispatch_port,
            Some(&health),
        )
        .expect("healthy target 'b' must always be available");
        assert_eq!(
            selected.target.host, "b",
            "ejected target 'a' must not be selected when health context is provided"
        );
    }
}

/// Pin the low-level primitive behavior for callers that intentionally omit a
/// health context: ejection state has no effect unless a `HealthContext` is
/// supplied. Stream call sites now supply one; this test remains here to keep
/// the primitive's explicit `None` semantics stable.
#[test]
fn per_port_selection_ignores_ejection_without_health_context() {
    // Same upstream setup as the companion test above.
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        9000,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(50),
                ..PassiveHealthCheck::default()
            }),
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let targets_list = vec![target("a", 9000), target("b", 9000)];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets_list.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    // Record ejection for "a" using the upstream-scoped key format, then call
    // the primitive with `None` so this map is never consulted.
    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    active_unhealthy.insert("u1::a:9000".to_string(), 0);

    let dispatch_port = LoadBalancerCache::initial_dispatch_port_override_from(&snapshot, "u1");
    assert_eq!(dispatch_port, 9000);

    // With no health context, ejection state is NOT consulted. Both "a" and
    // "b" remain selectable, even though "a" is ejected above.
    let mut saw_a = false;
    let mut saw_b = false;
    for i in 0..8 {
        let selected = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "u1",
            &format!("stream-key-{i}"),
            dispatch_port,
            None, // no health context
        )
        .expect("all targets selectable when no health context is provided");
        match selected.target.host.as_str() {
            "a" => saw_a = true,
            "b" => saw_b = true,
            other => panic!("unexpected host: {other}"),
        }
    }
    assert!(
        saw_a,
        "ejected target 'a' is still selectable when the caller supplies no health context"
    );
    assert!(saw_b, "target 'b' must also be selectable");
}

/// A stream upstream with a subset and a single port engages the
/// per-port-subset lane (mirrors HTTP subset routing with a port hint).
#[test]
fn stream_path_per_port_subset_engages_when_single_port() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        9000,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::Random,
        vec![
            tagged_target("a", 9000, &[("env", "prod")]),
            tagged_target("b", 9000, &[("env", "prod")]),
            tagged_target("c", 9000, &[("env", "staging")]),
        ],
        port_overrides,
    );
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "prod".to_string(),
        labels: HashMap::from([("env".to_string(), "prod".to_string())]),
        traffic_policy: None,
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let dispatch_port = LoadBalancerCache::initial_dispatch_port_override_from(&snapshot, "u1");
    assert_eq!(dispatch_port, 9000);

    // Simulate the stream subset path: select_target_for_port_subset_from.
    let results: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_subset_from(
                &snapshot,
                "u1",
                "stream-subset-key",
                dispatch_port,
                "prod",
                None,
            )
            .expect("prod subset has healthy targets")
            .target
            .host
            .clone()
        })
        .collect();

    // Only "a" and "b" (prod subset) must be selected; "c" (staging) must not.
    for host in &results {
        assert!(
            host == "a" || host == "b",
            "per-port subset selection must not escape to non-subset target 'c', got '{host}'"
        );
    }
}

/// The per-port lane engages the port's LB algorithm independently of the
/// upstream-level algorithm.  Specifically: an upstream-level `RoundRobin`
/// upstream with a per-port `ConsistentHashing` override (inheriting the
/// upstream's `hash_on` key) must route the SAME ctx_key to the SAME target
/// on every call via the port lane, while the upstream-level lane rotates.
/// This exercises a real per-port policy knob beyond mere port-pool confinement
/// and applies to both HTTP dispatch and the stream paths (which call
/// `select_target_for_port_from` when `initial_dispatch_port_override` is
/// non-zero).
#[test]
fn per_port_consistent_hash_overrides_upstream_round_robin() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        9000,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
            // No per-port hash_on: inherits the upstream's `hash_on` key
            // (cookie:srv) via `get_hash_on_strategy_for_port_from` semantics.
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 9000), target("b", 9000), target("c", 9000)],
        port_overrides,
    );
    // Set a hash_on key at the upstream level; the per-port ConsistentHashing
    // override without its own hash_on inherits it.
    upstream.hash_on = Some("header:x-session-id".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    // The per-port lane must engage ConsistentHashing (inherited hash key),
    // so the same ctx_key always selects the same target.
    let first = LoadBalancerCache::select_target_for_port_from(
        &snapshot,
        "u1",
        "sticky-session-abc",
        9000,
        None,
    )
    .expect("port selection must succeed")
    .target
    .host
    .clone();

    for _ in 0..4 {
        let again = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "u1",
            "sticky-session-abc",
            9000,
            None,
        )
        .expect("port selection must succeed")
        .target
        .host
        .clone();
        assert_eq!(
            again, first,
            "per-port ConsistentHashing must return the same target for the same ctx_key"
        );
    }

    // The upstream-level lane uses RoundRobin and MUST rotate across targets,
    // proving the two lanes are independent. Absolute starting bucket depends
    // on the calling thread's selection-counter shard phase.
    let rr: Vec<String> = (0..3)
        .map(|_| {
            LoadBalancerCache::select_target_from(&snapshot, "u1", "rr-key", None)
                .expect("upstream-level selection must succeed")
                .target
                .host
                .clone()
        })
        .collect();
    assert_contiguous_round_robin(&rr, &["a", "b", "c"]);
}

#[test]
fn port_subset_selection_unchanged_after_alloc_free_mask_refactor() {
    // Guard: the ≤128-target port+subset selection (now built from an alloc-free
    // subset∩port stack-`u128` mask instead of a heap index `Vec`) still selects
    // only targets inside subset∩port, with healthy targets preferred over an
    // ejected one. v1 on 8080 = {a (ejected), b (healthy)}; v1 on 9090 and v2 on
    // 8080 must never be selected for a port-8080 + subset-v1 dispatch.
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: Some(100), // loose: keep the ejected one out
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );
    let mut targets = vec![
        tagged_target("v1p-a", 8080, &[("version", "v1")]),
        tagged_target("v1p-b", 8080, &[("version", "v1")]),
        tagged_target("v1q-a", 9090, &[("version", "v1")]),
    ];
    targets.extend((0..3).map(|i| tagged_target(&format!("v2p-{i}"), 8080, &[("version", "v2")])));

    let upstream = upstream_with_subset_cap(
        targets.clone(),
        "v1",
        "version",
        "v1",
        Some(100),
        Some(100),
        port_overrides,
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream_subset("v1")],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    // v1p-a ejected under a 100% cap ⇒ stays out; only v1p-b is healthy.
    let health = passive_ctx_ejecting(&active_unhealthy, &[&targets[0]], Some(100));

    for i in 0..10 {
        let selection = LoadBalancerCache::select_target_for_port_subset_from(
            &snapshot,
            "u1",
            &format!("key-{i}"),
            8080,
            "v1",
            Some(&health),
        )
        .expect("a healthy subset∩port target is always available");
        assert_eq!(
            selection.target.host, "v1p-b",
            "only the healthy subset∩port target may be selected"
        );
        assert!(!selection.is_fallback);
    }
}
