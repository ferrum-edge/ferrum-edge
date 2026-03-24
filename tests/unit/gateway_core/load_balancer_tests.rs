//! Tests for load balancer module

use dashmap::DashMap;
use ferrum_gateway::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget,
};
use ferrum_gateway::load_balancer::{LoadBalancer, LoadBalancerCache, target_key};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

fn make_targets(n: usize) -> Vec<UpstreamTarget> {
    (0..n)
        .map(|i| UpstreamTarget {
            host: format!("host{}", i),
            port: 8080,
            weight: 1,
            tags: HashMap::new(),
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
        },
        UpstreamTarget {
            host: "light".into(),
            port: 8080,
            weight: 1,
            tags: HashMap::new(),
        },
    ]
}

#[test]
fn test_round_robin_distributes_evenly() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin, &targets, None);

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
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::WeightedRoundRobin, &targets, None);

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
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::ConsistentHashing, &targets, None);

    let first = lb.select("user-123", None).unwrap();
    for _ in 0..100 {
        let sel = lb.select("user-123", None).unwrap();
        assert_eq!(sel.target.host, first.target.host);
    }
}

#[test]
fn test_least_connections_prefers_least_loaded() {
    let targets = make_targets(2);
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::LeastConnections, &targets, None);

    // Simulate 5 connections to host0
    for _ in 0..5 {
        lb.active_connections
            .entry(target_key(&targets[0]))
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
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin, &targets, None);

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert("host0:8080".to_string(), 0);

    let mut seen = std::collections::HashSet::new();
    for _ in 0..100 {
        let sel = lb.select("", Some(&unhealthy)).unwrap();
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
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin, &targets, None);

    let unhealthy: DashMap<String, u64> = DashMap::new();
    unhealthy.insert("host0:8080".to_string(), 0);
    unhealthy.insert("host1:8080".to_string(), 0);

    // Should still return a target (fallback) and mark it as degraded
    let sel = lb.select("", Some(&unhealthy));
    assert!(sel.is_some());
    assert!(
        sel.unwrap().is_fallback,
        "All-unhealthy selection should be marked as fallback"
    );
}

#[test]
fn test_select_excluding_skips_target() {
    let targets = make_targets(3);
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin, &targets, None);

    let exclude = targets[0].clone();
    for _ in 0..100 {
        let t = lb.select_excluding("", &exclude, None).unwrap();
        assert_ne!(t.host, "host0");
    }
}

#[test]
fn test_empty_targets() {
    let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin, &[], None);
    assert!(lb.select("", None).is_none());
}

#[test]
fn test_load_balancer_cache() {
    let config = GatewayConfig {
        version: "1".to_string(),
        upstreams: vec![Upstream {
            id: "us1".into(),
            name: Some("test".into()),
            targets: make_targets(2),
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            health_checks: None,
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
