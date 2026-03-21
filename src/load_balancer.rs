//! Load balancer for distributing requests across upstream targets.
//!
//! Supports multiple algorithms: round-robin, weighted round-robin,
//! least connections, consistent hashing, and random.

use crate::config::types::{GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Load balancer cache, rebuilt atomically on config change.
pub struct LoadBalancerCache {
    balancers: ArcSwap<HashMap<String, LoadBalancer>>,
}

impl LoadBalancerCache {
    pub fn new(config: &GatewayConfig) -> Self {
        let balancers = Self::build_balancers(config);
        Self {
            balancers: ArcSwap::new(Arc::new(balancers)),
        }
    }

    pub fn rebuild(&self, config: &GatewayConfig) {
        let balancers = Self::build_balancers(config);
        self.balancers.store(Arc::new(balancers));
    }

    fn build_balancers(config: &GatewayConfig) -> HashMap<String, LoadBalancer> {
        let mut map = HashMap::new();
        for upstream in &config.upstreams {
            map.insert(
                upstream.id.clone(),
                LoadBalancer::new(
                    upstream.algorithm,
                    &upstream.targets,
                    upstream.hash_on.clone(),
                ),
            );
        }
        map
    }

    /// Look up an upstream by ID.
    #[allow(dead_code)]
    pub fn get_upstream<'a>(
        &self,
        config: &'a GatewayConfig,
        upstream_id: &str,
    ) -> Option<&'a Upstream> {
        config.upstreams.iter().find(|u| u.id == upstream_id)
    }

    /// Select a target from the upstream, filtering out unhealthy targets.
    pub fn select_target(
        &self,
        upstream_id: &str,
        ctx_key: &str,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<UpstreamTarget> {
        let balancers = self.balancers.load();
        let balancer = balancers.get(upstream_id)?;
        balancer.select(ctx_key, unhealthy)
    }

    /// Select next target, excluding a previously tried target (for retries).
    pub fn select_next_target(
        &self,
        upstream_id: &str,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<UpstreamTarget> {
        let balancers = self.balancers.load();
        let balancer = balancers.get(upstream_id)?;
        balancer.select_excluding(ctx_key, exclude, unhealthy)
    }

    /// Record that a connection was opened to a target (for least-connections).
    pub fn record_connection_start(&self, upstream_id: &str, target: &UpstreamTarget) {
        let balancers = self.balancers.load();
        if let Some(balancer) = balancers.get(upstream_id) {
            let key = target_key(target);
            balancer
                .active_connections
                .entry(key)
                .or_insert_with(|| AtomicI64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record that a connection was closed to a target (for least-connections).
    pub fn record_connection_end(&self, upstream_id: &str, target: &UpstreamTarget) {
        let balancers = self.balancers.load();
        if let Some(balancer) = balancers.get(upstream_id) {
            let key = target_key(target);
            if let Some(count) = balancer.active_connections.get(&key) {
                count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

fn target_key(target: &UpstreamTarget) -> String {
    format!("{}:{}", target.host, target.port)
}

/// Per-upstream load balancer with algorithm-specific state.
struct LoadBalancer {
    targets: Vec<UpstreamTarget>,
    algorithm: LoadBalancerAlgorithm,
    /// Round-robin counter.
    rr_counter: AtomicU64,
    /// Weighted round-robin state (smooth weighted round-robin).
    wrr_weights: Vec<AtomicI64>,
    /// Active connections per target (for least-connections).
    active_connections: DashMap<String, AtomicI64>,
    /// Consistent hash ring (sorted hash values -> target index).
    hash_ring: Vec<(u64, usize)>,
    /// Hash on field (e.g., "ip", "header:X-User-Id", "consumer").
    hash_on: Option<String>,
}

impl LoadBalancer {
    fn new(
        algorithm: LoadBalancerAlgorithm,
        targets: &[UpstreamTarget],
        hash_on: Option<String>,
    ) -> Self {
        let wrr_weights: Vec<AtomicI64> = targets.iter().map(|_| AtomicI64::new(0)).collect();

        // Build consistent hash ring with virtual nodes
        let mut hash_ring = Vec::new();
        if algorithm == LoadBalancerAlgorithm::ConsistentHashing {
            for (idx, target) in targets.iter().enumerate() {
                // 150 virtual nodes per target for better distribution
                for vnode in 0..150 {
                    let key = format!("{}:{}:{}", target.host, target.port, vnode);
                    let mut hasher = DefaultHasher::new();
                    key.hash(&mut hasher);
                    hash_ring.push((hasher.finish(), idx));
                }
            }
            hash_ring.sort_by_key(|&(hash, _)| hash);
        }

        Self {
            targets: targets.to_vec(),
            algorithm,
            rr_counter: AtomicU64::new(0),
            wrr_weights,
            active_connections: DashMap::new(),
            hash_ring,
            hash_on,
        }
    }

    fn healthy_targets(
        &self,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Vec<(usize, &UpstreamTarget)> {
        self.targets
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                if let Some(unhealthy_set) = unhealthy {
                    !unhealthy_set.contains_key(&target_key(t))
                } else {
                    true
                }
            })
            .collect()
    }

    fn select(
        &self,
        ctx_key: &str,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<UpstreamTarget> {
        let healthy = self.healthy_targets(unhealthy);
        if healthy.is_empty() {
            // Fallback: try all targets if everything is unhealthy
            if self.targets.is_empty() {
                return None;
            }
            return self.select_from_all(ctx_key);
        }

        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                let target_idx = idx % healthy.len();
                Some(healthy[target_idx].1.clone())
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr(&healthy),
            LoadBalancerAlgorithm::LeastConnections => self.select_least_connections(&healthy),
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash(ctx_key, &healthy)
            }
            LoadBalancerAlgorithm::Random => {
                // Use a simple counter-based pseudo-random to avoid rand dependency
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let mut hasher = DefaultHasher::new();
                idx.hash(&mut hasher);
                let hash = hasher.finish() as usize;
                Some(healthy[hash % healthy.len()].1.clone())
            }
        }
    }

    fn select_from_all(&self, ctx_key: &str) -> Option<UpstreamTarget> {
        let all: Vec<(usize, &UpstreamTarget)> = self.targets.iter().enumerate().collect();
        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin | LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                Some(all[idx % all.len()].1.clone())
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr(&all),
            LoadBalancerAlgorithm::LeastConnections => self.select_least_connections(&all),
            LoadBalancerAlgorithm::ConsistentHashing => self.select_consistent_hash(ctx_key, &all),
        }
    }

    fn select_excluding(
        &self,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<UpstreamTarget> {
        let exclude_key = target_key(exclude);
        let healthy: Vec<(usize, &UpstreamTarget)> = self
            .healthy_targets(unhealthy)
            .into_iter()
            .filter(|(_, t)| target_key(t) != exclude_key)
            .collect();

        if healthy.is_empty() {
            // If no other healthy targets, try any target except excluded
            let fallback: Vec<(usize, &UpstreamTarget)> = self
                .targets
                .iter()
                .enumerate()
                .filter(|(_, t)| target_key(t) != exclude_key)
                .collect();
            if fallback.is_empty() {
                return None;
            }
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(fallback[idx % fallback.len()].1.clone());
        }

        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin | LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                Some(healthy[idx % healthy.len()].1.clone())
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr(&healthy),
            LoadBalancerAlgorithm::LeastConnections => self.select_least_connections(&healthy),
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash(ctx_key, &healthy)
            }
        }
    }

    /// Smooth weighted round-robin (NGINX algorithm).
    fn select_wrr(&self, candidates: &[(usize, &UpstreamTarget)]) -> Option<UpstreamTarget> {
        if candidates.is_empty() {
            return None;
        }

        let total_weight: i64 = candidates.iter().map(|(_, t)| t.weight as i64).sum();
        if total_weight == 0 {
            // All weights zero, fall back to simple round-robin
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(candidates[idx % candidates.len()].1.clone());
        }

        // Add effective weight to current weight for each candidate
        let mut best_idx = 0;
        let mut best_current = i64::MIN;

        for (i, (orig_idx, target)) in candidates.iter().enumerate() {
            let current = self.wrr_weights[*orig_idx]
                .fetch_add(target.weight as i64, Ordering::Relaxed)
                + target.weight as i64;
            if current > best_current {
                best_current = current;
                best_idx = i;
            }
        }

        // Subtract total weight from the selected candidate
        let (orig_idx, _) = candidates[best_idx];
        self.wrr_weights[orig_idx].fetch_sub(total_weight, Ordering::Relaxed);

        Some(candidates[best_idx].1.clone())
    }

    /// Select target with least active connections.
    fn select_least_connections(
        &self,
        candidates: &[(usize, &UpstreamTarget)],
    ) -> Option<UpstreamTarget> {
        if candidates.is_empty() {
            return None;
        }

        let mut min_conns = i64::MAX;
        let mut best = &candidates[0];

        for candidate in candidates {
            let key = target_key(candidate.1);
            let conns = self
                .active_connections
                .get(&key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            if conns < min_conns {
                min_conns = conns;
                best = candidate;
            }
        }

        Some(best.1.clone())
    }

    /// Consistent hash: find the target on the hash ring closest to the hash of ctx_key.
    fn select_consistent_hash(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &UpstreamTarget)],
    ) -> Option<UpstreamTarget> {
        if candidates.is_empty() {
            return None;
        }

        let key = match &self.hash_on {
            Some(_) => ctx_key.to_string(),
            None => ctx_key.to_string(),
        };

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        // Create set of valid original indices
        let valid_indices: std::collections::HashSet<usize> =
            candidates.iter().map(|(idx, _)| *idx).collect();

        // Binary search on the ring
        let pos = match self.hash_ring.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(p) => p,
            Err(p) => p % self.hash_ring.len().max(1),
        };

        // Walk the ring from pos to find a valid (healthy) target
        for i in 0..self.hash_ring.len() {
            let ring_idx = (pos + i) % self.hash_ring.len();
            let target_idx = self.hash_ring[ring_idx].1;
            if valid_indices.contains(&target_idx) {
                return Some(self.targets[target_idx].clone());
            }
        }

        // Shouldn't happen if candidates is non-empty
        Some(candidates[0].1.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let t = lb.select("", None).unwrap();
            *counts.entry(t.host.clone()).or_insert(0) += 1;
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
            let t = lb.select("", None).unwrap();
            *counts.entry(t.host.clone()).or_insert(0) += 1;
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
            let t = lb.select("user-123", None).unwrap();
            assert_eq!(t.host, first.host);
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
        let t = lb.select("", None).unwrap();
        assert_eq!(t.host, "host1");
    }

    #[test]
    fn test_unhealthy_targets_filtered() {
        let targets = make_targets(3);
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin, &targets, None);

        let unhealthy: DashMap<String, u64> = DashMap::new();
        unhealthy.insert("host0:8080".to_string(), 0);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let t = lb.select("", Some(&unhealthy)).unwrap();
            seen.insert(t.host.clone());
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

        // Should still return a target (fallback)
        let t = lb.select("", Some(&unhealthy));
        assert!(t.is_some());
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
}
