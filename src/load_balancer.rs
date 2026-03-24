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

/// Result of a target selection, indicating whether the selection was from
/// healthy targets or a degraded-mode fallback (all targets were unhealthy).
#[derive(Debug, Clone)]
pub struct TargetSelection {
    pub target: UpstreamTarget,
    /// True when all targets were marked unhealthy and this selection is a
    /// best-effort fallback. Callers should propagate this as an
    /// `X-Gateway-Upstream-Status: degraded` response header so clients
    /// and ops teams can distinguish degraded-mode routing from normal routing.
    pub is_fallback: bool,
}

/// Load balancer cache, rebuilt atomically on config change.
///
/// Individual `LoadBalancer` instances are wrapped in `Arc` so that
/// incremental updates can clone the HashMap cheaply (just Arc pointer
/// copies) and only allocate new `LoadBalancer` instances for changed
/// upstreams. Unchanged upstreams keep their exact same instance —
/// round-robin counters, WRR weights, active connection counts, and
/// consistent hash rings are all preserved.
pub struct LoadBalancerCache {
    balancers: ArcSwap<HashMap<String, Arc<LoadBalancer>>>,
    /// O(1) upstream lookup by ID (avoids linear scan of config.upstreams).
    upstreams: ArcSwap<HashMap<String, Arc<Upstream>>>,
}

impl LoadBalancerCache {
    pub fn new(config: &GatewayConfig) -> Self {
        let balancers = Self::build_balancers(config);
        let upstreams = Self::build_upstream_index(config);
        Self {
            balancers: ArcSwap::new(Arc::new(balancers)),
            upstreams: ArcSwap::new(Arc::new(upstreams)),
        }
    }

    pub fn rebuild(&self, config: &GatewayConfig) {
        let balancers = Self::build_balancers(config);
        let upstreams = Self::build_upstream_index(config);
        self.balancers.store(Arc::new(balancers));
        self.upstreams.store(Arc::new(upstreams));
    }

    fn build_balancers(config: &GatewayConfig) -> HashMap<String, Arc<LoadBalancer>> {
        let mut map = HashMap::with_capacity(config.upstreams.len());
        for upstream in &config.upstreams {
            map.insert(
                upstream.id.clone(),
                Arc::new(LoadBalancer::new(
                    upstream.algorithm,
                    &upstream.targets,
                    upstream.hash_on.clone(),
                )),
            );
        }
        map
    }

    fn build_upstream_index(config: &GatewayConfig) -> HashMap<String, Arc<Upstream>> {
        let mut map = HashMap::with_capacity(config.upstreams.len());
        for upstream in &config.upstreams {
            map.insert(upstream.id.clone(), Arc::new(upstream.clone()));
        }
        map
    }

    /// Incrementally update only the changed upstreams.
    ///
    /// Clones the current `HashMap<String, Arc<LoadBalancer>>` (cheap — just
    /// Arc pointer copies for all 10k entries), then:
    /// - Removes deleted upstreams
    /// - Creates fresh `LoadBalancer` instances only for added/modified upstreams
    /// - Unchanged upstreams keep their exact same `Arc<LoadBalancer>`, preserving
    ///   round-robin counters, WRR weights, active connection counts, and hash rings
    pub fn apply_delta(
        &self,
        full_new_config: &GatewayConfig,
        added: &[Upstream],
        removed_ids: &[String],
        modified: &[Upstream],
    ) {
        if added.is_empty() && removed_ids.is_empty() && modified.is_empty() {
            return;
        }

        // Clone the current map — O(n) Arc pointer copies, no LoadBalancer cloning
        let mut new_balancers = self.balancers.load().as_ref().clone();

        // Remove deleted upstreams
        for id in removed_ids {
            new_balancers.remove(id);
        }

        // Create fresh LoadBalancer instances only for added/modified upstreams
        for upstream in added.iter().chain(modified.iter()) {
            new_balancers.insert(
                upstream.id.clone(),
                Arc::new(LoadBalancer::new(
                    upstream.algorithm,
                    &upstream.targets,
                    upstream.hash_on.clone(),
                )),
            );
        }

        // Upstream index is cheap to rebuild (just Arc<Upstream> clones)
        let new_upstream_idx = Self::build_upstream_index(full_new_config);

        self.balancers.store(Arc::new(new_balancers));
        self.upstreams.store(Arc::new(new_upstream_idx));
    }

    /// O(1) lookup of an upstream by ID from the pre-built index.
    pub fn get_upstream(&self, upstream_id: &str) -> Option<Arc<Upstream>> {
        let idx = self.upstreams.load();
        idx.get(upstream_id).cloned()
    }

    /// Select a target from the upstream, filtering out unhealthy targets.
    ///
    /// Returns a [`TargetSelection`] indicating whether the target came from
    /// the healthy pool or is a degraded-mode fallback (all targets unhealthy).
    pub fn select_target(
        &self,
        upstream_id: &str,
        ctx_key: &str,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<TargetSelection> {
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
            let key = balancer.find_target_key(target).unwrap_or("");
            if key.is_empty() {
                return;
            }
            // Fast path: get() uses a shared read lock. entry() takes a write
            // lock and clones the key — avoid it when the counter already exists.
            if let Some(counter) = balancer.active_connections.get(key) {
                counter.fetch_add(1, Ordering::Relaxed);
            } else {
                balancer
                    .active_connections
                    .entry(key.to_owned())
                    .or_insert_with(|| AtomicI64::new(0))
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record that a connection was closed to a target (for least-connections).
    pub fn record_connection_end(&self, upstream_id: &str, target: &UpstreamTarget) {
        let balancers = self.balancers.load();
        if let Some(balancer) = balancers.get(upstream_id) {
            let key = balancer.find_target_key(target).unwrap_or("");
            if key.is_empty() {
                return;
            }
            if let Some(count) = balancer.active_connections.get(key) {
                let _ = count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    if v > 0 { Some(v - 1) } else { None }
                });
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
    /// Pre-computed "host:port" keys for each target, avoiding format!() per request.
    target_keys: Vec<String>,
    algorithm: LoadBalancerAlgorithm,
    /// Round-robin counter.
    rr_counter: AtomicU64,
    /// Weighted round-robin state (smooth weighted round-robin).
    /// Protected by a mutex to prevent weight drift under concurrency.
    /// The critical section is sub-microsecond (weight arithmetic only).
    wrr_state: std::sync::Mutex<Vec<i64>>,
    /// Active connections per target (for least-connections).
    active_connections: DashMap<String, AtomicI64>,
    /// Consistent hash ring (sorted hash values -> target index).
    hash_ring: Vec<(u64, usize)>,
}

impl LoadBalancer {
    fn new(
        algorithm: LoadBalancerAlgorithm,
        targets: &[UpstreamTarget],
        _hash_on: Option<String>,
    ) -> Self {
        let wrr_weights: Vec<i64> = vec![0; targets.len()];
        // Pre-compute target keys once at build time, not per-request
        let target_keys: Vec<String> = targets.iter().map(target_key).collect();

        // Build consistent hash ring with virtual nodes
        let mut hash_ring = Vec::new();
        if algorithm == LoadBalancerAlgorithm::ConsistentHashing {
            for (idx, key) in target_keys.iter().enumerate() {
                // 150 virtual nodes per target for better distribution
                for vnode in 0..150 {
                    let vnode_key = format!("{}:{}", key, vnode);
                    let mut hasher = DefaultHasher::new();
                    vnode_key.hash(&mut hasher);
                    hash_ring.push((hasher.finish(), idx));
                }
            }
            hash_ring.sort_by_key(|&(hash, _)| hash);
        }

        Self {
            targets: targets.to_vec(),
            target_keys,
            algorithm,
            rr_counter: AtomicU64::new(0),
            wrr_state: std::sync::Mutex::new(wrr_weights),
            active_connections: DashMap::new(),
            hash_ring,
        }
    }

    /// Find the pre-computed target key for a target without allocating.
    /// Uses a linear scan of the (typically 2-5 element) targets vec, which is
    /// faster than a HashMap lookup that requires cloning the host String.
    fn find_target_key(&self, target: &UpstreamTarget) -> Option<&str> {
        for (i, t) in self.targets.iter().enumerate() {
            if t.host == target.host && t.port == target.port {
                return Some(self.target_keys[i].as_str());
            }
        }
        None
    }

    /// Build a bitmask of healthy target indices. Avoids per-request Vec allocation.
    /// Returns (bitmask, count). Bit `i` is set if target `i` is healthy.
    /// Supports up to 64 targets without heap allocation; >64 falls back to Vec.
    fn healthy_mask(&self, unhealthy: Option<&DashMap<String, u64>>) -> (u64, usize) {
        let mut mask: u64 = 0;
        let mut count = 0;
        for (i, _) in self.targets.iter().enumerate() {
            let is_healthy = if let Some(unhealthy_set) = unhealthy {
                !unhealthy_set.contains_key(&self.target_keys[i])
            } else {
                true
            };
            if is_healthy && i < 64 {
                mask |= 1u64 << i;
                count += 1;
            } else if is_healthy {
                count += 1;
            }
        }
        (mask, count)
    }

    /// Collect healthy targets into a Vec. Used only by algorithms that need
    /// a slice (WRR, least-connections). For RR/Random/ConsistentHash, prefer
    /// mask-based selection to avoid this allocation entirely.
    fn healthy_targets(
        &self,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Vec<(usize, &UpstreamTarget)> {
        self.targets
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                if let Some(unhealthy_set) = unhealthy {
                    !unhealthy_set.contains_key(&self.target_keys[*i])
                } else {
                    true
                }
            })
            .collect()
    }

    /// Select the Nth healthy target by scanning the mask, avoiding Vec allocation.
    fn nth_healthy(&self, mask: u64, healthy_count: usize, n: usize) -> Option<UpstreamTarget> {
        if healthy_count == 0 {
            return None;
        }
        let target_n = n % healthy_count;
        let mut seen = 0;
        for i in 0..self.targets.len().min(64) {
            if mask & (1u64 << i) != 0 {
                if seen == target_n {
                    return Some(self.targets[i].clone());
                }
                seen += 1;
            }
        }
        None
    }

    fn select(
        &self,
        ctx_key: &str,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<TargetSelection> {
        let (mask, healthy_count) = self.healthy_mask(unhealthy);
        if healthy_count == 0 {
            // Fallback: try all targets if everything is unhealthy
            if self.targets.is_empty() {
                return None;
            }
            return self.select_from_all(ctx_key).map(|target| TargetSelection {
                target,
                is_fallback: true,
            });
        }

        let target = match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                self.nth_healthy(mask, healthy_count, idx)
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => {
                let healthy = self.healthy_targets(unhealthy);
                self.select_wrr(&healthy)
            }
            LoadBalancerAlgorithm::LeastConnections => {
                let healthy = self.healthy_targets(unhealthy);
                self.select_least_connections(&healthy)
            }
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash(ctx_key, mask, healthy_count)
            }
            LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let mut hasher = DefaultHasher::new();
                idx.hash(&mut hasher);
                let hash = hasher.finish() as usize;
                self.nth_healthy(mask, healthy_count, hash)
            }
        };

        target.map(|t| TargetSelection {
            target: t,
            is_fallback: false,
        })
    }

    fn select_from_all(&self, ctx_key: &str) -> Option<UpstreamTarget> {
        if self.targets.is_empty() {
            return None;
        }
        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin | LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                Some(self.targets[idx % self.targets.len()].clone())
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => {
                let all: Vec<(usize, &UpstreamTarget)> = self.targets.iter().enumerate().collect();
                self.select_wrr(&all)
            }
            LoadBalancerAlgorithm::LeastConnections => {
                let all: Vec<(usize, &UpstreamTarget)> = self.targets.iter().enumerate().collect();
                self.select_least_connections(&all)
            }
            LoadBalancerAlgorithm::ConsistentHashing => {
                // All targets healthy — full mask
                let full_mask = if self.targets.len() >= 64 {
                    u64::MAX
                } else {
                    (1u64 << self.targets.len()) - 1
                };
                self.select_consistent_hash(ctx_key, full_mask, self.targets.len())
            }
        }
    }

    fn select_excluding(
        &self,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<UpstreamTarget> {
        // Find the exclude target's index via linear scan (avoids host.clone() allocation)
        let exclude_idx = self
            .targets
            .iter()
            .position(|t| t.host == exclude.host && t.port == exclude.port);

        // Build healthy targets excluding the specified target
        let healthy: Vec<(usize, &UpstreamTarget)> = self
            .targets
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                // Exclude the specified target
                if exclude_idx.is_some_and(|ei| ei == *i) {
                    return false;
                }
                if let Some(unhealthy_set) = unhealthy {
                    !unhealthy_set.contains_key(&self.target_keys[*i])
                } else {
                    true
                }
            })
            .collect();

        if healthy.is_empty() {
            // If no other healthy targets, try any target except excluded
            let fallback: Vec<(usize, &UpstreamTarget)> = self
                .targets
                .iter()
                .enumerate()
                .filter(|(i, _)| exclude_idx.is_none_or(|ei| ei != *i))
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
                // Build mask from the healthy vec for consistent hash
                let mut mask: u64 = 0;
                for &(i, _) in &healthy {
                    if i < 64 {
                        mask |= 1u64 << i;
                    }
                }
                self.select_consistent_hash(ctx_key, mask, healthy.len())
            }
        }
    }

    /// Smooth weighted round-robin (NGINX algorithm).
    ///
    /// Uses a mutex to prevent weight drift under concurrent access.
    /// The critical section is sub-microsecond (only integer arithmetic).
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

        let mut weights = self.wrr_state.lock().unwrap_or_else(|e| e.into_inner());

        // Add effective weight to current weight for each candidate
        let mut best_idx = 0;
        let mut best_current = i64::MIN;

        for (i, (orig_idx, target)) in candidates.iter().enumerate() {
            weights[*orig_idx] += target.weight as i64;
            let current = weights[*orig_idx];
            if current > best_current {
                best_current = current;
                best_idx = i;
            }
        }

        // Subtract total weight from the selected candidate
        let (orig_idx, _) = candidates[best_idx];
        weights[orig_idx] -= total_weight;

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
            let key = &self.target_keys[candidate.0];
            let conns = self
                .active_connections
                .get(key)
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
    /// Uses a bitmask for O(1) candidate membership check instead of allocating a HashSet.
    fn select_consistent_hash(
        &self,
        ctx_key: &str,
        candidate_mask: u64,
        candidate_count: usize,
    ) -> Option<UpstreamTarget> {
        if candidate_count == 0 {
            return None;
        }

        let mut hasher = DefaultHasher::new();
        ctx_key.hash(&mut hasher);
        let hash = hasher.finish();

        // Binary search on the ring
        let pos = match self.hash_ring.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(p) => p,
            Err(p) => p % self.hash_ring.len().max(1),
        };

        // Walk the ring from pos to find a valid (healthy) target.
        // Uses bitmask for O(1) membership check — no per-request HashSet allocation.
        for i in 0..self.hash_ring.len() {
            let ring_idx = (pos + i) % self.hash_ring.len();
            let target_idx = self.hash_ring[ring_idx].1;
            if target_idx < 64 && candidate_mask & (1u64 << target_idx) != 0 {
                return Some(self.targets[target_idx].clone());
            }
        }

        // Fallback: return first healthy target
        self.nth_healthy(candidate_mask, candidate_count, 0)
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
}
