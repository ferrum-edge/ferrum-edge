//! Load balancer for distributing requests across upstream targets.
//!
//! Supports multiple algorithms: round-robin, weighted round-robin,
//! least connections, least latency, consistent hashing, and random.

use crate::config::types::{GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Default EWMA smoothing factor, stored as fixed-point with 1000 = 1.0.
/// 300 = 0.3 — gives recent samples ~30% influence per update, balancing
/// responsiveness to latency changes against noise from individual spikes.
const DEFAULT_EWMA_ALPHA_FP: u64 = 300;

/// Fixed-point scale factor for EWMA alpha (1000 = 1.0).
const EWMA_SCALE: u64 = 1000;

/// Number of latency samples per target before switching from round-robin
/// warm-up to latency-based selection. Ensures every target gets enough
/// traffic to establish a meaningful baseline before the algorithm starts
/// preferring the lowest-latency target.
const LATENCY_WARMUP_THRESHOLD: u64 = 5;

/// Sentinel value indicating no latency has been recorded yet.
const LATENCY_UNSET: u64 = u64::MAX;

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
/// round-robin counters, WRR weights, active connection counts, latency
/// EWMAs, and consistent hash rings are all preserved.
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
    ///   round-robin counters, WRR weights, active connection counts, latency
    ///   EWMAs, and hash rings
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

    /// Update the targets for a single upstream (used by service discovery).
    ///
    /// Creates a new `LoadBalancer` instance with the provided targets and
    /// swaps it in atomically. Other upstreams keep their existing instances
    /// with preserved round-robin counters and connection counts.
    pub fn update_targets(
        &self,
        upstream_id: &str,
        new_targets: Vec<UpstreamTarget>,
        algorithm: LoadBalancerAlgorithm,
        hash_on: Option<String>,
    ) {
        // Update the balancer
        let mut new_balancers = self.balancers.load().as_ref().clone();
        new_balancers.insert(
            upstream_id.to_string(),
            Arc::new(LoadBalancer::new(algorithm, &new_targets, hash_on)),
        );
        self.balancers.store(Arc::new(new_balancers));

        // Update the upstream index
        let mut new_upstreams = self.upstreams.load().as_ref().clone();
        if let Some(existing) = new_upstreams.get(upstream_id) {
            let mut updated = (**existing).clone();
            updated.targets = new_targets;
            new_upstreams.insert(upstream_id.to_string(), Arc::new(updated));
        }
        self.upstreams.store(Arc::new(new_upstreams));
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

    /// Snapshot of active connection counts per upstream for metrics.
    pub fn active_connections_snapshot(&self) -> Vec<(String, Vec<(String, i64)>)> {
        let balancers = self.balancers.load();
        let mut result = Vec::new();
        for (upstream_id, balancer) in balancers.iter() {
            let mut targets = Vec::new();
            for entry in balancer.active_connections.iter() {
                let count = entry.value().load(Ordering::Relaxed);
                if count > 0 {
                    targets.push((entry.key().clone(), count));
                }
            }
            if !targets.is_empty() {
                result.push((upstream_id.clone(), targets));
            }
        }
        result
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

    /// Record a response latency measurement for a target (for least-latency).
    ///
    /// Updates the target's EWMA (Exponentially Weighted Moving Average) with
    /// the new sample. Latency is stored in microseconds for sub-millisecond
    /// precision without floating-point atomics.
    ///
    /// Called from one of two sources (active takes precedence):
    /// - **Active path**: `health_check.rs` after each successful probe RTT
    /// - **Passive path**: `proxy/mod.rs` after each successful non-5xx backend
    ///   response (TTFB) — only when no active health checks are configured
    pub fn record_latency(&self, upstream_id: &str, target: &UpstreamTarget, latency_us: u64) {
        let balancers = self.balancers.load();
        if let Some(balancer) = balancers.get(upstream_id) {
            balancer.record_latency(target, latency_us);
        }
    }

    /// Reset the latency EWMA for a target to the current minimum among healthy
    /// targets. Called when a target recovers from unhealthy status so it gets a
    /// fair chance at traffic instead of being penalized by a stale high EWMA.
    pub fn reset_recovered_target_latency(&self, upstream_id: &str, target: &UpstreamTarget) {
        let balancers = self.balancers.load();
        if let Some(balancer) = balancers.get(upstream_id) {
            balancer.reset_recovered_target_latency(target);
        }
    }
}

pub fn target_key(target: &UpstreamTarget) -> String {
    format!("{}:{}", target.host, target.port)
}

/// Per-upstream load balancer with algorithm-specific state.
pub struct LoadBalancer {
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
    pub active_connections: DashMap<String, AtomicI64>,
    /// Consistent hash ring (sorted hash values -> target index).
    hash_ring: Vec<(u64, usize)>,
    /// EWMA latency per target in microseconds (for least-latency).
    /// Key: "host:port", Value: EWMA in microseconds (LATENCY_UNSET = no data yet).
    /// Uses AtomicU64 for lock-free updates on the hot path.
    pub latency_ewma: DashMap<String, AtomicU64>,
    /// Number of latency samples recorded per target (for least-latency warm-up).
    /// During the warm-up phase (< LATENCY_WARMUP_THRESHOLD samples per target),
    /// round-robin is used to ensure all targets get enough traffic to establish
    /// baseline latency measurements.
    pub latency_sample_count: DashMap<String, AtomicU64>,
}

impl LoadBalancer {
    pub fn new(
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

        // Initialize latency tracking for least-latency algorithm
        let latency_ewma = DashMap::new();
        let latency_sample_count = DashMap::new();
        if algorithm == LoadBalancerAlgorithm::LeastLatency {
            for key in &target_keys {
                latency_ewma.insert(key.clone(), AtomicU64::new(LATENCY_UNSET));
                latency_sample_count.insert(key.clone(), AtomicU64::new(0));
            }
        }

        Self {
            targets: targets.to_vec(),
            target_keys,
            algorithm,
            rr_counter: AtomicU64::new(0),
            wrr_state: std::sync::Mutex::new(wrr_weights),
            active_connections: DashMap::new(),
            hash_ring,
            latency_ewma,
            latency_sample_count,
        }
    }

    /// Record a latency sample for a target, updating the EWMA.
    ///
    /// Uses fixed-point arithmetic (scale factor 1000) to avoid floating-point
    /// operations in the hot path. The EWMA formula is:
    ///
    ///   ewma = alpha * new_sample + (1 - alpha) * old_ewma
    ///
    /// With alpha = 0.3 (DEFAULT_EWMA_ALPHA_FP = 300), recent measurements
    /// account for ~30% of the EWMA, providing a good balance between
    /// responsiveness and stability.
    ///
    /// The first sample for a target sets the EWMA directly (no smoothing).
    pub fn record_latency(&self, target: &UpstreamTarget, latency_us: u64) {
        let key = match self.find_target_key(target) {
            Some(k) => k,
            None => return,
        };

        // Update sample count
        if let Some(count) = self.latency_sample_count.get(key) {
            count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_sample_count
                .insert(key.to_owned(), AtomicU64::new(1));
        }

        // Update EWMA using compare-and-swap loop for lock-free concurrent updates.
        // The CAS loop is bounded — contention only occurs when two latency
        // recordings for the same target happen simultaneously, which is rare.
        if let Some(ewma_ref) = self.latency_ewma.get(key) {
            let ewma = ewma_ref.value();
            loop {
                let current = ewma.load(Ordering::Relaxed);
                let new_ewma = if current == LATENCY_UNSET {
                    // First sample — seed the EWMA directly
                    latency_us
                } else {
                    // EWMA = alpha * sample + (1 - alpha) * current
                    // Using fixed-point: (alpha_fp * sample + (SCALE - alpha_fp) * current) / SCALE
                    let alpha = DEFAULT_EWMA_ALPHA_FP;
                    (alpha * latency_us + (EWMA_SCALE - alpha) * current) / EWMA_SCALE
                };
                if ewma
                    .compare_exchange_weak(current, new_ewma, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        } else {
            // Target not pre-initialized (shouldn't happen for LeastLatency, but
            // handle gracefully for mixed-algorithm recording)
            self.latency_ewma
                .insert(key.to_owned(), AtomicU64::new(latency_us));
        }
    }

    /// Reset a recovered target's EWMA to the current minimum among all targets
    /// so it gets a fair chance at traffic after recovering from unhealthy status.
    ///
    /// Without this, a target that was slow before going unhealthy would retain
    /// its high EWMA and never receive traffic even after recovery.
    ///
    /// The sample count is set to `LATENCY_WARMUP_THRESHOLD` so the recovered
    /// target immediately participates in latency-based selection rather than
    /// forcing the entire upstream back into round-robin warm-up mode.
    pub fn reset_recovered_target_latency(&self, target: &UpstreamTarget) {
        let key = match self.find_target_key(target) {
            Some(k) => k,
            None => return,
        };

        // Find minimum EWMA among all targets (excluding unset)
        let min_ewma = self
            .latency_ewma
            .iter()
            .map(|entry| entry.value().load(Ordering::Relaxed))
            .filter(|&v| v != LATENCY_UNSET)
            .min()
            .unwrap_or(LATENCY_UNSET);

        if let Some(ewma_ref) = self.latency_ewma.get(key) {
            ewma_ref.value().store(min_ewma, Ordering::Relaxed);
        }
        // Set sample count to the warm-up threshold so this target immediately
        // participates in latency-based selection. Setting to 0 would force the
        // entire upstream back into round-robin warm-up, disrupting routing for
        // other targets that already have good latency data.
        if let Some(count_ref) = self.latency_sample_count.get(key) {
            count_ref
                .value()
                .store(LATENCY_WARMUP_THRESHOLD, Ordering::Relaxed);
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
    /// Collect healthy targets into a Vec for selection by any algorithm.
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

    pub fn select(
        &self,
        ctx_key: &str,
        unhealthy: Option<&DashMap<String, u64>>,
    ) -> Option<TargetSelection> {
        let healthy = self.healthy_targets(unhealthy);
        if healthy.is_empty() {
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
                Some(healthy[idx % healthy.len()].1.clone())
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr(&healthy),
            LoadBalancerAlgorithm::LeastConnections => self.select_least_connections(&healthy),
            LoadBalancerAlgorithm::LeastLatency => self.select_least_latency(&healthy),
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash(ctx_key, &healthy)
            }
            LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let mut hasher = DefaultHasher::new();
                idx.hash(&mut hasher);
                let hash = hasher.finish() as usize;
                Some(healthy[hash % healthy.len()].1.clone())
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
            LoadBalancerAlgorithm::LeastLatency => {
                let all: Vec<(usize, &UpstreamTarget)> = self.targets.iter().enumerate().collect();
                self.select_least_latency(&all)
            }
            LoadBalancerAlgorithm::ConsistentHashing => {
                let all: Vec<(usize, &UpstreamTarget)> = self.targets.iter().enumerate().collect();
                self.select_consistent_hash(ctx_key, &all)
            }
        }
    }

    pub fn select_excluding(
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
            LoadBalancerAlgorithm::LeastLatency => self.select_least_latency(&healthy),
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash(ctx_key, &healthy)
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

    /// Select the target with the lowest latency EWMA.
    ///
    /// **Warm-up phase**: At initial startup, round-robin is used until every
    /// healthy candidate has at least `LATENCY_WARMUP_THRESHOLD` samples. This
    /// ensures all targets get enough traffic to establish meaningful baselines
    /// before the algorithm starts preferring the lowest-latency target.
    ///
    /// **Late joiners / recovery**: If some candidates already have latency data
    /// but a newly healthy target does not, the algorithm does NOT regress to
    /// round-robin. Instead, targets without data are treated as having the
    /// current minimum EWMA (optimistic assumption) so they get a fair chance at
    /// traffic while the rest of the upstream continues latency-based routing.
    /// Once the new target accumulates enough samples, its real EWMA takes over.
    ///
    /// **Steady-state**: Selects the candidate with the lowest EWMA value.
    /// Ties are broken by candidate order (first lowest wins), providing
    /// deterministic behavior under equal latency.
    ///
    /// **No data**: If no target has latency data (all EWMA values are LATENCY_UNSET),
    /// falls back to round-robin.
    fn select_least_latency(
        &self,
        candidates: &[(usize, &UpstreamTarget)],
    ) -> Option<UpstreamTarget> {
        if candidates.is_empty() {
            return None;
        }

        // Count how many candidates have warmed up and how many have any data at all.
        let mut warmed_count = 0usize;
        let mut any_has_data = false;
        for (idx, _) in candidates {
            let key = &self.target_keys[*idx];
            let samples = self
                .latency_sample_count
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            if samples >= LATENCY_WARMUP_THRESHOLD {
                warmed_count += 1;
            }
            if samples > 0 {
                any_has_data = true;
            }
        }

        // Initial warm-up: no candidate has any data yet, use round-robin so all
        // targets get baseline measurements. Also used when every target is still
        // below the warm-up threshold (fresh startup).
        if warmed_count == 0 || (!any_has_data) {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(candidates[idx % candidates.len()].1.clone());
        }

        // If all candidates are warmed up, pure latency-based selection.
        // If some are not (late joiner / recovery), use latency-based selection
        // but treat unwarmed targets optimistically (see below).
        let all_warmed_up = warmed_count == candidates.len();

        // Find the minimum EWMA among warmed candidates (for optimistic fallback).
        let min_known_ewma = if !all_warmed_up {
            candidates
                .iter()
                .filter_map(|(idx, _)| {
                    let key = &self.target_keys[*idx];
                    self.latency_ewma
                        .get(key)
                        .map(|v| v.load(Ordering::Relaxed))
                        .filter(|&v| v != LATENCY_UNSET)
                })
                .min()
                .unwrap_or(LATENCY_UNSET)
        } else {
            0 // unused when all warmed up
        };

        // Steady-state: select the candidate with the lowest EWMA.
        // Unwarmed targets use min_known_ewma so they get a fair share of traffic
        // without disrupting latency-based routing for established targets.
        let mut best_latency = u64::MAX;
        let mut best = &candidates[0];

        for candidate in candidates {
            let key = &self.target_keys[candidate.0];
            let samples = self
                .latency_sample_count
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            let latency = if samples >= LATENCY_WARMUP_THRESHOLD {
                // Warmed target — use real EWMA
                self.latency_ewma
                    .get(key)
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(LATENCY_UNSET)
            } else if !all_warmed_up && min_known_ewma != LATENCY_UNSET {
                // Late joiner: use a value slightly below the current minimum so
                // it wins ties and gets enough traffic to establish a real baseline.
                // The saturating_sub ensures we don't underflow past 0.
                min_known_ewma.saturating_sub(1)
            } else {
                LATENCY_UNSET
            };
            if latency < best_latency {
                best_latency = latency;
                best = candidate;
            }
        }

        // If all targets have no data, fall back to round-robin
        if best_latency == LATENCY_UNSET {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(candidates[idx % candidates.len()].1.clone());
        }

        Some(best.1.clone())
    }

    /// Consistent hash: find the target on the hash ring closest to the hash of ctx_key.
    /// Uses a bitmask for O(1) candidate membership check instead of allocating a HashSet.
    fn select_consistent_hash(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &UpstreamTarget)],
    ) -> Option<UpstreamTarget> {
        if candidates.is_empty() {
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
        for i in 0..self.hash_ring.len() {
            let ring_idx = (pos + i) % self.hash_ring.len();
            let target_idx = self.hash_ring[ring_idx].1;
            if candidates.iter().any(|&(ci, _)| ci == target_idx) {
                return Some(self.targets[target_idx].clone());
            }
        }

        // Fallback: return first candidate
        Some(candidates[0].1.clone())
    }
}
