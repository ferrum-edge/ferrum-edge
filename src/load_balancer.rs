//! Load balancer for distributing requests across upstream targets.
//!
//! Supports multiple algorithms: round-robin, weighted round-robin,
//! least connections, least latency, consistent hashing, and random.

use crate::config::types::{GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use crate::health_check::ProxyHealthState;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::HashMap;

/// Fibonacci / golden-ratio hash for fast pseudo-random distribution of sequential counters.
/// Maps sequential u64 inputs to well-distributed outputs across the full u64 range.
/// Used by the Random load balancer algorithm instead of SipHash (DefaultHasher) for
/// ~10x faster selection (~1-2ns vs ~15-25ns per call).
///
/// Same technique used in `overload.rs` for RED shedding and in the Linux kernel's
/// hash_long() for hash table slot selection.
#[inline]
fn golden_ratio_hash(val: u64) -> u64 {
    val.wrapping_mul(0x9E3779B97F4A7C15)
}

/// Fast non-cryptographic hash for consistent hashing key distribution.
/// FxHash-style multiply-rotate — ~3-5ns vs SipHash's ~15-25ns per call.
/// Security against HashDoS is irrelevant here: the input is client IP or a
/// config-selected cookie/header value, and collision resistance only affects
/// load distribution balance, not memory safety.
#[inline]
fn fx_hash_str(s: &str) -> u64 {
    let mut hash: u64 = 0;
    for &byte in s.as_bytes() {
        hash = hash.rotate_left(5) ^ (byte as u64);
        hash = hash.wrapping_mul(0x517cc1b727220a95);
    }
    hash
}

/// Maximum number of upstream targets eligible for the stack-allocated bitset
/// fast path. Upstreams with more targets fall back to the Vec-based path.
/// 128 covers essentially all real-world upstream configurations.
const MAX_BITSET_TARGETS: usize = 128;

/// Stack-allocated bitset for up to 128 upstream targets.
///
/// Provides O(1) health/candidate membership checks on the selection hot path,
/// eliminating per-request `Vec` allocations and replacing repeated `DashMap`
/// lookups with single-pass construction followed by free bit tests. Health
/// state is sampled once into the bitset at the start of `select()` so
/// algorithms never touch `DashMap` during selection.
#[derive(Clone, Copy)]
struct HealthBitset {
    bits: u128,
    len: u8,
}

impl HealthBitset {
    /// All targets healthy — all bits set for `n` targets.
    #[inline]
    fn all(n: usize) -> Self {
        debug_assert!(n <= MAX_BITSET_TARGETS);
        let bits = if n >= 128 {
            u128::MAX
        } else if n == 0 {
            0
        } else {
            (1u128 << n) - 1
        };
        Self { bits, len: n as u8 }
    }

    #[inline]
    fn empty() -> Self {
        Self { bits: 0, len: 0 }
    }

    #[inline]
    fn set(&mut self, idx: usize) {
        self.bits |= 1u128 << idx;
        self.len += 1;
    }

    #[inline]
    fn clear(&mut self, idx: usize) {
        if self.bits & (1u128 << idx) != 0 {
            self.bits &= !(1u128 << idx);
            self.len -= 1;
        }
    }

    #[inline]
    fn contains(&self, idx: usize) -> bool {
        self.bits & (1u128 << idx) != 0
    }

    #[inline]
    fn count(&self) -> usize {
        self.len as usize
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn is_all(&self, total: usize) -> bool {
        self.len as usize == total
    }

    /// Return the index of the `n`th set bit (0-based among set bits).
    /// Used by round-robin/random to map a counter to a healthy target by
    /// ordinal position without allocating a filtered Vec. Cost: O(n)
    /// clear-lowest-bit operations, which for typical upstream sizes (2-20
    /// targets) is a handful of cycles on register-width integers.
    #[inline]
    fn nth_set_bit(&self, n: usize) -> usize {
        debug_assert!(!self.is_empty());
        let wrapped = n % self.len as usize;
        let mut remaining = self.bits;
        for _ in 0..wrapped {
            remaining &= remaining - 1; // clear lowest set bit
        }
        remaining.trailing_zeros() as usize
    }
}

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Health context passed to target selection, bundling both active (shared
/// per-upstream) and passive (per-proxy) unhealthy target state.
///
/// A target is filtered out if it appears in EITHER:
/// - `active_unhealthy`: keyed by `upstream_id::host:port` (matches `LoadBalancer.target_keys`)
/// - `proxy_passive`: the calling proxy's `ProxyHealthState.unhealthy` map,
///   keyed by plain `host:port` (matches `LoadBalancer.host_port_keys`) —
///   resolved once via the outer `passive_health` DashMap before calling `select_target`
pub struct HealthContext<'a> {
    pub active_unhealthy: &'a DashMap<String, u64>,
    /// Pre-resolved per-proxy passive health state. `None` means no passive
    /// failures have been recorded for this proxy (all targets healthy).
    /// Resolved from `HealthChecker.passive_health.get(proxy_id)` at the call
    /// site — one outer DashMap lookup amortized across all targets.
    pub proxy_passive: Option<Arc<ProxyHealthState>>,
}

/// Parsed strategy for resolving the hash key used by consistent hashing.
/// Pre-computed at config-reload time so the request path does no string parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOnStrategy {
    /// Hash on client IP address (default).
    Ip,
    /// Hash on the value of a request header (lowercased name).
    Header(String),
    /// Hash on the value of a request cookie.
    Cookie(String),
}

impl HashOnStrategy {
    /// Parse a `hash_on` config string into a strategy.
    ///
    /// Accepted formats:
    /// - `None` or `"ip"` → `HashOnStrategy::Ip`
    /// - `"header:<name>"` → `HashOnStrategy::Header(name)` (lowercased)
    /// - `"cookie:<name>"` → `HashOnStrategy::Cookie(name)`
    pub fn parse(hash_on: Option<&str>) -> Self {
        match hash_on {
            None | Some("ip") | Some("") => Self::Ip,
            Some(s) if s.starts_with("header:") => {
                let name = s["header:".len()..].trim();
                if name.is_empty() {
                    Self::Ip
                } else {
                    Self::Header(name.to_ascii_lowercase())
                }
            }
            Some(s) if s.starts_with("cookie:") => {
                let name = s["cookie:".len()..].trim();
                if name.is_empty() {
                    Self::Ip
                } else {
                    Self::Cookie(name.to_string())
                }
            }
            Some(_) => Self::Ip, // Unknown format, fall back to IP
        }
    }
}

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
    /// The selected upstream target, wrapped in `Arc` so that load balancer
    /// selection is a cheap pointer bump instead of cloning the full struct
    /// (host String + port + weight + tags HashMap + path Option) per request.
    pub target: Arc<UpstreamTarget>,
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
                    &upstream.id,
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
                    &upstream.id,
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
            Arc::new(LoadBalancer::new(
                upstream_id,
                algorithm,
                &new_targets,
                hash_on,
            )),
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

    /// Get the pre-parsed hash-on strategy for an upstream.
    /// Returns `HashOnStrategy::Ip` if the upstream is not found.
    pub fn get_hash_on_strategy(&self, upstream_id: &str) -> HashOnStrategy {
        let balancers = self.balancers.load();
        balancers
            .get(upstream_id)
            .map(|b| b.hash_on_strategy.clone())
            .unwrap_or(HashOnStrategy::Ip)
    }

    /// Select a target from the upstream, filtering out unhealthy targets.
    ///
    /// Returns a [`TargetSelection`] indicating whether the target came from
    /// the healthy pool or is a degraded-mode fallback (all targets unhealthy).
    ///
    /// When `health` is provided, targets appearing in either the active
    /// unhealthy map (upstream-wide probe failures) or the passive unhealthy
    /// map (per-proxy traffic failures) are filtered out.
    pub fn select_target(
        &self,
        upstream_id: &str,
        ctx_key: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let balancers = self.balancers.load();
        let balancer = balancers.get(upstream_id)?;
        balancer.select(ctx_key, health)
    }

    /// Load the balancers map once and return a guard for multiple lookups.
    ///
    /// Use this when you need both `get_hash_on_strategy()` and `select_target()`
    /// for the same upstream — saves one `ArcSwap::load()` atomic operation per
    /// request by loading the balancers map once and reusing the guard.
    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<HashMap<String, Arc<LoadBalancer>>>> {
        self.balancers.load()
    }

    /// Get the hash-on strategy from a pre-loaded balancers guard.
    #[inline]
    pub fn get_hash_on_strategy_from(
        balancers: &HashMap<String, Arc<LoadBalancer>>,
        upstream_id: &str,
    ) -> HashOnStrategy {
        balancers
            .get(upstream_id)
            .map(|b| b.hash_on_strategy.clone())
            .unwrap_or(HashOnStrategy::Ip)
    }

    /// Select a target from a pre-loaded balancers guard.
    #[inline]
    pub fn select_target_from(
        balancers: &HashMap<String, Arc<LoadBalancer>>,
        upstream_id: &str,
        ctx_key: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let balancer = balancers.get(upstream_id)?;
        balancer.select(ctx_key, health)
    }

    /// Select next target, excluding a previously tried target (for retries).
    pub fn select_next_target(
        &self,
        upstream_id: &str,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let balancers = self.balancers.load();
        let balancer = balancers.get(upstream_id)?;
        balancer.select_excluding(ctx_key, exclude, health)
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

/// Build a health-check-scoped key ("upstream_id::host:port") for a target.
/// Used by `LoadBalancer::target_keys` and `HealthChecker` to scope health
/// state per-upstream, preventing cross-upstream contamination when different
/// upstreams contain overlapping host:port targets.
pub fn target_key(upstream_id: &str, target: &UpstreamTarget) -> String {
    format!("{}::{}:{}", upstream_id, target.host, target.port)
}

/// Build a plain "host:port" key for a target (no upstream scoping).
/// Used for sticky session cookies, active connection tracking, latency EWMA,
/// and other contexts where the key is already scoped to a single LoadBalancer.
pub fn target_host_port_key(target: &UpstreamTarget) -> String {
    format!("{}:{}", target.host, target.port)
}

/// Per-upstream load balancer with algorithm-specific state.
pub struct LoadBalancer {
    targets: Vec<Arc<UpstreamTarget>>,
    /// Pre-computed "upstream_id::host:port" keys for each target, matching the
    /// format used by `HealthChecker.unhealthy_targets` for O(1) health filtering.
    target_keys: Vec<String>,
    /// Pre-computed "host:port" keys (no upstream scope) for internal use by
    /// active_connections, latency_ewma, and find_target_key lookups that are
    /// already scoped to this LoadBalancer instance.
    host_port_keys: Vec<String>,
    /// O(1) reverse lookup from "host:port" string to index in `targets`/`host_port_keys`.
    /// Replaces the O(n) linear scan in `find_target_key()`. Keys are the same
    /// "host:port" format as `host_port_keys`, enabling zero-allocation lookup
    /// via `write!()` into a thread-local buffer.
    target_index: HashMap<String, usize>,
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
    /// Pre-parsed hash-on strategy for consistent hashing key resolution.
    pub hash_on_strategy: HashOnStrategy,
}

impl LoadBalancer {
    pub fn new(
        upstream_id: &str,
        algorithm: LoadBalancerAlgorithm,
        targets: &[UpstreamTarget],
        hash_on: Option<String>,
    ) -> Self {
        let wrr_weights: Vec<i64> = vec![0; targets.len()];
        // Pre-compute host:port keys for internal use (active connections, latency, hash ring)
        let host_port_keys: Vec<String> = targets.iter().map(target_host_port_key).collect();
        // Pre-compute upstream-scoped keys for health check filtering (matches HealthChecker key format)
        let target_keys: Vec<String> = targets.iter().map(|t| target_key(upstream_id, t)).collect();

        // Build consistent hash ring with virtual nodes using fx_hash_str
        // (faster than SipHash/DefaultHasher; security irrelevant for ring placement).
        let mut hash_ring = Vec::new();
        if algorithm == LoadBalancerAlgorithm::ConsistentHashing {
            for (idx, key) in host_port_keys.iter().enumerate() {
                // 150 virtual nodes per target for better distribution
                for vnode in 0..150 {
                    let vnode_key = format!("{}:{}", key, vnode);
                    hash_ring.push((fx_hash_str(&vnode_key), idx));
                }
            }
            hash_ring.sort_by_key(|&(hash, _)| hash);
        }

        // Initialize latency tracking for least-latency algorithm
        let latency_ewma = DashMap::new();
        let latency_sample_count = DashMap::new();
        if algorithm == LoadBalancerAlgorithm::LeastLatency {
            for key in &host_port_keys {
                latency_ewma.insert(key.clone(), AtomicU64::new(LATENCY_UNSET));
                latency_sample_count.insert(key.clone(), AtomicU64::new(0));
            }
        }

        let hash_on_strategy = HashOnStrategy::parse(hash_on.as_deref());

        // Pre-compute O(1) reverse index from "host:port" → index for find_target_key()
        let target_index: HashMap<String, usize> = host_port_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (k.clone(), i))
            .collect();

        Self {
            targets: targets.iter().cloned().map(Arc::new).collect(),
            target_keys,
            host_port_keys,
            target_index,
            algorithm,
            rr_counter: AtomicU64::new(0),
            wrr_state: std::sync::Mutex::new(wrr_weights),
            active_connections: DashMap::new(),
            hash_ring,
            latency_ewma,
            latency_sample_count,
            hash_on_strategy,
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
                    // Use saturating_mul to prevent overflow with extreme latency values.
                    let alpha = DEFAULT_EWMA_ALPHA_FP;
                    (alpha
                        .saturating_mul(latency_us)
                        .saturating_add((EWMA_SCALE - alpha).saturating_mul(current)))
                        / EWMA_SCALE
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

    /// Find the pre-computed host:port key for a target via O(1) HashMap lookup.
    /// Returns the internal (non-upstream-scoped) key used for active connections,
    /// latency EWMA, and hash ring lookups within this LoadBalancer instance.
    ///
    /// Uses a thread-local buffer to construct the lookup key without allocation.
    #[inline]
    fn find_target_key(&self, target: &UpstreamTarget) -> Option<&str> {
        use std::fmt::Write;
        thread_local! {
            static TARGET_KEY_BUF: std::cell::RefCell<String> =
                std::cell::RefCell::new(String::with_capacity(64));
        }
        TARGET_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let _ = write!(buf, "{}:{}", target.host, target.port);
            self.target_index
                .get(buf.as_str())
                .map(|&i| self.host_port_keys[i].as_str())
        })
    }

    /// Compute a stack-allocated bitset of healthy target indices in a single
    /// pass. Each target requires at most 2 `DashMap` lookups (active + passive),
    /// done once per `select()` call. All subsequent algorithm steps use free
    /// bit tests on the resulting bitset.
    ///
    /// Requires `self.targets.len() <= MAX_BITSET_TARGETS`.
    #[inline]
    fn compute_health_bitset(&self, health: Option<&HealthContext<'_>>) -> HealthBitset {
        let n = self.targets.len();
        let Some(h) = health else {
            return HealthBitset::all(n);
        };

        // Fast check: if both health maps are empty, all targets are healthy.
        if h.active_unhealthy.is_empty()
            && h.proxy_passive
                .as_ref()
                .is_none_or(|ps| ps.unhealthy.is_empty())
        {
            return HealthBitset::all(n);
        }

        let mut bitset = HealthBitset::empty();
        for i in 0..n {
            // Active: pre-computed "upstream_id::host:port" key
            if h.active_unhealthy.contains_key(&self.target_keys[i]) {
                continue;
            }
            // Passive: direct "host:port" lookup in proxy's own map
            if h.proxy_passive
                .as_ref()
                .is_some_and(|ps| ps.unhealthy.contains_key(&self.host_port_keys[i]))
            {
                continue;
            }
            bitset.set(i);
        }
        bitset
    }

    /// Collect healthy targets into a Vec — fallback for upstreams with >128
    /// targets that cannot use the bitset fast path.
    fn healthy_targets_vec(
        &self,
        health: Option<&HealthContext<'_>>,
    ) -> Vec<(usize, &Arc<UpstreamTarget>)> {
        let Some(h) = health else {
            return self.targets.iter().enumerate().collect();
        };
        self.targets
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                if h.active_unhealthy.contains_key(&self.target_keys[*i]) {
                    return false;
                }
                if h.proxy_passive
                    .as_ref()
                    .is_some_and(|ps| ps.unhealthy.contains_key(&self.host_port_keys[*i]))
                {
                    return false;
                }
                true
            })
            .collect()
    }

    pub fn select(
        &self,
        ctx_key: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let n = self.targets.len();
        if n == 0 {
            return None;
        }

        // For >128 targets, fall back to the Vec-based path.
        if n > MAX_BITSET_TARGETS {
            return self.select_vec_fallback(ctx_key, health);
        }

        // Single-pass health bitset: every DashMap lookup happens here, once.
        let healthy = self.compute_health_bitset(health);

        if healthy.is_empty() {
            // All targets unhealthy — degraded mode fallback using all targets.
            let all = HealthBitset::all(n);
            return self
                .select_with_bitset(ctx_key, &all)
                .map(|target| TargetSelection {
                    target,
                    is_fallback: true,
                });
        }

        self.select_with_bitset(ctx_key, &healthy)
            .map(|target| TargetSelection {
                target,
                is_fallback: false,
            })
    }

    /// Dispatch to the algorithm-specific selector using a pre-computed bitset.
    /// No heap allocation on any code path.
    fn select_with_bitset(
        &self,
        ctx_key: &str,
        healthy: &HealthBitset,
    ) -> Option<Arc<UpstreamTarget>> {
        if healthy.is_empty() {
            return None;
        }
        let all = healthy.is_all(self.targets.len());
        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                let target_idx = if all {
                    idx % self.targets.len()
                } else {
                    healthy.nth_set_bit(idx)
                };
                Some(Arc::clone(&self.targets[target_idx]))
            }
            LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let hash = golden_ratio_hash(idx) as usize;
                let target_idx = if all {
                    hash % self.targets.len()
                } else {
                    healthy.nth_set_bit(hash)
                };
                Some(Arc::clone(&self.targets[target_idx]))
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr_bitset(healthy),
            LoadBalancerAlgorithm::LeastConnections => {
                self.select_least_connections_bitset(healthy)
            }
            LoadBalancerAlgorithm::LeastLatency => self.select_least_latency_bitset(healthy),
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash_bitset(ctx_key, healthy)
            }
        }
    }

    /// Vec-based fallback for select() when targets.len() > MAX_BITSET_TARGETS.
    fn select_vec_fallback(
        &self,
        ctx_key: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let healthy = self.healthy_targets_vec(health);
        if healthy.is_empty() {
            let all: Vec<(usize, &Arc<UpstreamTarget>)> = self.targets.iter().enumerate().collect();
            return self
                .select_from_candidates_vec(ctx_key, &all)
                .map(|target| TargetSelection {
                    target,
                    is_fallback: true,
                });
        }
        self.select_from_candidates_vec(ctx_key, &healthy)
            .map(|target| TargetSelection {
                target,
                is_fallback: false,
            })
    }

    /// Vec-based algorithm dispatch (fallback for >128 targets).
    fn select_from_candidates_vec(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }
        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                Some(Arc::clone(candidates[idx % candidates.len()].1))
            }
            LoadBalancerAlgorithm::Random => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let hash = golden_ratio_hash(idx) as usize;
                Some(Arc::clone(candidates[hash % candidates.len()].1))
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr_vec(candidates),
            LoadBalancerAlgorithm::LeastConnections => {
                self.select_least_connections_vec(candidates)
            }
            LoadBalancerAlgorithm::LeastLatency => self.select_least_latency_vec(candidates),
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash_vec(ctx_key, candidates)
            }
        }
    }

    pub fn select_excluding(
        &self,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let n = self.targets.len();
        if n == 0 {
            return None;
        }

        // Find the exclude target's index via linear scan (avoids host.clone() allocation)
        let exclude_idx = self
            .targets
            .iter()
            .position(|t| t.host == exclude.host && t.port == exclude.port);

        // For >128 targets, fall back to Vec-based path.
        if n > MAX_BITSET_TARGETS {
            return self.select_excluding_vec_fallback(ctx_key, exclude_idx, health);
        }

        // Build healthy bitset excluding the specified target
        let mut healthy = self.compute_health_bitset(health);
        if let Some(ei) = exclude_idx {
            healthy.clear(ei);
        }

        if healthy.is_empty() {
            // No healthy targets except excluded — try any target except excluded
            let mut fallback = HealthBitset::all(n);
            if let Some(ei) = exclude_idx {
                fallback.clear(ei);
            }
            if fallback.is_empty() {
                return None;
            }
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let target_idx = fallback.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        self.select_with_bitset(ctx_key, &healthy)
    }

    /// Vec-based fallback for select_excluding() when targets.len() > MAX_BITSET_TARGETS.
    fn select_excluding_vec_fallback(
        &self,
        ctx_key: &str,
        exclude_idx: Option<usize>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let healthy: Vec<(usize, &Arc<UpstreamTarget>)> = self
            .healthy_targets_vec(health)
            .into_iter()
            .filter(|(i, _)| exclude_idx.is_none_or(|ei| ei != *i))
            .collect();

        if healthy.is_empty() {
            let fallback: Vec<(usize, &Arc<UpstreamTarget>)> = self
                .targets
                .iter()
                .enumerate()
                .filter(|(i, _)| exclude_idx.is_none_or(|ei| ei != *i))
                .collect();
            if fallback.is_empty() {
                return None;
            }
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(Arc::clone(fallback[idx % fallback.len()].1));
        }

        self.select_from_candidates_vec(ctx_key, &healthy)
    }

    // ─── Bitset-based algorithm implementations (zero-alloc hot path) ────────

    /// Smooth weighted round-robin (NGINX algorithm) using bitset.
    /// No Vec allocation — iterates targets directly, skipping unset bits.
    fn select_wrr_bitset(&self, healthy: &HealthBitset) -> Option<Arc<UpstreamTarget>> {
        let total_weight: i64 = self
            .targets
            .iter()
            .enumerate()
            .filter(|(i, _)| healthy.contains(*i))
            .map(|(_, t)| t.weight as i64)
            .sum();

        if total_weight == 0 {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let target_idx = healthy.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        let mut weights = self.wrr_state.lock().unwrap_or_else(|e| e.into_inner());
        let mut best_idx = 0;
        let mut best_current = i64::MIN;

        for (i, target) in self.targets.iter().enumerate() {
            if !healthy.contains(i) {
                continue;
            }
            weights[i] += target.weight as i64;
            if weights[i] > best_current {
                best_current = weights[i];
                best_idx = i;
            }
        }

        weights[best_idx] -= total_weight;
        Some(Arc::clone(&self.targets[best_idx]))
    }

    /// Select target with least active connections using bitset.
    fn select_least_connections_bitset(
        &self,
        healthy: &HealthBitset,
    ) -> Option<Arc<UpstreamTarget>> {
        let mut min_conns = i64::MAX;
        let mut best_idx = 0;
        let mut found = false;

        for i in 0..self.targets.len() {
            if !healthy.contains(i) {
                continue;
            }
            let key = &self.host_port_keys[i];
            let conns = self
                .active_connections
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            if !found || conns < min_conns {
                min_conns = conns;
                best_idx = i;
                found = true;
            }
        }

        if found {
            Some(Arc::clone(&self.targets[best_idx]))
        } else {
            None
        }
    }

    /// Select the target with the lowest latency EWMA using bitset.
    ///
    /// See the module-level documentation on `select_least_latency_vec` for
    /// the warm-up / late-joiner / steady-state semantics — this is the
    /// zero-allocation equivalent using a `HealthBitset`.
    fn select_least_latency_bitset(&self, healthy: &HealthBitset) -> Option<Arc<UpstreamTarget>> {
        let hcount = healthy.count();
        if hcount == 0 {
            return None;
        }

        let mut warmed_count = 0usize;
        let mut any_has_data = false;

        for i in 0..self.targets.len() {
            if !healthy.contains(i) {
                continue;
            }
            let key = &self.host_port_keys[i];
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

        // Initial warm-up: round-robin so all targets get baseline measurements.
        if warmed_count == 0 || !any_has_data {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let target_idx = healthy.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        let all_warmed_up = warmed_count == hcount;

        // Find minimum EWMA among warmed candidates (for optimistic fallback).
        let min_known_ewma = if !all_warmed_up {
            let mut min_val = LATENCY_UNSET;
            for i in 0..self.targets.len() {
                if !healthy.contains(i) {
                    continue;
                }
                if let Some(v) = self.latency_ewma.get(&self.host_port_keys[i]) {
                    let val = v.load(Ordering::Relaxed);
                    if val != LATENCY_UNSET && val < min_val {
                        min_val = val;
                    }
                }
            }
            min_val
        } else {
            0 // unused when all warmed up
        };

        // Select the candidate with the lowest EWMA.
        let mut best_latency = u64::MAX;
        let mut best_idx = 0;
        let mut found = false;

        for i in 0..self.targets.len() {
            if !healthy.contains(i) {
                continue;
            }
            let key = &self.host_port_keys[i];
            let samples = self
                .latency_sample_count
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            let latency = if samples >= LATENCY_WARMUP_THRESHOLD {
                self.latency_ewma
                    .get(key)
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(LATENCY_UNSET)
            } else if !all_warmed_up && min_known_ewma != LATENCY_UNSET {
                min_known_ewma.saturating_sub(1)
            } else {
                LATENCY_UNSET
            };
            if !found || latency < best_latency {
                best_latency = latency;
                best_idx = i;
                found = true;
            }
        }

        if best_latency == LATENCY_UNSET {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let target_idx = healthy.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        Some(Arc::clone(&self.targets[best_idx]))
    }

    /// Consistent hash: find the target on the ring closest to the hash of
    /// `ctx_key`. Uses the bitset for O(1) candidate membership check per
    /// ring position instead of O(candidates) linear scan.
    fn select_consistent_hash_bitset(
        &self,
        ctx_key: &str,
        healthy: &HealthBitset,
    ) -> Option<Arc<UpstreamTarget>> {
        if healthy.is_empty() || self.hash_ring.is_empty() {
            return None;
        }

        let hash = fx_hash_str(ctx_key);

        // Binary search on the ring
        let pos = match self.hash_ring.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(p) => p,
            Err(p) => p % self.hash_ring.len(),
        };

        // Walk the ring from pos — O(1) bitset check per position.
        for i in 0..self.hash_ring.len() {
            let ring_idx = (pos + i) % self.hash_ring.len();
            let target_idx = self.hash_ring[ring_idx].1;
            if healthy.contains(target_idx) {
                return Some(Arc::clone(&self.targets[target_idx]));
            }
        }

        // Fallback: first healthy target
        let target_idx = healthy.nth_set_bit(0);
        Some(Arc::clone(&self.targets[target_idx]))
    }

    // ─── Vec-based algorithm implementations (fallback for >128 targets) ─────

    /// Smooth weighted round-robin (NGINX algorithm) — Vec fallback.
    fn select_wrr_vec(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }

        let total_weight: i64 = candidates.iter().map(|(_, t)| t.weight as i64).sum();
        if total_weight == 0 {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(Arc::clone(candidates[idx % candidates.len()].1));
        }

        let mut weights = self.wrr_state.lock().unwrap_or_else(|e| e.into_inner());
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

        let (orig_idx, _) = candidates[best_idx];
        weights[orig_idx] -= total_weight;
        Some(Arc::clone(candidates[best_idx].1))
    }

    /// Select target with least active connections — Vec fallback.
    fn select_least_connections_vec(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }

        let mut min_conns = i64::MAX;
        let mut best = &candidates[0];

        for candidate in candidates {
            let key = &self.host_port_keys[candidate.0];
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

        Some(Arc::clone(best.1))
    }

    /// Select the target with the lowest latency EWMA — Vec fallback.
    ///
    /// **Warm-up phase**: At initial startup, round-robin is used until every
    /// healthy candidate has at least `LATENCY_WARMUP_THRESHOLD` samples.
    ///
    /// **Late joiners / recovery**: Targets without data are treated as having
    /// the current minimum EWMA (optimistic assumption).
    ///
    /// **Steady-state**: Selects the candidate with the lowest EWMA value.
    ///
    /// **No data**: Falls back to round-robin.
    fn select_least_latency_vec(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }

        let mut warmed_count = 0usize;
        let mut any_has_data = false;
        for (idx, _) in candidates {
            let key = &self.host_port_keys[*idx];
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

        if warmed_count == 0 || !any_has_data {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(Arc::clone(candidates[idx % candidates.len()].1));
        }

        let all_warmed_up = warmed_count == candidates.len();

        let min_known_ewma = if !all_warmed_up {
            candidates
                .iter()
                .filter_map(|(idx, _)| {
                    let key = &self.host_port_keys[*idx];
                    self.latency_ewma
                        .get(key)
                        .map(|v| v.load(Ordering::Relaxed))
                        .filter(|&v| v != LATENCY_UNSET)
                })
                .min()
                .unwrap_or(LATENCY_UNSET)
        } else {
            0
        };

        let mut best_latency = u64::MAX;
        let mut best = &candidates[0];

        for candidate in candidates {
            let key = &self.host_port_keys[candidate.0];
            let samples = self
                .latency_sample_count
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            let latency = if samples >= LATENCY_WARMUP_THRESHOLD {
                self.latency_ewma
                    .get(key)
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(LATENCY_UNSET)
            } else if !all_warmed_up && min_known_ewma != LATENCY_UNSET {
                min_known_ewma.saturating_sub(1)
            } else {
                LATENCY_UNSET
            };
            if latency < best_latency {
                best_latency = latency;
                best = candidate;
            }
        }

        if best_latency == LATENCY_UNSET {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(Arc::clone(candidates[idx % candidates.len()].1));
        }

        Some(Arc::clone(best.1))
    }

    /// Consistent hash — Vec fallback. Uses bitset for O(1) candidate
    /// membership check instead of the previous O(candidates) linear scan.
    fn select_consistent_hash_vec(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() || self.hash_ring.is_empty() {
            return None;
        }

        let hash = fx_hash_str(ctx_key);

        // Build a membership set for O(1) candidate check during ring walk.
        // For the >128-target Vec fallback, use a HashSet.
        let candidate_set: std::collections::HashSet<usize> =
            candidates.iter().map(|(i, _)| *i).collect();

        let pos = match self.hash_ring.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(p) => p,
            Err(p) => p % self.hash_ring.len(),
        };

        for i in 0..self.hash_ring.len() {
            let ring_idx = (pos + i) % self.hash_ring.len();
            let target_idx = self.hash_ring[ring_idx].1;
            if candidate_set.contains(&target_idx) {
                return Some(Arc::clone(&self.targets[target_idx]));
            }
        }

        Some(Arc::clone(candidates[0].1))
    }
}
