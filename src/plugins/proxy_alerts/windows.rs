//! Sliding-window state for `proxy_alerts` rule evaluation.
//!
//! Two flavors share the same fixed-bucket layout:
//! - [`BucketedCounter`] for matched-vs-total counters (error_rate,
//!   status_code_count, grpc_status_count, grpc_status_rate, error_class,
//!   stream_disconnect_cause).
//! - [`BucketedLatencyHistogram`] for percentile estimation against a fixed
//!   log-scale bin layout.
//!
//! The window is split into `N_BUCKETS` sub-buckets. Each sub-bucket carries
//! a timestamp-tag that detects rollover: when a new sample lands in a slot
//! whose tag points at an older epoch, the slot is reset (counters cleared)
//! before being incremented.
//!
//! Bucket tags and eviction cutoffs are process-monotonic milliseconds (see
//! [`monotonic_now_ms`]), not Unix wall time. Elapsed-window aging therefore
//! follows process elapsed time; NTP/administrator wall-clock steps do not
//! freeze or prematurely expire samples. Snapshots and eviction also reject
//! future-dated tags so an injected or discontinuous backward step cannot
//! treat pre-step samples as age-zero forever.
//!
//! All operations use atomics only. `record()` does at most:
//! - 1 atomic load on the slot tag in the common case
//! - 1 CAS + counter resets when the slot rolls over (rare)
//! - 1–2 atomic fetch_adds on the slot's counters
//!
//! `snapshot()` does N_BUCKETS atomic loads. No allocation on either path.
//!
//! One minor race is intentional:
//! - A `snapshot()` may see a partial bucket mid-update or skip a bucket while
//!   its rollover reset is in progress.
//!
//! Both are acceptable for alerting where threshold breaches sustain across
//! many buckets and individual samples are not load-bearing.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use super::generation_map::GenerationMap;
use crate::util::sharding::pool_shard_amount;

const N_BUCKETS: usize = 10;
const RESETTING_EPOCH: u64 = u64::MAX;

/// Upper bounds (exclusive) of latency histogram buckets, in milliseconds.
/// Bucket `i` covers `[upper[i-1], upper[i])` for `i > 0` and `[0, upper[0])`
/// for `i = 0`. The final bucket (index `LATENCY_BUCKET_COUNT - 1`) covers
/// `[upper[last], +∞)`.
const LATENCY_UPPER_BOUNDS_MS: [u64; 15] = [
    5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10_000, 30_000, 60_000, 120_000, 300_000,
];
pub const MAX_FINITE_LATENCY_BOUND_MS: u64 =
    LATENCY_UPPER_BOUNDS_MS[LATENCY_UPPER_BOUNDS_MS.len() - 1];
const LATENCY_BUCKET_COUNT: usize = LATENCY_UPPER_BOUNDS_MS.len() + 1;

#[derive(Debug)]
pub struct AtomicBucket {
    epoch_index: AtomicU64,
    matched: AtomicU64,
    total: AtomicU64,
}

impl Default for AtomicBucket {
    fn default() -> Self {
        Self {
            epoch_index: AtomicU64::new(0),
            matched: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
pub struct BucketedCounter {
    buckets: Box<[AtomicBucket]>,
    bucket_ms: u64,
}

impl BucketedCounter {
    pub fn new(window_seconds: u32) -> Self {
        let window_ms = u64::from(window_seconds.max(1)) * 1000;
        let bucket_ms = (window_ms / N_BUCKETS as u64).max(1);
        Self {
            buckets: (0..N_BUCKETS).map(|_| AtomicBucket::default()).collect(),
            bucket_ms,
        }
    }

    pub fn record(&self, matched: bool, now_ms: u64) {
        let tag = now_ms / self.bucket_ms;
        let slot = (tag % self.buckets.len() as u64) as usize;
        let bucket = &self.buckets[slot];
        prepare_counter_bucket(bucket, tag);
        if matched {
            bucket.matched.fetch_add(1, Ordering::Relaxed);
        }
        bucket.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns `(matched, total)` summed across buckets currently within the
    /// window relative to `now_ms`.
    ///
    /// Future-dated tags (`tag > cur_tag`) are excluded so a backward clock
    /// discontinuity cannot keep pre-step samples age-zero via saturating
    /// subtraction.
    pub fn snapshot(&self, now_ms: u64) -> (u64, u64) {
        let cur_tag = now_ms / self.bucket_ms;
        let max_age = self.buckets.len() as u64;
        let mut matched = 0u64;
        let mut total = 0u64;
        for bucket in self.buckets.iter() {
            let tag = bucket.epoch_index.load(Ordering::Acquire);
            if tag_within_window(tag, cur_tag, max_age) {
                matched = matched.saturating_add(bucket.matched.load(Ordering::Relaxed));
                total = total.saturating_add(bucket.total.load(Ordering::Relaxed));
            }
        }
        (matched, total)
    }

    pub fn last_record_ms(&self) -> u64 {
        self.buckets
            .iter()
            .map(|b| epoch_to_record_ms(b.epoch_index.load(Ordering::Acquire), self.bucket_ms))
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct LatencyBucket {
    epoch_index: AtomicU64,
    counts: [AtomicU64; LATENCY_BUCKET_COUNT],
}

impl Default for LatencyBucket {
    fn default() -> Self {
        Self {
            epoch_index: AtomicU64::new(0),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

#[derive(Debug)]
pub struct BucketedLatencyHistogram {
    buckets: Box<[LatencyBucket]>,
    bucket_ms: u64,
}

impl BucketedLatencyHistogram {
    pub fn new(window_seconds: u32) -> Self {
        let window_ms = u64::from(window_seconds.max(1)) * 1000;
        let bucket_ms = (window_ms / N_BUCKETS as u64).max(1);
        Self {
            buckets: (0..N_BUCKETS).map(|_| LatencyBucket::default()).collect(),
            bucket_ms,
        }
    }

    pub fn record(&self, latency_ms: f64, now_ms: u64) {
        let tag = now_ms / self.bucket_ms;
        let slot = (tag % self.buckets.len() as u64) as usize;
        let bucket = &self.buckets[slot];
        prepare_latency_bucket(bucket, tag);
        let idx = bucket_index_for(latency_ms);
        bucket.counts[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns `(estimated_percentile_upper_bound_ms, total_samples)`.
    /// `percentile` is clamped to `[1, 99]`.
    ///
    /// Future-dated tags are excluded; see [`BucketedCounter::snapshot`].
    pub fn percentile(&self, percentile: u8, now_ms: u64) -> (Option<f64>, u64) {
        let cur_tag = now_ms / self.bucket_ms;
        let max_age = self.buckets.len() as u64;
        let mut totals = [0u64; LATENCY_BUCKET_COUNT];
        let mut total = 0u64;
        for bucket in self.buckets.iter() {
            let tag = bucket.epoch_index.load(Ordering::Acquire);
            if tag_within_window(tag, cur_tag, max_age) {
                for (idx, slot) in bucket.counts.iter().enumerate() {
                    let v = slot.load(Ordering::Relaxed);
                    totals[idx] = totals[idx].saturating_add(v);
                    total = total.saturating_add(v);
                }
            }
        }
        if total == 0 {
            return (None, 0);
        }
        let pct = percentile.clamp(1, 99) as f64;
        let target = ((pct / 100.0) * total as f64).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;
        for (idx, count) in totals.iter().enumerate() {
            cumulative = cumulative.saturating_add(*count);
            if cumulative >= target {
                let upper = if idx < LATENCY_UPPER_BOUNDS_MS.len() {
                    LATENCY_UPPER_BOUNDS_MS[idx] as f64
                } else {
                    f64::INFINITY
                };
                return (Some(upper), total);
            }
        }
        (Some(f64::INFINITY), total)
    }

    pub fn last_record_ms(&self) -> u64 {
        self.buckets
            .iter()
            .map(|b| epoch_to_record_ms(b.epoch_index.load(Ordering::Acquire), self.bucket_ms))
            .max()
            .unwrap_or(0)
    }
}

fn prepare_counter_bucket(bucket: &AtomicBucket, tag: u64) {
    loop {
        match bucket.epoch_index.load(Ordering::Acquire) {
            current if current == tag => return,
            RESETTING_EPOCH => std::hint::spin_loop(),
            current => {
                if bucket
                    .epoch_index
                    .compare_exchange(
                        current,
                        RESETTING_EPOCH,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    bucket.matched.store(0, Ordering::Relaxed);
                    bucket.total.store(0, Ordering::Relaxed);
                    bucket.epoch_index.store(tag, Ordering::Release);
                    return;
                }
            }
        }
    }
}

fn prepare_latency_bucket(bucket: &LatencyBucket, tag: u64) {
    loop {
        match bucket.epoch_index.load(Ordering::Acquire) {
            current if current == tag => return,
            RESETTING_EPOCH => std::hint::spin_loop(),
            current => {
                if bucket
                    .epoch_index
                    .compare_exchange(
                        current,
                        RESETTING_EPOCH,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    for c in bucket.counts.iter() {
                        c.store(0, Ordering::Relaxed);
                    }
                    bucket.epoch_index.store(tag, Ordering::Release);
                    return;
                }
            }
        }
    }
}

fn epoch_to_record_ms(tag: u64, bucket_ms: u64) -> u64 {
    if tag == RESETTING_EPOCH {
        0
    } else {
        tag.saturating_mul(bucket_ms)
    }
}

#[inline]
fn tag_within_window(tag: u64, current_tag: u64, max_age: u64) -> bool {
    tag != RESETTING_EPOCH && tag <= current_tag && current_tag - tag < max_age
}

fn bucket_index_for(latency_ms: f64) -> usize {
    if !latency_ms.is_finite() || latency_ms < 0.0 {
        return 0;
    }
    let v = latency_ms as u64;
    for (i, &upper) in LATENCY_UPPER_BOUNDS_MS.iter().enumerate() {
        if v < upper {
            return i;
        }
    }
    LATENCY_BUCKET_COUNT - 1
}

#[derive(Debug)]
pub enum WindowState {
    Counter(BucketedCounter),
    Histogram(BucketedLatencyHistogram),
}

impl WindowState {
    fn last_record_ms(&self) -> u64 {
        match self {
            Self::Counter(c) => c.last_record_ms(),
            Self::Histogram(h) => h.last_record_ms(),
        }
    }
}

/// Rule-window kind used at construction so the store knows which variant
/// to lazily initialize on first record.
#[derive(Debug, Clone, Copy)]
pub enum WindowKind {
    Counter,
    Histogram,
}

/// Per-rule metadata the store needs to lazily create windows on first
/// observation.
#[derive(Debug, Clone, Copy)]
pub struct RuleWindowSpec {
    pub window_seconds: u32,
    pub kind: WindowKind,
}

/// `(rule_id → proxy_id → ownership_generation → WindowState)` map.
///
/// Outer rule/proxy DashMaps use `pool_shard_amount` and avoid composite string
/// keys on the hot path (`proxy_id` uses `String: Borrow<str>`). The generation
/// dimension is a compact [`GenerationMap`] of `Arc<WindowState>` so typically
/// one live incarnation does not pay for a fully pool-sharded DashMap. An
/// established generation is resolved through the map's lock-free `ArcSwap`
/// snapshot (no mutex), and record/snapshot then run on the window atomics.
/// Rule evaluation uses the fused [`WindowStore::record_count_and_snapshot`] /
/// [`WindowStore::record_latency_and_percentile`] so one sample walks the
/// store once per rule.
type GenerationWindows = GenerationMap<Arc<WindowState>>;
type ProxyWindows = DashMap<String, Arc<GenerationWindows>>;
type RuleWindows = DashMap<u32, Arc<ProxyWindows>>;

pub struct WindowStore {
    by_rule: RuleWindows,
    rule_specs: HashMap<u32, RuleWindowSpec>,
    inner_shard_amount: usize,
}

impl WindowStore {
    pub fn new(rule_specs: HashMap<u32, RuleWindowSpec>) -> Self {
        Self::with_shard_amount(rule_specs, pool_shard_amount(0))
    }

    /// `shard_amount` must already be normalized (a power of two >= 2), as
    /// `PluginHttpClient::pool_shard_amount()` returns it.
    pub fn with_shard_amount(
        rule_specs: HashMap<u32, RuleWindowSpec>,
        shard_amount: usize,
    ) -> Self {
        Self {
            by_rule: DashMap::with_shard_amount(shard_amount),
            rule_specs,
            inner_shard_amount: shard_amount,
        }
    }

    fn inner_for(&self, rule_id: u32) -> Option<Arc<ProxyWindows>> {
        if let Some(existing) = self.by_rule.get(&rule_id) {
            return Some(Arc::clone(existing.value()));
        }
        let shard_amount = self.inner_shard_amount;
        let entry = self
            .by_rule
            .entry(rule_id)
            .or_insert_with(|| Arc::new(DashMap::with_shard_amount(shard_amount)));
        Some(Arc::clone(entry.value()))
    }

    fn generations_for(&self, rule_id: u32, proxy_id: &str) -> Option<Arc<GenerationWindows>> {
        let inner = self.inner_for(rule_id)?;
        if let Some(existing) = inner.get(proxy_id) {
            return Some(Arc::clone(existing.value()));
        }
        let entry = inner
            .entry(proxy_id.to_string())
            .or_insert_with(|| Arc::new(GenerationMap::new()));
        Some(Arc::clone(entry.value()))
    }

    fn window_for_generation(
        generations: &GenerationWindows,
        ownership_generation: u64,
        spec: RuleWindowSpec,
    ) -> Arc<WindowState> {
        generations.get_or_insert_with(ownership_generation, || {
            Arc::new(match spec.kind {
                WindowKind::Counter => {
                    WindowState::Counter(BucketedCounter::new(spec.window_seconds))
                }
                WindowKind::Histogram => {
                    WindowState::Histogram(BucketedLatencyHistogram::new(spec.window_seconds))
                }
            })
        })
    }

    pub fn record_count(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        matched: bool,
        now_ms: u64,
    ) {
        let Some(spec) = self.rule_specs.get(&rule_id).copied() else {
            return;
        };
        let Some(generations) = self.generations_for(rule_id, proxy_id) else {
            return;
        };
        let state = Self::window_for_generation(&generations, ownership_generation, spec);
        if let WindowState::Counter(c) = state.as_ref() {
            c.record(matched, now_ms);
        }
    }

    #[allow(dead_code)] // Rule evaluation uses the fused path; kept for tests.
    pub fn record_latency(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        latency_ms: f64,
        now_ms: u64,
    ) {
        let Some(spec) = self.rule_specs.get(&rule_id).copied() else {
            return;
        };
        let Some(generations) = self.generations_for(rule_id, proxy_id) else {
            return;
        };
        let state = Self::window_for_generation(&generations, ownership_generation, spec);
        if let WindowState::Histogram(h) = state.as_ref() {
            h.record(latency_ms, now_ms);
        }
    }

    /// Record one counter sample and return the window's `(matched, total)`
    /// at `now_ms`, resolving the window row once.
    pub fn record_count_and_snapshot(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        matched: bool,
        now_ms: u64,
    ) -> (u64, u64) {
        let Some(spec) = self.rule_specs.get(&rule_id).copied() else {
            return (0, 0);
        };
        let Some(generations) = self.generations_for(rule_id, proxy_id) else {
            return (0, 0);
        };
        let state = Self::window_for_generation(&generations, ownership_generation, spec);
        match state.as_ref() {
            WindowState::Counter(c) => {
                c.record(matched, now_ms);
                c.snapshot(now_ms)
            }
            WindowState::Histogram(_) => (0, 0),
        }
    }

    /// Record one latency sample and return the window's
    /// `(estimated_percentile_upper_bound_ms, total)` at `now_ms`, resolving the
    /// window row once.
    pub fn record_latency_and_percentile(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        latency_ms: f64,
        percentile: u8,
        now_ms: u64,
    ) -> (Option<f64>, u64) {
        let Some(spec) = self.rule_specs.get(&rule_id).copied() else {
            return (None, 0);
        };
        let Some(generations) = self.generations_for(rule_id, proxy_id) else {
            return (None, 0);
        };
        let state = Self::window_for_generation(&generations, ownership_generation, spec);
        match state.as_ref() {
            WindowState::Histogram(h) => {
                h.record(latency_ms, now_ms);
                h.percentile(percentile, now_ms)
            }
            WindowState::Counter(_) => (None, 0),
        }
    }

    /// Run `f` while the generation-map writer mutex for `(rule_id, proxy_id)`
    /// is held. Returns `None` when no window row exists yet.
    ///
    /// Test-only hook proving established record/snapshot lookups are served
    /// from the lock-free snapshot rather than waiting on that mutex.
    #[doc(hidden)]
    #[allow(dead_code)] // External test crate only.
    pub fn with_generation_writer_lock_for_test<R>(
        &self,
        rule_id: u32,
        proxy_id: &str,
        f: impl FnOnce() -> R,
    ) -> Option<R> {
        let generations = {
            let inner = self.by_rule.get(&rule_id)?;
            let generations = inner.get(proxy_id)?;
            Arc::clone(generations.value())
        };
        Some(generations.with_writer_lock_held(f))
    }

    pub fn snapshot_count(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        now_ms: u64,
    ) -> (u64, u64) {
        let Some(inner) = self.by_rule.get(&rule_id) else {
            return (0, 0);
        };
        let Some(generations) = inner.get(proxy_id) else {
            return (0, 0);
        };
        let Some(state) = generations.get_cloned(&ownership_generation) else {
            return (0, 0);
        };
        match state.as_ref() {
            WindowState::Counter(c) => c.snapshot(now_ms),
            WindowState::Histogram(_) => (0, 0),
        }
    }

    pub fn snapshot_percentile(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
        percentile: u8,
        now_ms: u64,
    ) -> (Option<f64>, u64) {
        let Some(inner) = self.by_rule.get(&rule_id) else {
            return (None, 0);
        };
        let Some(generations) = inner.get(proxy_id) else {
            return (None, 0);
        };
        let Some(state) = generations.get_cloned(&ownership_generation) else {
            return (None, 0);
        };
        match state.as_ref() {
            WindowState::Histogram(h) => h.percentile(percentile, now_ms),
            WindowState::Counter(_) => (None, 0),
        }
    }

    /// Drop entries that have not been written to in the last `keep_ms`.
    /// Called periodically by the eviction sweep task.
    pub fn evict_stale(&self, now_ms: u64, keep_ms: u64) {
        let cutoff = now_ms.saturating_sub(keep_ms);
        for outer in self.by_rule.iter() {
            outer.value().retain(|_, generations| {
                generations.retain(|_, state| {
                    let last_record_ms = state.last_record_ms();
                    last_record_ms <= now_ms && last_record_ms >= cutoff
                });
                !generations.is_empty()
            });
        }
    }

    /// Drop window rows for proxies absent from `active_proxy_generations`
    /// or whose stored generation does not match the published incarnation.
    ///
    /// Cold-path only: paired with cooldown/recovery retention so a delete
    /// and recreate of the same proxy ID cannot inherit prior samples.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        for outer in self.by_rule.iter() {
            outer.value().retain(|proxy_id, generations| {
                match active_proxy_generations.get(proxy_id.as_str()).copied() {
                    Some(active_gen) => {
                        generations.retain(|&generation, _| generation == active_gen);
                        !generations.is_empty()
                    }
                    None => false,
                }
            });
        }
    }

    /// Whether any rule window currently holds a row for `proxy_id` under any
    /// ownership generation.
    #[allow(dead_code)] // Used by external test crate and admin/debug helpers.
    pub fn contains_proxy(&self, proxy_id: &str) -> bool {
        self.by_rule.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| !generations.is_empty())
        })
    }

    /// Whether any rule window holds a row for `(proxy_id, generation)`.
    #[allow(dead_code)] // Used by external test crate.
    pub fn contains_proxy_generation(&self, proxy_id: &str, ownership_generation: u64) -> bool {
        self.by_rule.iter().any(|entry| {
            entry
                .value()
                .get(proxy_id)
                .is_some_and(|generations| generations.contains_key(&ownership_generation))
        })
    }
}

/// Process-monotonic milliseconds used by every elapsed-time surface in this
/// plugin. Zero remains reserved as the cooldown "never sent" sentinel.
#[inline]
pub fn monotonic_now_ms() -> u64 {
    crate::socket_opts::monotonic_now_ms().saturating_add(1)
}
