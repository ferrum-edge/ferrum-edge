//! Sliding-window state for `proxy_alerts` rule evaluation.
//!
//! Two flavors share the same fixed-bucket layout:
//! - [`BucketedCounter`] for matched-vs-total counters (error_rate,
//!   status_code_count, error_class, stream_disconnect_cause).
//! - [`BucketedLatencyHistogram`] for percentile estimation against a fixed
//!   log-scale bin layout.
//!
//! The window is split into `N_BUCKETS` sub-buckets. Each sub-bucket carries
//! a timestamp-tag that detects rollover: when a new sample lands in a slot
//! whose tag points at an older epoch, the slot is reset (counters cleared)
//! before being incremented.
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
use std::time::Duration;

use dashmap::DashMap;

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
    pub fn snapshot(&self, now_ms: u64) -> (u64, u64) {
        let cur_tag = now_ms / self.bucket_ms;
        let max_age = self.buckets.len() as u64;
        let mut matched = 0u64;
        let mut total = 0u64;
        for bucket in self.buckets.iter() {
            let tag = bucket.epoch_index.load(Ordering::Acquire);
            if tag != RESETTING_EPOCH && cur_tag.saturating_sub(tag) < max_age {
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
    pub fn percentile(&self, percentile: u8, now_ms: u64) -> (Option<f64>, u64) {
        let cur_tag = now_ms / self.bucket_ms;
        let max_age = self.buckets.len() as u64;
        let mut totals = [0u64; LATENCY_BUCKET_COUNT];
        let mut total = 0u64;
        for bucket in self.buckets.iter() {
            let tag = bucket.epoch_index.load(Ordering::Acquire);
            if tag != RESETTING_EPOCH && cur_tag.saturating_sub(tag) < max_age {
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

/// `(rule_id → proxy_id → WindowState)` two-level map. The outer DashMap
/// avoids needing to allocate a composite key on the hot path; the inner
/// map can be looked up by `&str` thanks to `String: Borrow<str>`.
pub struct WindowStore {
    by_rule: DashMap<u32, Arc<DashMap<String, WindowState>>>,
    rule_specs: HashMap<u32, RuleWindowSpec>,
    inner_shard_amount: usize,
}

impl WindowStore {
    pub fn new(rule_specs: HashMap<u32, RuleWindowSpec>) -> Self {
        let shard_amount = pool_shard_amount(0);
        Self {
            by_rule: DashMap::with_shard_amount(shard_amount),
            rule_specs,
            inner_shard_amount: shard_amount,
        }
    }

    fn inner_for(&self, rule_id: u32) -> Option<Arc<DashMap<String, WindowState>>> {
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

    pub fn record_count(&self, rule_id: u32, proxy_id: &str, matched: bool, now_ms: u64) {
        let Some(spec) = self.rule_specs.get(&rule_id).copied() else {
            return;
        };
        let Some(inner) = self.inner_for(rule_id) else {
            return;
        };
        if let Some(state) = inner.get(proxy_id)
            && let WindowState::Counter(c) = state.value()
        {
            c.record(matched, now_ms);
            return;
        }
        let entry = inner
            .entry(proxy_id.to_string())
            .or_insert_with(|| match spec.kind {
                WindowKind::Counter => {
                    WindowState::Counter(BucketedCounter::new(spec.window_seconds))
                }
                WindowKind::Histogram => {
                    WindowState::Histogram(BucketedLatencyHistogram::new(spec.window_seconds))
                }
            });
        if let WindowState::Counter(c) = entry.value() {
            c.record(matched, now_ms);
        }
    }

    pub fn record_latency(&self, rule_id: u32, proxy_id: &str, latency_ms: f64, now_ms: u64) {
        let Some(spec) = self.rule_specs.get(&rule_id).copied() else {
            return;
        };
        let Some(inner) = self.inner_for(rule_id) else {
            return;
        };
        if let Some(state) = inner.get(proxy_id)
            && let WindowState::Histogram(h) = state.value()
        {
            h.record(latency_ms, now_ms);
            return;
        }
        let entry = inner
            .entry(proxy_id.to_string())
            .or_insert_with(|| match spec.kind {
                WindowKind::Counter => {
                    WindowState::Counter(BucketedCounter::new(spec.window_seconds))
                }
                WindowKind::Histogram => {
                    WindowState::Histogram(BucketedLatencyHistogram::new(spec.window_seconds))
                }
            });
        if let WindowState::Histogram(h) = entry.value() {
            h.record(latency_ms, now_ms);
        }
    }

    pub fn snapshot_count(&self, rule_id: u32, proxy_id: &str, now_ms: u64) -> (u64, u64) {
        let Some(inner) = self.by_rule.get(&rule_id) else {
            return (0, 0);
        };
        let Some(state) = inner.get(proxy_id) else {
            return (0, 0);
        };
        match state.value() {
            WindowState::Counter(c) => c.snapshot(now_ms),
            WindowState::Histogram(_) => (0, 0),
        }
    }

    pub fn snapshot_percentile(
        &self,
        rule_id: u32,
        proxy_id: &str,
        percentile: u8,
        now_ms: u64,
    ) -> (Option<f64>, u64) {
        let Some(inner) = self.by_rule.get(&rule_id) else {
            return (None, 0);
        };
        let Some(state) = inner.get(proxy_id) else {
            return (None, 0);
        };
        match state.value() {
            WindowState::Histogram(h) => h.percentile(percentile, now_ms),
            WindowState::Counter(_) => (None, 0),
        }
    }

    /// Drop entries that have not been written to in the last `keep_ms`.
    /// Called periodically by the eviction sweep task.
    pub fn evict_stale(&self, now_ms: u64, keep_ms: u64) {
        let cutoff = now_ms.saturating_sub(keep_ms);
        for outer in self.by_rule.iter() {
            outer
                .value()
                .retain(|_, state| state.last_record_ms() >= cutoff);
        }
    }
}

impl WindowStore {
    /// Spawn a background task that periodically evicts stale entries when
    /// called from inside a Tokio runtime.
    ///
    /// Validation paths can instantiate plugins outside a runtime, so this is
    /// deliberately best-effort. Runtime plugin instances keep the returned
    /// handle and abort it on drop.
    pub fn start_eviction_task(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return None;
        };
        let store = Arc::clone(self);
        Some(handle.spawn(async move {
            // Eviction cadence chosen to be coarse — staleness is determined
            // by per-rule window length, and inactive proxies just take a
            // bit longer to free up.
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                let now_ms = current_epoch_ms();
                // Keep entries that recorded within the last hour OR the
                // largest window (whichever is greater). 1h is a generous
                // floor that covers all reasonable rule windows.
                store.evict_stale(now_ms, 3_600_000);
            }
        }))
    }
}

pub fn current_epoch_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
