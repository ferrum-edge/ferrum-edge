//! Load balancer for distributing requests across upstream targets.
//!
//! Supports multiple algorithms: round-robin, weighted round-robin,
//! least connections, least latency, consistent hashing, and random.

use crate::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, LocalityPreference, Proxy, SubsetDefinition, Upstream,
    UpstreamLocalityLbSetting, UpstreamPortOverride, UpstreamTarget,
};
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

fn build_hash_ring_for_indices<I>(host_port_keys: &[String], indices: I) -> Vec<(u64, usize)>
where
    I: IntoIterator<Item = usize>,
{
    let mut hash_ring = Vec::new();
    for idx in indices {
        let Some(key) = host_port_keys.get(idx) else {
            continue;
        };
        // 150 virtual nodes per target for better distribution
        for vnode in 0..150 {
            let vnode_key = format!("{}:{}", key, vnode);
            hash_ring.push((fx_hash_str(&vnode_key), idx));
        }
    }
    hash_ring.sort_by_key(|&(hash, _)| hash);
    hash_ring
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

    /// Build a bitset directly from a raw `u128` mask, recomputing `len` from
    /// the population count. Used to construct candidate masks (e.g. subset∩port)
    /// without a per-request `Vec` — the result stays a stack `u128`.
    #[inline]
    fn from_bits(bits: u128) -> Self {
        Self {
            bits,
            len: bits.count_ones() as u8,
        }
    }

    /// Intersection of two bitsets (`self & other`) as a new stack `u128`.
    /// Alloc-free analogue of intersecting two index slices.
    #[inline]
    fn intersect(&self, other: &Self) -> Self {
        Self::from_bits(self.bits & other.bits)
    }

    /// Invoke `f` once per set bit, in ascending index order, without
    /// allocating. Iterates by repeatedly reading and clearing the lowest set
    /// bit — O(popcount) on register-width integers.
    #[inline]
    fn for_each_set_bit(&self, mut f: impl FnMut(usize)) {
        let mut remaining = self.bits;
        while remaining != 0 {
            let idx = remaining.trailing_zeros() as usize;
            f(idx);
            remaining &= remaining - 1; // clear lowest set bit
        }
    }
}

fn bitset_for_indices(indices: &[usize]) -> HealthBitset {
    let mut bitset = HealthBitset::empty();
    for &idx in indices {
        debug_assert!(idx < MAX_BITSET_TARGETS);
        if idx < MAX_BITSET_TARGETS {
            bitset.set(idx);
        }
    }
    bitset
}

fn membership_mask_for_indices(len: usize, indices: &[usize]) -> Vec<bool> {
    let mut mask = vec![false; len];
    for &idx in indices {
        if let Some(slot) = mask.get_mut(idx) {
            *slot = true;
        }
    }
    mask
}

use crossbeam_utils::CachePadded;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Cap on a precomputed smooth-WRR schedule length.
///
/// Normal weights produce `sum(weight)/gcd` entries (often tens). Pathological
/// huge periods are proportionally apportioned into this many entries while
/// retaining at least one entry for every positive-weight target.
const WRR_MAX_SCHEDULE_LEN: usize = 8192;

/// Maximum smooth-WRR construction work (`schedule_steps × positive_candidates`)
/// before publishing a lottery-only sentinel instead of running the quadratic
/// NGINX loop on a Tokio worker.
///
/// Ordinary sets (small candidate counts and uncapped or modest periods) stay
/// well under this budget and retain exact smooth-WRR sequences. The bound is
/// `WRR_MAX_SCHEDULE_LEN × MAX_BITSET_TARGETS` (8192 × 128): a full bitset-path
/// capped period is still buildable, while pathologically large candidate ×
/// period products fall back. Oversized builds publish an exact-key empty-order
/// schedule (`!zero_weight`) so the same fingerprint does not repeatedly retry
/// the expensive construction; steady hits then use the allocation-free
/// weighted-lottery / all-zero round-robin path.
const WRR_SMOOTH_BUILD_MAX_WORK: u64 = (WRR_MAX_SCHEDULE_LEN as u64) * (MAX_BITSET_TARGETS as u64);

/// Bound on concurrently cached healthy-set schedules per WRR lane.
///
/// One [`LoadBalancer`] is shared for an upstream, but per-proxy passive health,
/// retry exclusions, and locality candidate sets produce distinct fingerprints.
/// Caching several recurring fingerprints avoids thrashing a single slot (and
/// the rebuild path) under realistic shared-upstream traffic.
const WRR_SCHEDULE_CACHE_SLOTS: usize = 8;

/// After the fingerprint cache is full, attempt a schedule publish at most once
/// per this many locked miss decisions.
///
/// Cold-start fills of empty slots are uncapped. Sustained churn beyond
/// [`WRR_SCHEDULE_CACHE_SLOTS`] therefore cannot rebuild/allocate a smooth
/// schedule on every request; unsampled misses use the allocation-free
/// candidate scan instead.
const WRR_MISS_PUBLISH_SAMPLE: u64 = 64;

/// Per-schedule selection-counter shards (power of two).
///
/// Small healthy sets make a single shared `AtomicU64` the throughput ceiling:
/// concurrent workers bounce one cache line on every pick and can fall *below*
/// single-thread throughput. Sharded, cache-line-padded counters keep each
/// worker on its own line while every shard still walks the same precomputed
/// smooth-WRR order (the schedule-defined long-run ratios are preserved;
/// workers no longer share one global interleaving).
const WRR_COUNTER_SHARDS: usize = 16;

/// Exact cache key for one healthy target set.
#[derive(Debug)]
enum WrrScheduleKey {
    Invalid,
    Bitset(u128),
    Indices(Box<[usize]>),
}

/// Precomputed smooth weighted round-robin order for one healthy fingerprint.
///
/// Built on the cold path when a fingerprint miss is allowed to publish into
/// the lane cache (empty-slot fill or rate-sampled replacement); steady-state
/// selection only loads a matching slot via [`ArcSwap`] and advances one
/// sharded [`AtomicU64`]. Unsampled / contended misses never construct this
/// value — they use the allocation-free candidate scan instead.
///
/// # Order / flag contract
///
/// - Non-empty `order`, `zero_weight == false`: exact or weight-bounded smooth
///   WRR walk.
/// - Empty `order`, `zero_weight == true`: all-zero weights — round-robin over
///   the current healthy set via shard counters.
/// - Empty `order`, `zero_weight == false`, non-[`Invalid`] key: **lottery-only
///   sentinel** published when smooth construction would exceed
///   [`WRR_SMOOTH_BUILD_MAX_WORK`]. Hits use the allocation-free weighted
///   lottery (or all-zero RR if weights are later all zero) and never retry the
///   quadratic build for this exact key.
struct WrrSchedule {
    /// Exact healthy-set identity. The >128-target path retains its indices so
    /// a hash collision can never reuse a schedule for the wrong candidate set.
    key: WrrScheduleKey,
    /// Per-worker counter shards. Each cached healthy set keeps its own shard
    /// set so alternating fingerprints cannot alias onto one counter parity.
    counters: [CachePadded<AtomicU64>; WRR_COUNTER_SHARDS],
    /// Target indices in NGINX smooth-WRR order for one exact or proportionally
    /// bounded weight period. Empty for inactive/invalid, all-zero, or
    /// lottery-only sentinel schedules (see struct docs).
    order: Box<[usize]>,
    /// When true, selection uses this schedule's counter over healthy targets
    /// (all-zero weight round-robin). When false with an empty `order` and a
    /// real key, the schedule is a lottery-only sentinel.
    zero_weight: bool,
}

impl WrrSchedule {
    fn invalid() -> Self {
        Self {
            key: WrrScheduleKey::Invalid,
            counters: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
            order: Box::new([]),
            zero_weight: false,
        }
    }

    /// `healthy_count` is used only for all-zero schedules (`zero_weight`): it
    /// spreads shard phases across the healthy candidate count so independent
    /// shards do not start lockstep on the same RR offset. Pass `0` when
    /// unused (smooth or lottery-only).
    fn with_seed(
        key: WrrScheduleKey,
        order: Box<[usize]>,
        zero_weight: bool,
        seed: u64,
        healthy_count: usize,
    ) -> Self {
        // Deterministic stride across the healthy set: shard_i starts at
        // seed + i × max(1, healthy_count / WRR_COUNTER_SHARDS).
        let zero_phase_stride = (healthy_count / WRR_COUNTER_SHARDS).max(1) as u64;
        Self {
            key,
            // Distinct per-shard phases avoid lockstep bursts when many workers
            // start together; ratios are unchanged because each shard is itself
            // a full smooth-WRR walk of `order` (or RR/lottery over the set).
            counters: std::array::from_fn(|i| {
                let initial = if zero_weight {
                    seed.wrapping_add((i as u64).wrapping_mul(zero_phase_stride))
                } else {
                    seed.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15))
                };
                CachePadded::new(AtomicU64::new(initial))
            }),
            order,
            zero_weight,
        }
    }

    /// True when this cached schedule is a work-budget lottery-only sentinel.
    #[inline]
    fn is_lottery_only(&self) -> bool {
        self.order.is_empty() && !self.zero_weight && !matches!(self.key, WrrScheduleKey::Invalid)
    }
}

/// Assign a stable counter shard for the current OS thread.
#[inline]
fn wrr_counter_shard() -> usize {
    thread_local! {
        static SHARD: Cell<usize> = const { Cell::new(usize::MAX) };
    }
    SHARD.with(|cell| {
        let current = cell.get();
        if current < WRR_COUNTER_SHARDS {
            return current;
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let assigned = (NEXT.fetch_add(1, Ordering::Relaxed) as usize) & (WRR_COUNTER_SHARDS - 1);
        cell.set(assigned);
        assigned
    })
}

/// Per-lane smooth-WRR state shared by parent, subset, and port selectors.
///
/// # Concurrency / distribution tradeoff
///
/// Steady-state selection is **wait-free**: each request scans the bounded
/// [`ArcSwap`] schedule slots for the current healthy fingerprint, then does
/// one sharded per-schedule [`AtomicU64::fetch_add`] to pick the next index.
/// Concurrent Tokio workers therefore scale across cores without taking a
/// blocking mutex on the hot path — including when several recurring
/// fingerprints alternate. Each worker shard walks the same precomputed
/// smooth-WRR order, so uncapped cached periods retain exact configured ratios;
/// workers do **not** share a single global interleaving (the intentional
/// contention tradeoff).
///
/// On a cache miss, publishers use `Mutex::try_lock` so rebuilds stay
/// contention-bounded and never block the hot path. Empty cache slots fill
/// immediately; once the cache is full, further publishes are rate-sampled
/// ([`WRR_MISS_PUBLISH_SAMPLE`]). Contending missers and unsampled misses
/// **never** build an ephemeral smooth schedule — they take an allocation-free
/// O(candidate) weighted lottery (or all-zero round-robin) over eligible
/// positive-weight targets. That fallback preserves reachability and safety
/// but does **not** claim exact smooth-WRR interleaving. The lock is never
/// held across `.await`.
///
/// # Why there is no invalidate flag
///
/// A schedule is a pure function of `(fingerprint, immutable target weights)`
/// for a given [`LoadBalancer`] generation. Config reload swaps the balancer
/// `Arc` through [`LoadBalancerCache`]'s `ArcSwap`, so schedules cannot bleed
/// across target-set generations. Recovering a target either changes the
/// fingerprint (miss → rebuild) or restores a previously cached fingerprint
/// whose order is still correct — a boolean `invalidate` is unnecessary and
/// would race with concurrent publishers (`store(true)` lost to a late
/// `store(false)`). See `wrr_recovery_reuses_cached_fingerprint_schedule`.
///
/// # Bounded state / wrap semantics
///
/// At most [`WRR_SCHEDULE_CACHE_SLOTS`] schedules are retained (strict memory
/// bound). Each shard counter is `u64` and indexes with `% order.len()`.
/// Wrapping is well-defined and does not bias the schedule's long-run ratios.
/// Config-valid schedules are capped at [`WRR_MAX_SCHEDULE_LEN`]; larger exact
/// periods are deterministically apportioned while preserving every positive-
/// weight target, then smoothed over the complete bounded period. Those capped
/// 8192-entry schedules are bounded approximations of the exact period — they
/// retain every positive-weight target but do not claim exact configured ratios
/// for pathological weight products that exceed the cap.
///
/// Smooth construction itself is additionally bounded by
/// [`WRR_SMOOTH_BUILD_MAX_WORK`] (`schedule_steps × positive_candidates`). When
/// that work budget would be exceeded, the publisher stores an exact-key
/// lottery-only sentinel (empty order, `!zero_weight`) so the fingerprint does
/// not repeatedly attempt the quadratic build; hits then use the same
/// allocation-free lottery / all-zero RR as the miss path.
struct WrrLaneState {
    /// Bounded fingerprint → schedule cache. Steady hits load matching slots
    /// with no lock and no per-selection allocation.
    slots: Box<[ArcSwap<WrrSchedule>]>,
    /// Round-robin index of the next slot to overwrite on publish.
    publish_cursor: AtomicU64,
    /// Cold-path publish gate — `try_lock` only; never blocks the hot path.
    rebuild: std::sync::Mutex<()>,
    /// `0` means this lane does not run WRR (e.g. non-WRR port override).
    target_len: usize,
    /// Steady-state cache hits (fingerprint matched a slot). Test builds only —
    /// never updated on the release hot path (avoids a second shared RMW).
    #[cfg(test)]
    cache_hits: AtomicU64,
    /// Successful schedule publishes into the bounded cache.
    rebuilds: AtomicU64,
    /// Allocation-free miss-fallback selections (miss path only; not the
    /// steady-state hit path).
    miss_fallbacks: CachePadded<AtomicU64>,
    /// Rate-sample counter for full-cache replacement publishes.
    miss_publish_tickets: AtomicU64,
    /// Seed source for newly published schedules. Distinct seeds avoid a herd
    /// of concurrent first-fill publishes all choosing entry zero.
    schedule_seed: AtomicU64,
}

impl std::fmt::Debug for WrrLaneState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self
            .slots
            .iter()
            .map(|slot| {
                let guard = slot.load();
                match &guard.key {
                    WrrScheduleKey::Invalid => "invalid".to_string(),
                    WrrScheduleKey::Bitset(bits) => format!("bitset:{bits:032x}"),
                    WrrScheduleKey::Indices(indices) => {
                        format!("indices(len={})", indices.len())
                    }
                }
            })
            .collect();
        let mut debug = f.debug_struct("WrrLaneState");
        debug
            .field("target_len", &self.target_len)
            .field("rebuilds", &self.rebuilds.load(Ordering::Relaxed))
            .field(
                "miss_fallbacks",
                &self.miss_fallbacks.load(Ordering::Relaxed),
            )
            .field("slot_keys", &keys);
        #[cfg(test)]
        debug.field("cache_hits", &self.cache_hits.load(Ordering::Relaxed));
        debug.finish()
    }
}

impl WrrLaneState {
    fn empty_slots() -> Box<[ArcSwap<WrrSchedule>]> {
        (0..WRR_SCHEDULE_CACHE_SLOTS)
            .map(|_| ArcSwap::from_pointee(WrrSchedule::invalid()))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    fn inactive() -> Self {
        Self {
            slots: Vec::new().into_boxed_slice(),
            publish_cursor: AtomicU64::new(0),
            rebuild: std::sync::Mutex::new(()),
            target_len: 0,
            #[cfg(test)]
            cache_hits: AtomicU64::new(0),
            rebuilds: AtomicU64::new(0),
            miss_fallbacks: CachePadded::new(AtomicU64::new(0)),
            miss_publish_tickets: AtomicU64::new(0),
            schedule_seed: AtomicU64::new(0),
        }
    }

    fn new(target_len: usize) -> Self {
        if target_len == 0 {
            return Self::inactive();
        }
        Self {
            slots: Self::empty_slots(),
            publish_cursor: AtomicU64::new(0),
            rebuild: std::sync::Mutex::new(()),
            target_len,
            #[cfg(test)]
            cache_hits: AtomicU64::new(0),
            rebuilds: AtomicU64::new(0),
            miss_fallbacks: CachePadded::new(AtomicU64::new(0)),
            miss_publish_tickets: AtomicU64::new(0),
            schedule_seed: AtomicU64::new(0),
        }
    }

    #[inline]
    fn is_active(&self) -> bool {
        self.target_len > 0
    }

    /// Load a cached bitset schedule without recording a hit.
    #[inline]
    fn lookup_bitset_schedule(
        &self,
        fingerprint: u128,
    ) -> Option<arc_swap::Guard<Arc<WrrSchedule>>> {
        for slot in self.slots.iter() {
            let guard = slot.load();
            if matches!(&guard.key, WrrScheduleKey::Bitset(value) if *value == fingerprint) {
                return Some(guard);
            }
        }
        None
    }

    /// Load a cached >128-target schedule by exact ordered membership.
    #[inline]
    fn lookup_vec_schedule(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<arc_swap::Guard<Arc<WrrSchedule>>> {
        for slot in self.slots.iter() {
            let guard = slot.load();
            let WrrScheduleKey::Indices(indices) = &guard.key else {
                continue;
            };
            if indices.len() == candidates.len()
                && indices
                    .iter()
                    .copied()
                    .eq(candidates.iter().map(|(idx, _)| *idx))
            {
                return Some(guard);
            }
        }
        None
    }

    /// Steady-state bitset hit: lookup (+ test-only hit counter).
    #[inline]
    fn hit_bitset_schedule(&self, fingerprint: u128) -> Option<arc_swap::Guard<Arc<WrrSchedule>>> {
        let guard = self.lookup_bitset_schedule(fingerprint)?;
        #[cfg(test)]
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        Some(guard)
    }

    /// Steady-state Vec hit: exact lookup (+ test-only hit counter).
    #[inline]
    fn hit_vec_schedule(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<arc_swap::Guard<Arc<WrrSchedule>>> {
        let guard = self.lookup_vec_schedule(candidates)?;
        #[cfg(test)]
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        Some(guard)
    }

    #[inline]
    fn next_schedule_seed(&self) -> u64 {
        self.schedule_seed.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    fn next_miss_fallback(&self) -> u64 {
        self.miss_fallbacks.fetch_add(1, Ordering::Relaxed)
    }

    /// True when at least one cache slot has never been published.
    #[inline]
    fn has_free_slot(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| matches!(&slot.load().key, WrrScheduleKey::Invalid))
    }

    /// Whether a locked miss may build+publish a schedule.
    ///
    /// Empty slots always fill. Full-cache replacement is rate-sampled so
    /// sustained fingerprint churn cannot allocate on every request.
    #[inline]
    fn should_publish_on_miss(&self) -> bool {
        if self.has_free_slot() {
            return true;
        }
        let ticket = self.miss_publish_tickets.fetch_add(1, Ordering::Relaxed);
        ticket.is_multiple_of(WRR_MISS_PUBLISH_SAMPLE)
    }

    /// Publish `schedule` into the next round-robin slot (caller holds try-lock).
    fn publish_schedule(&self, schedule: Arc<WrrSchedule>) {
        let slot_count = self.slots.len();
        if slot_count == 0 {
            return;
        }
        let idx = (self.publish_cursor.fetch_add(1, Ordering::Relaxed) as usize) % slot_count;
        self.slots[idx].store(schedule);
        self.rebuilds.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    #[inline]
    fn cache_stats(&self) -> (u64, u64) {
        (
            self.cache_hits.load(Ordering::Relaxed),
            self.rebuilds.load(Ordering::Relaxed),
        )
    }

    /// `(schedule_publishes, allocation_free_miss_fallbacks)` for diagnostics/tests.
    #[inline]
    fn schedule_counters(&self) -> (u64, u64) {
        (
            self.rebuilds.load(Ordering::Relaxed),
            self.miss_fallbacks.load(Ordering::Relaxed),
        )
    }
}

/// Greatest common divisor for shrinking WRR schedule length.
#[inline]
fn wrr_gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Result of building a smooth-WRR order for one healthy weight set.
#[derive(Debug)]
enum WrrOrderBuild {
    /// Exact or weight-bounded NGINX smooth-WRR sequence.
    Smooth(Box<[usize]>),
    /// Every weight was zero — callers publish an all-zero RR schedule.
    ZeroWeight,
    /// Construction work would exceed [`WRR_SMOOTH_BUILD_MAX_WORK`]. Callers
    /// publish a lottery-only sentinel for the exact healthy-set key.
    LotteryOnly,
}

/// Bound a normalized WRR period without starving positive-weight targets.
///
/// Each target first receives one slot. Remaining slots are apportioned by the
/// largest-remainder method in original target order for deterministic ties.
/// Config validation limits upstreams to fewer targets than the normal cap;
/// `max` also keeps direct internal construction safe if that invariant changes.
fn bound_wrr_weights(normalized: &[(usize, u64)], total_weight: u64) -> Vec<(usize, i64)> {
    let schedule_len = WRR_MAX_SCHEDULE_LEN.max(normalized.len());
    if total_weight <= schedule_len as u64 {
        return normalized
            .iter()
            .map(|&(idx, weight)| (idx, weight as i64))
            .collect();
    }

    let remaining = schedule_len.saturating_sub(normalized.len());
    let denominator = u128::from(total_weight).max(1);
    let mut apportioned = Vec::with_capacity(normalized.len());
    let mut remainders = Vec::with_capacity(normalized.len());
    let mut assigned = normalized.len();

    for (slot, &(idx, weight)) in normalized.iter().enumerate() {
        let numerator = u128::from(weight).saturating_mul(remaining as u128);
        let extra = usize::try_from(numerator / denominator).unwrap_or(usize::MAX);
        let slots = (extra as u64).saturating_add(1);
        apportioned.push((idx, slots.min(i64::MAX as u64) as i64));
        remainders.push((slot, numerator % denominator));
        assigned = assigned.saturating_add(extra);
    }

    remainders.sort_unstable_by(|(slot_a, remainder_a), (slot_b, remainder_b)| {
        remainder_b
            .cmp(remainder_a)
            .then_with(|| slot_a.cmp(slot_b))
    });
    let leftover = schedule_len.saturating_sub(assigned);
    for &(slot, _) in remainders.iter().take(leftover) {
        apportioned[slot].1 = apportioned[slot].1.saturating_add(1);
    }
    apportioned
}

/// Build a smooth-WRR order for `(target_index, weight)` pairs with weight > 0.
///
/// Returns [`WrrOrderBuild::LotteryOnly`] when the quadratic NGINX loop would
/// exceed [`WRR_SMOOTH_BUILD_MAX_WORK`], so callers can publish an exact-key
/// sentinel instead of blocking a Tokio worker on a pathological build.
fn build_smooth_wrr_order(weighted: &[(usize, u32)]) -> WrrOrderBuild {
    let mut gcd = 0u32;
    for &(_, weight) in weighted {
        if weight == 0 {
            continue;
        }
        gcd = if gcd == 0 {
            weight
        } else {
            wrr_gcd(gcd, weight)
        };
    }
    if gcd == 0 {
        return WrrOrderBuild::ZeroWeight;
    }

    let normalized: Vec<(usize, u64)> = weighted
        .iter()
        .filter(|(_, weight)| *weight > 0)
        .map(|&(idx, weight)| (idx, u64::from(weight / gcd)))
        .collect();
    let total_weight: u64 = normalized.iter().map(|(_, weight)| *weight).sum();
    let bounded = bound_wrr_weights(&normalized, total_weight);
    let bounded_total: i64 = bounded.iter().map(|(_, weight)| *weight).sum();
    if bounded_total <= 0 {
        return WrrOrderBuild::ZeroWeight;
    }

    let steps = bounded_total as usize;
    let positive_candidates = bounded.len();
    match (steps as u64).checked_mul(positive_candidates as u64) {
        Some(work) if work <= WRR_SMOOTH_BUILD_MAX_WORK => {}
        _ => return WrrOrderBuild::LotteryOnly,
    }

    let mut current = vec![0i64; positive_candidates];
    let mut order = Vec::with_capacity(steps);
    for _ in 0..steps {
        let mut best_slot = 0usize;
        let mut best_current = i64::MIN;
        for (slot, &(_, weight)) in bounded.iter().enumerate() {
            current[slot] = current[slot].saturating_add(weight);
            if current[slot] > best_current {
                best_current = current[slot];
                best_slot = slot;
            }
        }
        current[best_slot] = current[best_slot].saturating_sub(bounded_total);
        order.push(bounded[best_slot].0);
    }
    WrrOrderBuild::Smooth(order.into_boxed_slice())
}

/// Resolve a schedule original-index into a >128-target candidate slice.
///
/// All Vec candidate construction paths retain ascending original-index order
/// (enumerate / filter / locality masks, with passive readmits re-sorted), so
/// steady-state hits use `binary_search_by_key` — O(log n), allocation-free.
#[inline]
fn resolve_wrr_vec_candidate<'a>(
    candidates: &[(usize, &'a Arc<UpstreamTarget>)],
    orig_idx: usize,
) -> Option<&'a Arc<UpstreamTarget>> {
    match candidates.binary_search_by_key(&orig_idx, |(idx, _)| *idx) {
        Ok(pos) => Some(candidates[pos].1),
        Err(_) => None,
    }
}

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
    /// Maximum percentage of targets (0-100) that may be ejected simultaneously
    /// via passive health checks. When the ejection count would exceed
    /// `ceil(total * pct / 100)`, the earliest passive ejections are re-admitted
    /// to keep the effective ejection count within
    /// the cap. `None` = no cap (default behavior).
    pub max_ejection_percent: Option<u8>,
}

fn passive_ejections_to_readmit(
    passive_ejected: &mut [(usize, u64)],
    total_targets: usize,
    max_ejection_percent: Option<u8>,
) -> usize {
    let Some(max_pct) = max_ejection_percent else {
        return 0;
    };
    if passive_ejected.is_empty() || total_targets == 0 {
        return 0;
    }

    // ceil(n * pct / 100) — at least 0, at most n.
    let max_ejected = ((total_targets as u64)
        .saturating_mul(max_pct as u64)
        .saturating_add(99))
        / 100;
    let max_ejected = (max_ejected as usize).min(total_targets);
    if passive_ejected.len() <= max_ejected {
        return 0;
    }

    // Re-admit the earliest passive ejections first, matching outlier-detection
    // recovery intuition: targets that have waited longest get the first chance.
    passive_ejected.sort_unstable_by_key(|&(_, ts)| ts);
    passive_ejected.len() - max_ejected
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

/// Fixed-point scale used when splitting locality-level distribute weights
/// across endpoints in the same matching locality.
const LOCALITY_DISTRIBUTE_WEIGHT_SCALE: u64 = 1_000_000;

/// Whether a target is a LOCAL (same-cluster) endpoint for strict local-first
/// locality LB. Keyed on the RESERVED, un-spoofable remote-provenance tag
/// [`crate::modes::mesh::multicluster::MESH_REMOTE_TAG`] (`mesh.remote`) carrying
/// the discoverer's exact internal value
/// [`crate::modes::mesh::multicluster::MESH_REMOTE_TAG_VALUE`] (`"true"`). That tag
/// is stamped ONLY by the service discoverer, from a workload's
/// `remote_provenance` flag set at remote-poll INGESTION — NOT from a locality
/// string prefix, and NOT from `cluster`-name equality. It is trustworthy here
/// because two things guarantee only the discoverer can set it: (1) the provenance
/// flag never crosses a wire/file boundary, and (2) every target builder that
/// copies operator/workload labels into `UpstreamTarget.tags` (east-west, egress
/// ServiceEntry) strips the reserved `mesh.*` namespace first
/// ([`crate::modes::mesh::multicluster::strip_reserved_mesh_tags`]), so a
/// hand-authored `mesh.remote: "true"` label can never reach a target. Checking
/// the exact VALUE (not mere key presence) is belt-and-suspenders. A real local
/// Kubernetes region named `remote-<something>` carries no provenance tag and
/// stays LOCAL. A target without the marker (local-cluster, non-mesh, or
/// operator-authored) is local. Used at construction to precompute
/// `LoadBalancer.local_locality_mask`.
#[inline]
fn target_is_local(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(crate::modes::mesh::multicluster::MESH_REMOTE_TAG)
        .map(String::as_str)
        != Some(crate::modes::mesh::multicluster::MESH_REMOTE_TAG_VALUE)
}

/// Whether a target is a CROSS-CLUSTER east-west GATEWAY target — a SNI-
/// passthrough gateway endpoint materialized by
/// `append_cross_cluster_mesh_targets` (tagged
/// [`crate::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG`] = `"true"`). Such a
/// target is categorically a FAILOVER: the remote gateway LB-picks the backend
/// (so the client cannot steer it to its expected trust domain), and WebSocket
/// over the cross-cluster path is unsupported. When ANY candidate is one, the
/// balancer enforces local-first selection on the no-source-locality path even
/// while `locality_lb_strict` is at its default `false` — otherwise a service
/// with healthy LOCAL endpoints would round-robin onto the remote gateway
/// instead of using it only as failover. See
/// `LoadBalancer.cross_cluster_failover_present`.
#[inline]
fn target_is_cross_cluster(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(crate::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG)
        .map(String::as_str)
        == Some("true")
}

/// Warm-up bias subtracted from `min_known_ewma` for unsampled (late-joiner)
/// targets during the mixed warm-up phase.
///
/// Used only when comparing among **unwarmed** candidates (bounded
/// exploration). Warmed targets are never displaced by an unconditional
/// biased-best preference for an unsampled peer — see
/// `LATENCY_WARMUP_EXPLORE_PERMILLE`.
///
/// **Behavioral note:** any nonzero bias value (including `1`) produces the
/// same selection outcome among unwarmed peers because `saturating_sub(N)`
/// for any `N >= 1` makes the unsampled target strictly less than the
/// minimum warmed EWMA when `min_known_ewma > 0`, and saturates to `0` (a tie
/// broken by iteration order) when `min_known_ewma == 0`.
///
/// The constant exists as a named policy anchor: 1 ms (1 000 us) documents
/// the intended preference gap in human-readable latency units and makes the
/// warm-up strategy greppable and self-documenting, replacing a bare magic
/// literal.
#[allow(dead_code)] // policy-anchor constant; mixed warm-up now uses bounded exploration
const LATENCY_WARMUP_BIAS_US: u64 = 1_000;

/// Permille (‰) of mixed-warm-up selections that explore sub-threshold
/// (unwarmed) targets via round-robin among them.
///
/// Bounds late-joiner / never-sampled exploration so a persistently failing
/// unsampled target cannot pin 100% of traffic. Healthy late joiners still
/// receive a fair share of exploration traffic to establish a baseline.
const LATENCY_WARMUP_EXPLORE_PERMILLE: u64 = 100; // 10%

/// Select an unwarmed peer slot for a mixed-warm-up ticket.
///
/// Uses a golden-ratio scramble of `ticket` so short observation windows
/// still see ~`LATENCY_WARMUP_EXPLORE_PERMILLE` rate and distribute those
/// selections across every unwarmed peer. A contiguous
/// `ticket % 1000 < permille` test fails that contract: the first 200
/// selections after a zeroed counter would explore 50% of the time, while
/// deriving the peer slot from `ticket / 1000` would send that whole window to
/// one late joiner.
#[inline]
fn unwarmed_explore_slot(ticket: u64, unwarmed_count: usize) -> Option<usize> {
    if unwarmed_count == 0 {
        return None;
    }
    let scrambled = golden_ratio_hash(ticket);
    if (scrambled % 1000) >= LATENCY_WARMUP_EXPLORE_PERMILLE {
        return None;
    }
    Some(((scrambled / 1000) % unwarmed_count as u64) as usize)
}

/// Synthetic EWMA sample (microseconds) recorded for a failed dispatch
/// attempt. Counts toward the warm-up threshold and penalizes the target so
/// a target that fails every request exits warm-up with a poor score instead
/// of remaining biased-best forever. 1 second is deliberately worse than
/// typical healthy TTFB while still finite for EWMA math.
const LATENCY_FAILURE_PENALTY_US: u64 = 1_000_000;

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

/// All load-balancer state swapped as a single unit so readers never see
/// new balancer entries paired with a stale upstream index (or vice versa).
pub struct LoadBalancerCacheInner {
    balancers: HashMap<String, Arc<LoadBalancer>>,
    /// O(1) upstream lookup by ID (avoids linear scan of config.upstreams).
    upstreams: HashMap<String, Arc<Upstream>>,
}

impl LoadBalancerCacheInner {
    /// Access the balancers map for custom code that needs direct HashMap access.
    ///
    /// Prefer the typed accessors [`LoadBalancerCache::get_hash_on_strategy_from`]
    /// and [`LoadBalancerCache::select_target_from`] when possible — they cover
    /// the standard hot-path use cases without exposing internal structure.
    #[allow(dead_code)] // Public API used by custom plugins
    #[inline]
    pub fn balancers(&self) -> &HashMap<String, Arc<LoadBalancer>> {
        &self.balancers
    }

    /// Access the upstream index for custom code that needs direct lookup.
    #[allow(dead_code)] // Public API used by custom plugins
    #[inline]
    pub fn upstreams(&self) -> &HashMap<String, Arc<Upstream>> {
        &self.upstreams
    }

    #[inline]
    pub fn get_balancer(&self, upstream_id: &str) -> Option<Arc<LoadBalancer>> {
        self.balancers.get(upstream_id).cloned()
    }
}

/// Load balancer cache, rebuilt atomically on config change.
///
/// Individual `LoadBalancer` instances are wrapped in `Arc` so that
/// incremental updates can clone the HashMap cheaply (just Arc pointer
/// copies) and only allocate new `LoadBalancer` instances for changed
/// upstreams. Unchanged upstreams keep their exact same instance --
/// round-robin counters, WRR schedules, active connection counts, latency
/// EWMAs, and consistent hash rings are all preserved.
pub struct LoadBalancerCache {
    inner: ArcSwap<LoadBalancerCacheInner>,
}

impl LoadBalancerCache {
    pub fn new(config: &GatewayConfig) -> Self {
        Self {
            inner: ArcSwap::new(Self::build_inner(config)),
        }
    }

    pub fn rebuild(&self, config: &GatewayConfig) {
        self.inner.store(Self::build_inner(config));
    }

    pub(crate) fn build_inner(config: &GatewayConfig) -> Arc<LoadBalancerCacheInner> {
        Arc::new(LoadBalancerCacheInner {
            balancers: Self::build_balancers(config),
            upstreams: Self::build_upstream_index(config),
        })
    }

    pub(crate) fn store_inner(&self, inner: Arc<LoadBalancerCacheInner>) {
        self.inner.store(inner);
    }

    pub(crate) fn load_inner(&self) -> Arc<LoadBalancerCacheInner> {
        self.inner.load_full()
    }

    fn build_balancers(config: &GatewayConfig) -> HashMap<String, Arc<LoadBalancer>> {
        let mut map = HashMap::with_capacity(config.upstreams.len());
        for upstream in &config.upstreams {
            map.insert(
                upstream.id.clone(),
                Arc::new(LoadBalancer::with_subsets_and_port_overrides(
                    &upstream.id,
                    upstream.algorithm,
                    &upstream.targets,
                    upstream.hash_on.clone(),
                    upstream.subsets.as_deref(),
                    Some(&upstream.port_overrides),
                    upstream.source_locality.as_deref(),
                    upstream.locality_lb_setting.as_ref(),
                    upstream.locality_lb_strict,
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
    ///   round-robin counters, WRR schedules, active connection counts, latency
    ///   EWMAs, and hash rings
    pub(crate) fn build_delta_inner(
        current: &LoadBalancerCacheInner,
        full_new_config: &GatewayConfig,
        added: &[Upstream],
        removed_ids: &[String],
        modified: &[Upstream],
    ) -> Arc<LoadBalancerCacheInner> {
        if added.is_empty() && removed_ids.is_empty() && modified.is_empty() {
            return Arc::new(LoadBalancerCacheInner {
                balancers: current.balancers.clone(),
                upstreams: current.upstreams.clone(),
            });
        }

        // Clone the current map -- O(n) Arc pointer copies, no LoadBalancer cloning
        let mut new_balancers = current.balancers.clone();

        // Remove deleted upstreams
        for id in removed_ids {
            new_balancers.remove(id);
        }

        // Create fresh LoadBalancer instances only for added/modified upstreams
        for upstream in added.iter().chain(modified.iter()) {
            new_balancers.insert(
                upstream.id.clone(),
                Arc::new(LoadBalancer::with_subsets_and_port_overrides(
                    &upstream.id,
                    upstream.algorithm,
                    &upstream.targets,
                    upstream.hash_on.clone(),
                    upstream.subsets.as_deref(),
                    Some(&upstream.port_overrides),
                    upstream.source_locality.as_deref(),
                    upstream.locality_lb_setting.as_ref(),
                    upstream.locality_lb_strict,
                )),
            );
        }

        // Upstream index is cheap to rebuild (just Arc<Upstream> clones)
        let new_upstream_idx = Self::build_upstream_index(full_new_config);

        // Single atomic swap
        Arc::new(LoadBalancerCacheInner {
            balancers: new_balancers,
            upstreams: new_upstream_idx,
        })
    }

    pub fn apply_delta(
        &self,
        full_new_config: &GatewayConfig,
        added: &[Upstream],
        removed_ids: &[String],
        modified: &[Upstream],
    ) {
        let current = self.inner.load();
        let inner =
            Self::build_delta_inner(&current, full_new_config, added, removed_ids, modified);
        self.store_inner(inner);
    }

    /// O(1) lookup of an upstream by ID from the pre-built index.
    pub fn get_upstream(&self, upstream_id: &str) -> Option<Arc<Upstream>> {
        let inner = self.inner.load();
        inner.upstreams.get(upstream_id).cloned()
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
        let current = self.inner.load();
        self.store_inner(Self::build_update_targets_inner(
            &current,
            upstream_id,
            new_targets,
            algorithm,
            hash_on,
        ));
    }

    pub(crate) fn build_update_targets_inner(
        current: &LoadBalancerCacheInner,
        upstream_id: &str,
        new_targets: Vec<UpstreamTarget>,
        algorithm: LoadBalancerAlgorithm,
        hash_on: Option<String>,
    ) -> Arc<LoadBalancerCacheInner> {
        let Some(existing_upstream) = current.upstreams.get(upstream_id) else {
            return Arc::new(LoadBalancerCacheInner {
                balancers: current.balancers.clone(),
                upstreams: current.upstreams.clone(),
            });
        };

        // Clone-and-patch both maps, then swap as a single unit
        let mut new_balancers = current.balancers.clone();
        let existing_subsets = existing_upstream
            .subsets
            .as_deref()
            .map(|subsets| subsets.to_vec());
        let existing_port_overrides = existing_upstream.port_overrides.clone();
        let existing_source_locality = existing_upstream.source_locality.clone();
        let existing_locality_lb_setting = existing_upstream.locality_lb_setting.clone();
        let existing_locality_lb_strict = existing_upstream.locality_lb_strict;
        new_balancers.insert(
            upstream_id.to_string(),
            Arc::new(LoadBalancer::with_subsets_and_port_overrides(
                upstream_id,
                algorithm,
                &new_targets,
                hash_on,
                existing_subsets.as_deref(),
                Some(&existing_port_overrides),
                existing_source_locality.as_deref(),
                existing_locality_lb_setting.as_ref(),
                existing_locality_lb_strict,
            )),
        );

        let mut new_upstreams = current.upstreams.clone();
        let mut updated = (**existing_upstream).clone();
        updated.targets = new_targets;
        new_upstreams.insert(upstream_id.to_string(), Arc::new(updated));

        Arc::new(LoadBalancerCacheInner {
            balancers: new_balancers,
            upstreams: new_upstreams,
        })
    }

    /// Get the pre-parsed hash-on strategy for an upstream.
    /// Returns `HashOnStrategy::Ip` if the upstream is not found.
    pub fn get_hash_on_strategy(&self, upstream_id: &str) -> HashOnStrategy {
        let inner = self.inner.load();
        inner
            .balancers
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
        let inner = self.inner.load();
        let balancer = inner.balancers.get(upstream_id)?;
        balancer.select(ctx_key, health)
    }

    /// Load the balancers map once and return a guard for multiple lookups.
    ///
    /// Use this when you need both `get_hash_on_strategy()` and `select_target()`
    /// for the same upstream -- saves one `ArcSwap::load()` atomic operation per
    /// request by loading the balancers map once and reusing the guard.
    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<LoadBalancerCacheInner>> {
        self.inner.load()
    }

    /// Get the hash-on strategy from a pre-loaded snapshot.
    #[inline]
    pub fn get_hash_on_strategy_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
    ) -> HashOnStrategy {
        snapshot
            .balancers
            .get(upstream_id)
            .map(|b| b.hash_on_strategy.clone())
            .unwrap_or(HashOnStrategy::Ip)
    }

    /// Get the pre-parsed hash-on strategy for a per-port override.
    #[inline]
    pub fn get_hash_on_strategy_for_port_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        port: u16,
    ) -> HashOnStrategy {
        snapshot
            .balancers
            .get(upstream_id)
            .map(|b| b.hash_on_strategy_for_port(port))
            .unwrap_or(HashOnStrategy::Ip)
    }

    /// Get the pre-parsed hash-on strategy for the effective selection lane.
    /// Precedence matches target selection: per-port override, then subset,
    /// then upstream.
    #[inline]
    pub fn get_hash_on_strategy_for_selection_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        port: Option<u16>,
        subset_name: Option<&str>,
    ) -> HashOnStrategy {
        snapshot
            .balancers
            .get(upstream_id)
            .map(|b| b.hash_on_strategy_for_selection(port, subset_name))
            .unwrap_or(HashOnStrategy::Ip)
    }

    /// Return the pre-computed port override that covers every target in an
    /// upstream, if one exists. This keeps initial request dispatch O(1) for
    /// large service-discovery upstreams.
    #[inline]
    pub fn initial_dispatch_port_override_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
    ) -> u16 {
        snapshot
            .balancers
            .get(upstream_id)
            .map(|b| b.initial_dispatch_port_override)
            .unwrap_or(0)
    }

    /// Returns true when the precomputed load balancer has an actual per-port
    /// state lane for `port`. `Proxy.dispatch_port_overrides` may still contain
    /// phantom ports from config/service-discovery churn; callers should not use
    /// port-scoped policy unless this says the balancer can also select on it.
    #[inline]
    pub fn has_port_override_state_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        port: u16,
    ) -> bool {
        snapshot
            .balancers
            .get(upstream_id)
            .is_some_and(|b| b.has_port_override_state(port))
    }

    #[inline]
    pub fn get_upstream_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
    ) -> Option<Arc<Upstream>> {
        snapshot.upstreams.get(upstream_id).cloned()
    }

    /// Select a target from a pre-loaded snapshot.
    #[inline]
    pub fn select_target_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select(ctx_key, health)
    }

    /// Select a target from a port-specific load balancer state.
    #[inline]
    pub fn select_target_for_port_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        port: u16,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_for_port(ctx_key, port, health)
    }

    /// Select a target from a named subset within an upstream.
    /// Unknown, empty, or fully unhealthy subsets return `None`.
    #[inline]
    pub fn select_target_subset_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        subset_name: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_from_subset(ctx_key, subset_name, health)
    }

    /// Select a target from a named subset using port-specific state.
    #[inline]
    pub fn select_target_for_port_subset_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        port: u16,
        subset_name: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_for_port_from_subset(ctx_key, port, subset_name, health)
    }

    /// Resolve the effective LB algorithm for `(upstream, port_override, subset)`
    /// from a snapshot, with the same precedence the `select*` family uses.
    /// Returns `None` only when the upstream id is unknown.
    #[inline]
    pub fn effective_algorithm_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        port: Option<u16>,
        subset_name: Option<&str>,
    ) -> Option<LoadBalancerAlgorithm> {
        snapshot
            .balancers
            .get(upstream_id)
            .map(|b| b.effective_algorithm(port, subset_name))
    }

    /// PASSTHROUGH selection from a snapshot: return the pool target matching
    /// the captured original destination (subset∩port-scoped, health-respecting),
    /// or `None` to signal a round-robin fallback.
    #[inline]
    pub fn select_passthrough_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        orig_dst: std::net::SocketAddr,
        port: Option<u16>,
        subset_name: Option<&str>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_passthrough(orig_dst, port, subset_name, health)
    }

    /// Select next target, excluding a previously tried target (for retries).
    pub fn select_next_target(
        &self,
        upstream_id: &str,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let inner = self.inner.load();
        let balancer = inner.balancers.get(upstream_id)?;
        balancer.select_excluding(ctx_key, exclude, health)
    }

    pub fn select_next_target_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_excluding(ctx_key, exclude, health)
    }

    pub fn select_next_target_for_port_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        port: u16,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_excluding_for_port(ctx_key, port, exclude, health)
    }

    pub fn select_next_target_subset_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        subset_name: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_excluding_from_subset(ctx_key, subset_name, exclude, health)
    }

    pub fn select_next_target_for_port_subset_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        ctx_key: &str,
        port: u16,
        subset_name: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let balancer = snapshot.balancers.get(upstream_id)?;
        balancer.select_excluding_for_port_from_subset(ctx_key, port, subset_name, exclude, health)
    }

    #[inline]
    pub fn max_ejection_percent_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
    ) -> Option<u8> {
        snapshot
            .upstreams
            .get(upstream_id)
            .and_then(|u| u.health_checks.as_ref())
            .and_then(|hc| hc.passive.as_ref())
            .and_then(|p| p.max_ejection_percent)
    }

    #[inline]
    pub fn max_ejection_percent_for_port_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        proxy: &Proxy,
        port: u16,
    ) -> Option<u8> {
        if Self::has_port_override_state_from(snapshot, upstream_id, port)
            && let Some(port_passive) = proxy
                .dispatch_port_overrides
                .as_ref()
                .and_then(|overrides| overrides.get(&port))
                .and_then(|override_config| override_config.passive_health_check.as_ref())
        {
            return port_passive.max_ejection_percent;
        }

        Self::max_ejection_percent_from(snapshot, upstream_id)
    }

    /// Resolve the passive-health `maxEjectionPercent` cap for a dispatch using
    /// the SAME tier precedence the *thresholds* use in
    /// `backend_dispatch::passive_health_for_target`:
    ///
    /// per-port override (`portLevelSettings[].outlierDetection`) > per-subset
    /// (`subsets[].trafficPolicy.outlierDetection`) > upstream-level.
    ///
    /// `port` is `Some` only when a single dispatch port is resolvable for this
    /// dispatch AND a per-port override is actually in effect for it (the caller
    /// has already confirmed via `has_effective_port_override` /
    /// `retry_port_override_dispatch_port` + `has_port_override_state_from`);
    /// pass `None` otherwise so a phantom `dispatch_port_overrides` entry
    /// without a live balancer lane is ignored.
    ///
    /// PRE-SELECTION ASYMMETRY — this cap is resolved *before* a concrete target
    /// (and therefore its port) is chosen, so the per-port tier only applies
    /// when a single dispatch port is resolvable up front: non-subset dispatch
    /// or subset dispatch on a single-port upstream (one full-coverage port via
    /// `initial_dispatch_port_override`), and explicitly port-pinned retries.
    /// For subset-routed dispatch on a *multi-port* upstream no single dispatch
    /// port exists pre-selection (`initial_dispatch_port_override` is 0), so the
    /// caller passes `None` and the **subset** cap governs the subset candidate
    /// pool (falling back to the upstream cap). This mirrors the long-standing
    /// thresholds-vs-cap asymmetry: the thresholds in `passive_health_for_target`
    /// reach a per-port overlay only because they run *per selected target*,
    /// keyed by `target.port` after selection. Resolving a per-port cap for a
    /// homogeneous single-port subset (all its endpoints on one port) is a
    /// possible future refinement; today it resolves the subset/upstream cap,
    /// matching the pre-PR behavior (which never resolved a port cap here).
    ///
    /// INVARIANT — the tiers are **wholesale**: a present overlay replaces all
    /// lower tiers *even when its own `max_ejection_percent` is `None`*. This
    /// MUST match `passive_health_for_target`'s wholesale `.or_else()` chain so
    /// the cap and the thresholds are always drawn from the SAME tier — a subset
    /// (or per-port) `outlierDetection` that omits `maxEjectionPercent` must not
    /// silently fall back to the upstream-level cap while its thresholds come
    /// from the subset, which would mix policy from two tiers.
    ///
    /// Hot-path safe: snapshot map lookups only; `snapshot.upstreams` already
    /// holds the `Arc<Upstream>`, so the subset tier borrows it without cloning.
    #[inline]
    pub fn max_ejection_percent_resolved_from(
        snapshot: &LoadBalancerCacheInner,
        upstream_id: &str,
        proxy: &Proxy,
        port: Option<u16>,
    ) -> Option<u8> {
        // Per-port tier: a live override lane whose `passive_health_check` is
        // present wins wholesale (its cap may be `None`).
        if let Some(port) = port
            && Self::has_port_override_state_from(snapshot, upstream_id, port)
            && let Some(port_passive) = proxy
                .dispatch_port_overrides
                .as_ref()
                .and_then(|overrides| overrides.get(&port))
                .and_then(|override_config| override_config.passive_health_check.as_ref())
        {
            return port_passive.max_ejection_percent;
        }

        // Per-subset tier: a subset-bound proxy whose subset resolved an
        // `outlierDetection` overlay wins wholesale over the upstream level
        // (mirrors how `passive_health_for_target` reaches the subset overlay
        // via `resolved_subset_tls`).
        if let Some(subset) = proxy.upstream_subset.as_deref()
            && let Some(subset_passive) = snapshot
                .upstreams
                .get(upstream_id)
                .and_then(|u| u.resolved_subset_tls.get(subset))
                .and_then(|resolved| resolved.passive_health_check.as_ref())
        {
            return subset_passive.max_ejection_percent;
        }

        // Upstream tier.
        Self::max_ejection_percent_from(snapshot, upstream_id)
    }

    /// Snapshot of active connection counts per upstream for metrics.
    pub fn active_connections_snapshot(&self) -> Vec<(String, Vec<(String, i64)>)> {
        let inner = self.inner.load();
        let mut result = Vec::new();
        for (upstream_id, balancer) in inner.balancers.iter() {
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
        let inner = self.inner.load();
        if let Some(balancer) = inner.balancers.get(upstream_id) {
            balancer.record_connection_start(target);
        }
    }

    /// Record that a connection was closed to a target (for least-connections).
    pub fn record_connection_end(&self, upstream_id: &str, target: &UpstreamTarget) {
        let inner = self.inner.load();
        if let Some(balancer) = inner.balancers.get(upstream_id) {
            balancer.record_connection_end(target);
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
    ///   response (TTFB) -- only when no active health checks are configured
    pub fn record_latency(&self, upstream_id: &str, target: &UpstreamTarget, latency_us: u64) {
        let inner = self.inner.load();
        if let Some(balancer) = inner.balancers.get(upstream_id) {
            balancer.record_latency(target, latency_us);
        }
    }

    /// Record a failed dispatch attempt for least-latency warm-up (see
    /// [`LoadBalancer::record_failed_attempt`]).
    pub fn record_failed_attempt(&self, upstream_id: &str, target: &UpstreamTarget) {
        let inner = self.inner.load();
        if let Some(balancer) = inner.balancers.get(upstream_id) {
            balancer.record_failed_attempt(target);
        }
    }

    /// Reset the latency EWMA for a target to the current minimum among healthy
    /// targets. Called when a target recovers from unhealthy status so it gets a
    /// fair chance at traffic instead of being penalized by a stale high EWMA.
    pub fn reset_recovered_target_latency(&self, upstream_id: &str, target: &UpstreamTarget) {
        let inner = self.inner.load();
        if let Some(balancer) = inner.balancers.get(upstream_id) {
            balancer.reset_recovered_target_latency(target);
        }
    }
}

/// Build a health-check-scoped key ("upstream_id::host:port") for a target.
/// Used by `LoadBalancer::target_keys` and `HealthChecker` to scope health
/// state per-upstream, preventing cross-upstream contamination when different
/// upstreams contain overlapping host:port targets.
pub fn target_key(upstream_id: &str, target: &UpstreamTarget) -> String {
    let mut key = String::with_capacity(upstream_id.len() + 2 + target.host.len() + 6);
    key.push_str(upstream_id);
    key.push_str("::");
    write_target_host_port_key(&mut key, target);
    key
}

/// Build a plain "host:port" key for a target (no upstream scoping).
/// Used for sticky session cookies, active connection tracking, latency EWMA,
/// and other contexts where the key is already scoped to a single LoadBalancer.
pub fn target_host_port_key(target: &UpstreamTarget) -> String {
    let mut key = String::with_capacity(target.host.len() + 6);
    write_target_host_port_key(&mut key, target);
    key
}

/// Append the plain "host:port" target key into a reusable buffer.
pub(crate) fn write_target_host_port_key(buf: &mut String, target: &UpstreamTarget) {
    use std::fmt::Write;

    let _ = write!(buf, "{}:{}", target.host, target.port);
}

#[inline]
fn retry_exclude_target_matches(target: &UpstreamTarget, exclude: &UpstreamTarget) -> bool {
    target.host == exclude.host
        && target.port == exclude.port
        && target.dispatch_policy_port() == exclude.dispatch_policy_port()
}

/// Build the pre-computed locality-LB state from an operator's
/// `UpstreamLocalityLbSetting` against the upstream's `source_locality`.
///
/// Returns `None` when no setting applies — the load balancer then skips
/// every locality-aware path beyond the existing priority-tier preference.
/// Returns `Some(LocalityLbState { enabled: false, .. })` when the operator
/// explicitly disabled locality LB; the request path treats that as "no
/// priority, no distribute, no failover" (matches Istio semantics).
///
/// Pre-computes per-target weights / failover masks once at construction so
/// the hot path stays branch-light: distribute is a candidate mask plus a
/// weighted bucket pick, failover is one Vec index check inside the existing
/// tier preference.
fn build_locality_lb_state(
    setting: Option<&UpstreamLocalityLbSetting>,
    source_locality: Option<&str>,
    targets: &[UpstreamTarget],
) -> Option<LocalityLbState> {
    let setting = setting?;
    // When the operator disabled the block we still surface the state so
    // `preferred_locality_bitset` can short-circuit priority-tier preference
    // alongside distribute / failover.
    if !setting.enabled {
        return Some(LocalityLbState {
            enabled: false,
            distribute_weights: None,
            distribute_groups: None,
            distribute_counter: AtomicU64::new(0),
            failover_target_matches: None,
        });
    }

    let source = source_locality.and_then(LocalityPreference::parse);
    let Some(source) = source else {
        // No source locality means no distribute/failover entry can match;
        // the priority-tier preference is also empty in that case. We still
        // record `enabled: true` so existing tests stay deterministic.
        return Some(LocalityLbState {
            enabled: true,
            distribute_weights: None,
            distribute_groups: None,
            distribute_counter: AtomicU64::new(0),
            failover_target_matches: None,
        });
    };

    let target_localities: Vec<Option<LocalityPreference>> = targets
        .iter()
        .map(|target| {
            target
                .locality
                .as_deref()
                .and_then(LocalityPreference::parse)
        })
        .collect();

    // distribute[]: first matching `from` wins. Each `to` entry is a
    // locality-level percentage, so split that weight across endpoints in the
    // matching locality according to their endpoint weights instead of copying
    // the full locality weight onto each endpoint. Endpoints with weight 0 stay
    // drained; an all-zero locality is treated as ineligible for distribute.
    let mut distribute_weights: Option<Vec<u64>> = None;
    let mut distribute_groups: Option<Vec<LocalityDistributeGroup>> = None;
    for entry in &setting.distribute {
        let Some(entry_from) = LocalityPreference::parse(&entry.from) else {
            continue;
        };
        if !locality_from_matches_source(&entry_from, &source) {
            continue;
        }
        let mut weights = vec![0u64; targets.len()];
        let mut total: u64 = 0;
        let mut groups = Vec::new();
        let to_entries: Vec<(LocalityPreference, u32)> = entry
            .to
            .iter()
            .filter_map(|(to_locality, to_weight)| {
                LocalityPreference::parse(to_locality).map(|to_pref| (to_pref, *to_weight))
            })
            .collect();
        let best_to_entry_by_target: Vec<Option<usize>> = target_localities
            .iter()
            .map(|target_pref| {
                let target_pref = target_pref.as_ref()?;
                let mut best = None;
                for (to_idx, (to_pref, _)) in to_entries.iter().enumerate() {
                    if !locality_match_for_distribute(to_pref, target_pref) {
                        continue;
                    }
                    let specificity = locality_distribute_specificity(to_pref);
                    if best.is_none_or(|(_, best_specificity)| specificity > best_specificity) {
                        best = Some((to_idx, specificity));
                    }
                }
                best.map(|(to_idx, _)| to_idx)
            })
            .collect();
        for (to_idx, (_, to_weight)) in to_entries.iter().enumerate() {
            let matching_targets: Vec<(usize, u64)> = target_localities
                .iter()
                .enumerate()
                .filter_map(|(idx, target_pref)| {
                    (target_pref.is_some() && best_to_entry_by_target[idx] == Some(to_idx))
                        .then_some((idx, u64::from(targets[idx].weight)))
                })
                .collect();
            if matching_targets.is_empty() {
                continue;
            }
            let scaled_weight =
                u64::from(*to_weight).saturating_mul(LOCALITY_DISTRIBUTE_WEIGHT_SCALE);
            let endpoint_weight_total: u128 = matching_targets
                .iter()
                .map(|(_, endpoint_weight)| u128::from(*endpoint_weight))
                .sum();
            let Some(endpoint_weight_total) = std::num::NonZeroU128::new(endpoint_weight_total)
            else {
                continue;
            };
            let endpoint_weight_total = endpoint_weight_total.get();
            let scaled_weight_u128 = u128::from(scaled_weight);
            let mut allocated = 0u64;
            let mut allocations = Vec::with_capacity(matching_targets.len());
            for (idx, endpoint_weight) in matching_targets {
                if endpoint_weight == 0 {
                    allocations.push((idx, 0u64, 0u128, endpoint_weight));
                    continue;
                }
                let numerator = scaled_weight_u128.saturating_mul(u128::from(endpoint_weight));
                let share = (numerator / endpoint_weight_total) as u64;
                let remainder = numerator % endpoint_weight_total;
                allocated = allocated.saturating_add(share);
                allocations.push((idx, share, remainder, endpoint_weight));
            }
            allocations.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
            let mut leftover = scaled_weight.saturating_sub(allocated);
            let mut group_indices = Vec::new();
            let mut group_total = 0u64;
            for (idx, mut share, _, endpoint_weight) in allocations {
                if endpoint_weight > 0 && leftover > 0 {
                    share = share.saturating_add(1);
                    leftover -= 1;
                }
                if share == 0 {
                    continue;
                }
                group_indices.push(idx);
                group_total = group_total.saturating_add(share);
                weights[idx] = weights[idx].saturating_add(share);
                total = total.saturating_add(share);
            }
            if group_total > 0 {
                let target_membership = membership_mask_for_indices(targets.len(), &group_indices);
                groups.push(LocalityDistributeGroup {
                    weight: group_total,
                    target_indices: group_indices,
                    target_membership,
                });
            }
        }
        // Only honour the match if at least one target was reachable;
        // otherwise an operator typo (e.g. `to` regions naming no real
        // target) would strand the upstream. Fall through to the next
        // distribute entry, or to the rest of the locality LB path.
        if total > 0 {
            distribute_weights = Some(weights);
            distribute_groups = Some(groups);
            break;
        }
    }

    // failover[]: only consulted when distribute did not match (Istio
    // semantics — distribute takes priority). First matching `from` wins.
    let mut failover_target_matches: Option<Vec<bool>> = None;
    if distribute_weights.is_none() {
        for entry in &setting.failover {
            if entry.from != source.region {
                continue;
            }
            let mut matches = vec![false; targets.len()];
            let mut any_match = false;
            for (idx, target) in targets.iter().enumerate() {
                let Some(locality) = target.locality.as_deref() else {
                    continue;
                };
                let Some(target_pref) = LocalityPreference::parse(locality) else {
                    continue;
                };
                if target_pref.region == entry.to {
                    matches[idx] = true;
                    any_match = true;
                }
            }
            if any_match {
                failover_target_matches = Some(matches);
                break;
            }
        }
    }

    Some(LocalityLbState {
        enabled: true,
        distribute_weights,
        distribute_groups,
        distribute_counter: AtomicU64::new(0),
        failover_target_matches,
    })
}

/// True when `to` (a distribute key, e.g. `us-west` or `us-west/us-west-1`)
/// applies to `target` (a target locality, e.g. `us-west/us-west-1/a`).
///
/// Istio matches at every prefix component: a region-only `to` entry
/// applies to every target in that region; a `region/zone` entry applies
/// to every target in that zone; an exact `region/zone/subzone` requires
/// an exact match. Subzone is therefore optional in both directions —
/// only the components the operator declared have to align.
#[inline]
fn locality_match_for_distribute(to: &LocalityPreference, target: &LocalityPreference) -> bool {
    if to.region != "*" && to.region != target.region {
        return false;
    }
    if let Some(ref to_zone) = to.zone {
        if to_zone == "*" {
            return true;
        }
        if target.zone.as_ref() != Some(to_zone) {
            return false;
        }
        if let Some(ref to_sub) = to.sub_zone
            && to_sub != "*"
            && target.sub_zone.as_ref() != Some(to_sub)
        {
            return false;
        }
    }
    true
}

#[inline]
fn locality_distribute_specificity(to: &LocalityPreference) -> u8 {
    if to.region == "*" {
        return 0;
    }
    let Some(zone) = to.zone.as_deref() else {
        return 1;
    };
    if zone == "*" {
        return 1;
    }
    let Some(sub_zone) = to.sub_zone.as_deref() else {
        return 2;
    };
    if sub_zone == "*" { 2 } else { 3 }
}

/// True when a `distribute[].from` pattern matches the concrete source
/// locality. Region-only and region/zone values match the corresponding source
/// tier, and Istio wildcard forms such as `region/zone/*` match that tier.
#[inline]
fn locality_from_matches_source(from: &LocalityPreference, source: &LocalityPreference) -> bool {
    if from.region == "*" && from.zone.is_none() && from.sub_zone.is_none() {
        return true;
    }
    if from.region != "*" && from.region != source.region {
        return false;
    }
    let Some(from_zone) = from.zone.as_deref() else {
        return from.sub_zone.is_none();
    };
    if from_zone == "*" {
        return true;
    }
    if source.zone.as_deref() != Some(from_zone) {
        return false;
    }
    let Some(from_sub_zone) = from.sub_zone.as_deref() else {
        return true;
    };
    from_sub_zone == "*" || source.sub_zone.as_deref() == Some(from_sub_zone)
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
    /// Pre-computed locality tier rank per target with respect to the
    /// upstream's `source_locality`. Each value is one of `0` (exact match),
    /// `1` (same zone), `2` (same region), or `3` (no preference). Index-
    /// aligned with `targets` when populated. Empty `Vec` when no source
    /// locality is set — the hot path then skips locality filtering entirely.
    ///
    /// Computed at construction so the request path is an O(1) array index
    /// instead of three `String` comparisons through `LocalityPreference`.
    /// The source `LocalityPreference` itself is not stored on the balancer
    /// (it is dropped after construction); diagnostic callers can read it
    /// from `LoadBalancerCacheInner.upstreams[id].source_locality`.
    target_locality_ranks: Vec<u8>,
    /// O(1) reverse lookup from "host:port" string to index in `targets`/`host_port_keys`.
    /// Replaces the O(n) linear scan in `find_target_key()`. Keys are the same
    /// "host:port" format as `host_port_keys`, enabling zero-allocation lookup
    /// via `write!()` into a thread-local buffer.
    target_index: HashMap<String, usize>,
    algorithm: LoadBalancerAlgorithm,
    /// Round-robin counter.
    rr_counter: AtomicU64,
    /// Weighted round-robin lane state (smooth weighted round-robin).
    /// See [`WrrLaneState`] for the wait-free hot path and rebuild tradeoff.
    wrr_state: WrrLaneState,
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
    /// Pre-computed subset → target indices mapping for O(1) subset lookup.
    /// Built at config reload from the upstream's `SubsetDefinition` list.
    /// Each entry maps a subset name to the sorted indices of targets whose
    /// `tags` are a superset of the subset's `labels`.
    subset_indices: HashMap<String, Vec<usize>>,
    /// Effective load-balancing algorithm per subset. A subset's
    /// `traffic_policy.load_balancer_algorithm` overrides the upstream's
    /// algorithm; otherwise this repeats `algorithm` for that subset.
    subset_algorithms: HashMap<String, LoadBalancerAlgorithm>,
    /// Pre-parsed hash-key strategy per subset for consistent hashing. A subset
    /// strategy overrides the upstream strategy when that subset's effective
    /// algorithm is consistent hashing; non-hash subset lanes store `Ip`.
    subset_hash_on_strategies: HashMap<String, HashOnStrategy>,
    /// Smooth-WRR state isolated per subset so weighted routing in one subset
    /// cannot perturb the schedule of another subset.
    subset_wrr_state: HashMap<String, WrrLaneState>,
    /// Per-subset consistent-hash rings. These avoid walking the full upstream
    /// ring when a small subset uses consistent hashing.
    subset_hash_rings: HashMap<String, Vec<(u64, usize)>>,
    /// Per-destination-port load-balancing state projected from
    /// DestinationRule `trafficPolicy.portLevelSettings[]`.
    port_overrides: HashMap<u16, PortLbState>,
    /// If every target in this upstream belongs to the same overridden
    /// destination port, initial selection can safely use that port lane before
    /// a concrete target is chosen. Zero means mixed/unknown.
    initial_dispatch_port_override: u16,
    /// Pre-computed pieces of `UpstreamLocalityLbSetting` resolved against
    /// `Upstream.source_locality`. `None` when no DR `localityLbSetting`
    /// applies — the hot path then short-circuits to the existing priority
    /// tier preference. Computed at construction so request-time work is
    /// limited to bitset masks and a small weighted bucket pick.
    locality_lb: Option<LocalityLbState>,
    /// Strict local-first locality LB. Projected from
    /// `FERRUM_MESH_LOCALITY_LB_STRICT` onto mesh upstreams. When `true` and the
    /// upstream has no resolved source locality (`target_locality_ranks` empty),
    /// the locality filter restricts selection to LOCAL-locality targets (those
    /// not tagged with the synthetic `remote-<cluster>` locality) instead of
    /// returning the mixed local + remote pool. Falls back to the full candidate
    /// set (with a one-time warn) when no local target exists, so traffic is
    /// never black-holed. `false` (default) preserves the historical fail-open
    /// mixed-pool behavior and skips all strict-mode work on the hot path.
    locality_lb_strict: bool,
    /// One-time guard so the "strict locality LB found no local endpoints,
    /// widening to the full pool" warning is logged at most once per balancer
    /// instance instead of on every request that hits the fallback.
    locality_strict_widen_warned: AtomicBool,
    /// Per-target "is a LOCAL endpoint" mask, index-aligned with `targets`. A
    /// target is local unless it carries the explicit `mesh.remote` provenance
    /// tag (stamped at materialization from the workload's cross-cluster
    /// identity — see [`crate::modes::mesh::multicluster::MESH_REMOTE_TAG`]); the
    /// locality string is NOT consulted, so a real local region named
    /// `remote-<something>` stays local. Populated (non-empty) when
    /// `locality_lb_strict` is `true` OR `cross_cluster_failover_present` is
    /// `true`; empty otherwise so the default path pays nothing. Computed at
    /// construction so the strict hot path is an O(n) bitset build over a
    /// precomputed mask rather than per-request tag lookups.
    local_locality_mask: Vec<bool>,
    /// `true` when any target is a cross-cluster east-west GATEWAY failover
    /// target (see [`target_is_cross_cluster`]). Those are always-failover
    /// regardless of the `locality_lb_strict` opt-in, so on the no-source-locality
    /// path the balancer restricts to LOCAL endpoints (via `local_locality_mask`,
    /// which is therefore built whenever this is `true`) and only widens to the
    /// remote gateway when no local endpoint is healthy. Independent of
    /// `locality_lb_strict`, which still governs non-cross-cluster remote targets.
    cross_cluster_failover_present: bool,
}

/// Per-target state derived from `UpstreamLocalityLbSetting` so the hot
/// path doesn't re-parse / re-match localities on every selection.
#[derive(Debug)]
struct LocalityLbState {
    /// `true` when the operator left the block enabled. When `false`, the
    /// load balancer skips both distribute weighting and failover override
    /// AND the existing priority-tier preference (matches Istio semantics
    /// of `enabled: false`).
    enabled: bool,
    /// Per-target fixed-point distribute weight, index-aligned with
    /// `LoadBalancer.targets`.
    /// `None` when no `distribute[]` entry matched the source locality.
    /// Targets with weight 0 are excluded from distribute-mode candidate sets.
    distribute_weights: Option<Vec<u64>>,
    /// Locality buckets for a matching `distribute[]` entry. Runtime selection
    /// picks one bucket by the configured locality share, then runs the
    /// upstream / port / subset algorithm inside that bucket.
    distribute_groups: Option<Vec<LocalityDistributeGroup>>,
    /// Independent counter for weighted locality-bucket selection. This keeps
    /// the endpoint algorithm's own counter cadence unchanged.
    distribute_counter: AtomicU64,
    /// Per-target failover-region match, index-aligned with `LoadBalancer.targets`.
    /// `true` when the target's locality region matches the failover `to`
    /// region for this source. `None` when no `failover[]` entry matched
    /// the source region. Consulted as a fourth tier after exact/zone/region.
    failover_target_matches: Option<Vec<bool>>,
}

#[derive(Debug)]
struct LocalityDistributeGroup {
    weight: u64,
    target_indices: Vec<usize>,
    target_membership: Vec<bool>,
}

#[derive(Debug)]
struct PortLbState {
    target_indices: Vec<usize>,
    algorithm: LoadBalancerAlgorithm,
    algorithm_overridden: bool,
    rr_counter: AtomicU64,
    wrr_state: WrrLaneState,
    hash_ring: Vec<(u64, usize)>,
    hash_on_strategy: HashOnStrategy,
    hash_on_override_strategy: Option<HashOnStrategy>,
    /// Per-port projection of `UpstreamPortOverride.locality_lb_setting`.
    /// When `Some`, dispatch on this port consults the per-port locality
    /// preference before falling through to the upstream-level
    /// `LoadBalancer.locality_lb`. Pre-computed at cold path so the hot
    /// path stays branch-light.
    locality_lb: Option<LocalityLbState>,
}

impl LoadBalancer {
    pub fn new(
        upstream_id: &str,
        algorithm: LoadBalancerAlgorithm,
        targets: &[UpstreamTarget],
        hash_on: Option<String>,
    ) -> Self {
        Self::with_subsets(upstream_id, algorithm, targets, hash_on, None)
    }

    /// Create a new load balancer with optional subset definitions.
    /// Pre-computes subset → target index mappings at construction time
    /// so the hot path does O(1) HashMap lookup, not O(n) label matching.
    pub fn with_subsets(
        upstream_id: &str,
        algorithm: LoadBalancerAlgorithm,
        targets: &[UpstreamTarget],
        hash_on: Option<String>,
        subsets: Option<&[SubsetDefinition]>,
    ) -> Self {
        Self::with_subsets_and_port_overrides(
            upstream_id,
            algorithm,
            targets,
            hash_on,
            subsets,
            None,
            None,
            None,
            false,
        )
    }

    /// Create a new load balancer with optional subset definitions and
    /// per-port override state.
    #[allow(clippy::too_many_arguments)]
    fn with_subsets_and_port_overrides(
        upstream_id: &str,
        algorithm: LoadBalancerAlgorithm,
        targets: &[UpstreamTarget],
        hash_on: Option<String>,
        subsets: Option<&[SubsetDefinition]>,
        port_overrides: Option<&HashMap<u16, UpstreamPortOverride>>,
        source_locality: Option<&str>,
        locality_lb_setting: Option<&UpstreamLocalityLbSetting>,
        locality_lb_strict: bool,
    ) -> Self {
        // Pre-compute host:port keys for internal use (active connections, latency, hash ring)
        let host_port_keys: Vec<String> = targets.iter().map(target_host_port_key).collect();
        // Pre-compute upstream-scoped keys for health check filtering (matches HealthChecker key format)
        let target_keys: Vec<String> = targets.iter().map(|t| target_key(upstream_id, t)).collect();
        // Pre-compute the locality tier rank for every target against the
        // source locality so the request path doesn't re-parse / re-compare
        // strings on every selection. Empty `Vec` when no source locality is
        // set so callers can cheaply skip the entire locality filter. The
        // parsed source `LocalityPreference` is dropped after construction —
        // diagnostic callers can re-parse from `Upstream.source_locality` via
        // the upstream index.
        let target_locality_ranks: Vec<u8> =
            if let Some(source) = source_locality.and_then(LocalityPreference::parse) {
                targets
                    .iter()
                    .map(|target| {
                        let Some(target_locality) = target
                            .locality
                            .as_deref()
                            .and_then(LocalityPreference::parse)
                        else {
                            return 3u8;
                        };
                        if source.exact_matches(&target_locality) {
                            0
                        } else if source.same_zone(&target_locality) {
                            1
                        } else if source.same_region(&target_locality) {
                            2
                        } else {
                            3
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };

        // Build consistent hash ring with virtual nodes using fx_hash_str
        // (faster than SipHash/DefaultHasher; security irrelevant for ring placement).
        let subset_uses_consistent_hashing = subsets.is_some_and(|defs| {
            defs.iter().any(|def| {
                def.traffic_policy
                    .as_ref()
                    .and_then(|policy| policy.load_balancer_algorithm)
                    == Some(LoadBalancerAlgorithm::ConsistentHashing)
            })
        });
        let hash_ring = if algorithm == LoadBalancerAlgorithm::ConsistentHashing
            || subset_uses_consistent_hashing
        {
            build_hash_ring_for_indices(&host_port_keys, 0..targets.len())
        } else {
            Vec::new()
        };

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

        // Pre-compute subset → target indices for O(1) subset routing.
        // A target belongs to a subset if its `tags` are a superset of the
        // subset's `labels` (every label key-value pair appears in tags).
        let (subset_indices, subset_algorithms, subset_hash_on_strategies) =
            if let Some(defs) = subsets {
                let mut indices_map = HashMap::with_capacity(defs.len());
                let mut algorithm_map = HashMap::with_capacity(defs.len());
                let mut hash_on_map = HashMap::with_capacity(defs.len());
                for def in defs {
                    let mut indices = Vec::new();
                    for (i, target) in targets.iter().enumerate() {
                        let matches = def
                            .labels
                            .iter()
                            .all(|(k, v)| target.tags.get(k).is_some_and(|tv| tv == v));
                        if matches {
                            indices.push(i);
                        }
                    }
                    let effective_algorithm = def
                        .traffic_policy
                        .as_ref()
                        .and_then(|policy| policy.load_balancer_algorithm)
                        .unwrap_or(algorithm);
                    let effective_hash_on =
                        if effective_algorithm == LoadBalancerAlgorithm::ConsistentHashing {
                            def.traffic_policy
                                .as_ref()
                                .and_then(|policy| policy.hash_on.as_deref())
                                .or(hash_on.as_deref())
                        } else {
                            None
                        };
                    indices_map.insert(def.name.clone(), indices);
                    algorithm_map.insert(def.name.clone(), effective_algorithm);
                    hash_on_map.insert(def.name.clone(), HashOnStrategy::parse(effective_hash_on));
                }
                (indices_map, algorithm_map, hash_on_map)
            } else {
                (HashMap::new(), HashMap::new(), HashMap::new())
            };

        let mut subset_wrr_state = HashMap::new();
        let mut subset_hash_rings = HashMap::new();
        for (subset_name, subset_algorithm) in &subset_algorithms {
            if *subset_algorithm == LoadBalancerAlgorithm::WeightedRoundRobin {
                subset_wrr_state.insert(subset_name.clone(), WrrLaneState::new(targets.len()));
            }
            if *subset_algorithm == LoadBalancerAlgorithm::ConsistentHashing
                && let Some(indices) = subset_indices.get(subset_name)
            {
                subset_hash_rings.insert(
                    subset_name.clone(),
                    build_hash_ring_for_indices(&host_port_keys, indices.iter().copied()),
                );
            }
        }

        let mut port_states = HashMap::new();
        if let Some(overrides) = port_overrides {
            for (port, override_config) in overrides {
                let target_indices: Vec<usize> = targets
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, target)| {
                        (target.dispatch_policy_port() == *port).then_some(idx)
                    })
                    .collect();
                if target_indices.is_empty() {
                    continue;
                }
                let effective_algorithm = override_config.algorithm.unwrap_or(algorithm);
                let effective_hash_on =
                    if effective_algorithm == LoadBalancerAlgorithm::ConsistentHashing {
                        override_config.hash_on.as_deref().or(hash_on.as_deref())
                    } else {
                        None
                    };
                let hash_ring = if effective_algorithm == LoadBalancerAlgorithm::ConsistentHashing {
                    build_hash_ring_for_indices(&host_port_keys, target_indices.iter().copied())
                } else {
                    Vec::new()
                };
                let wrr_state = if effective_algorithm == LoadBalancerAlgorithm::WeightedRoundRobin
                {
                    // Keep WRR state indexed by the full upstream target
                    // vector, even when only a subset serves this port, so
                    // bitset, subset, and Vec fallback paths can share the
                    // same target-index bookkeeping.
                    WrrLaneState::new(targets.len())
                } else {
                    WrrLaneState::inactive()
                };
                // Per-port locality LB falls back to the upstream-level setting
                // when the operator did not override it at this port. The
                // pre-compute uses the full target list so target indices stay
                // aligned with `LoadBalancer.targets`.
                let port_locality_setting = override_config
                    .locality_lb_setting
                    .as_ref()
                    .or(locality_lb_setting);
                let port_locality_lb =
                    build_locality_lb_state(port_locality_setting, source_locality, targets);
                port_states.insert(
                    *port,
                    PortLbState {
                        target_indices,
                        algorithm: effective_algorithm,
                        algorithm_overridden: override_config.algorithm.is_some(),
                        rr_counter: AtomicU64::new(0),
                        wrr_state,
                        hash_ring,
                        hash_on_strategy: HashOnStrategy::parse(effective_hash_on),
                        hash_on_override_strategy: override_config
                            .hash_on
                            .as_deref()
                            .map(|hash_on| HashOnStrategy::parse(Some(hash_on))),
                        locality_lb: port_locality_lb,
                    },
                );
            }
        }
        let mut initial_dispatch_port_override = 0;
        let mut full_coverage_port_count = 0usize;
        for (&port, state) in &port_states {
            if !targets.is_empty() && state.target_indices.len() == targets.len() {
                full_coverage_port_count += 1;
                initial_dispatch_port_override = if full_coverage_port_count == 1 {
                    port
                } else {
                    0
                };
            }
        }
        debug_assert!(
            full_coverage_port_count <= 1,
            "at most one destination port can cover every target in one upstream"
        );

        // Pre-compute per-target distribute weights and failover-region matches
        // against the source locality so the request path stays branch-light.
        // `enabled: false` disables every locality-aware path; `distribute`
        // and `failover` are mutually exclusive at evaluation time so the
        // pre-compute below is allowed to populate one, the other, or neither.
        let locality_lb = build_locality_lb_state(locality_lb_setting, source_locality, targets);

        // Strict local-first locality LB: precompute which targets are LOCAL so
        // the request path can restrict to them when no source locality
        // resolves, without re-checking provenance per request. A target is
        // local unless it carries the explicit `mesh.remote` provenance tag
        // (stamped at materialization from the workload's cross-cluster
        // identity). Only built when strict mode is enabled so the default path
        // allocates nothing.
        // Cross-cluster east-west gateway targets are always-failover (see
        // `target_is_cross_cluster`): when present, enforce local-first even with
        // `locality_lb_strict` at its default `false`, so the local mask must be
        // built.
        let cross_cluster_failover_present = targets.iter().any(target_is_cross_cluster);
        let local_locality_mask: Vec<bool> = if locality_lb_strict || cross_cluster_failover_present
        {
            targets.iter().map(target_is_local).collect()
        } else {
            Vec::new()
        };

        Self {
            targets: targets.iter().cloned().map(Arc::new).collect(),
            target_keys,
            host_port_keys,
            target_locality_ranks,
            target_index,
            algorithm,
            rr_counter: AtomicU64::new(0),
            wrr_state: if algorithm == LoadBalancerAlgorithm::WeightedRoundRobin {
                WrrLaneState::new(targets.len())
            } else {
                WrrLaneState::inactive()
            },
            active_connections: DashMap::new(),
            hash_ring,
            latency_ewma,
            latency_sample_count,
            hash_on_strategy,
            subset_indices,
            subset_algorithms,
            subset_hash_on_strategies,
            subset_wrr_state,
            subset_hash_rings,
            port_overrides: port_states,
            initial_dispatch_port_override,
            locality_lb,
            locality_lb_strict,
            locality_strict_widen_warned: AtomicBool::new(false),
            local_locality_mask,
            cross_cluster_failover_present,
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

    /// Record a failed dispatch attempt for least-latency warm-up accounting.
    ///
    /// Failed attempts (connection errors / 5xx) never previously counted toward
    /// `latency_sample_count`, so a persistently failing target stayed forever
    /// in the biased warm-up state. A synthetic penalty sample both exits
    /// warm-up and keeps the EWMA from looking artificially fast.
    pub fn record_failed_attempt(&self, target: &UpstreamTarget) {
        self.record_latency(target, LATENCY_FAILURE_PENALTY_US);
    }

    pub fn record_connection_start(&self, target: &UpstreamTarget) {
        let key = self.find_target_key(target).unwrap_or("");
        if key.is_empty() {
            return;
        }
        // Fast path: get() uses a shared read lock. entry() takes a write
        // lock and clones the key -- avoid it when the counter already exists.
        if let Some(counter) = self.active_connections.get(key) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            self.active_connections
                .entry(key.to_owned())
                .or_insert_with(|| AtomicI64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_connection_end(&self, target: &UpstreamTarget) {
        let key = self.find_target_key(target).unwrap_or("");
        if key.is_empty() {
            return;
        }
        if let Some(count) = self.active_connections.get(key) {
            let _ = count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v > 0 { Some(v - 1) } else { None }
            });
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
        // WRR schedules are pure functions of healthy-set fingerprint + immutable
        // weights on this balancer generation. Recovery either changes the
        // fingerprint (cold miss) or restores a still-valid cached schedule —
        // no invalidate flag is required (and a boolean would race publishers).

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

    /// Parent WRR lane counters: `(schedule_publishes, allocation_free_miss_fallbacks)`.
    ///
    /// Intended for diagnostics and deterministic unit coverage of cache-miss
    /// amortization. Neither counter is touched on the steady-state cache-hit path.
    pub fn wrr_parent_schedule_counters(&self) -> (u64, u64) {
        self.wrr_state.schedule_counters()
    }

    /// Find the pre-computed host:port key for a target via O(1) HashMap lookup.
    /// Returns the internal (non-upstream-scoped) key used for active connections,
    /// latency EWMA, and hash ring lookups within this LoadBalancer instance.
    ///
    /// Uses a thread-local buffer to construct the lookup key without allocation.
    #[inline]
    fn find_target_key(&self, target: &UpstreamTarget) -> Option<&str> {
        thread_local! {
            static TARGET_KEY_BUF: std::cell::RefCell<String> =
                std::cell::RefCell::new(String::with_capacity(64));
        }
        TARGET_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_target_host_port_key(&mut buf, target);
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
        // Track which indices are ejected only by passive health (not active),
        // so the ejection cap can selectively re-admit the earliest ones.
        let mut passive_ejected: Vec<(usize, u64)> = Vec::new();

        for i in 0..n {
            // Active: pre-computed "upstream_id::host:port" key
            if h.active_unhealthy.contains_key(&self.target_keys[i]) {
                // Active ejections are not subject to the cap — the target is
                // genuinely unreachable.
                continue;
            }
            // Passive: direct "host:port" lookup in proxy's own map
            if let Some(ref ps) = h.proxy_passive
                && let Some(entry) = ps.unhealthy.get(&self.host_port_keys[i])
            {
                passive_ejected.push((i, entry.ejected_at_ms));
                continue;
            }
            bitset.set(i);
        }

        let to_readmit =
            passive_ejections_to_readmit(&mut passive_ejected, n, h.max_ejection_percent);
        for &(idx, _) in passive_ejected.iter().take(to_readmit) {
            bitset.set(idx);
        }

        bitset
    }

    /// Compute healthy indices for a pre-filtered target set. This keeps
    /// passive max-ejection caps scoped to the actual candidate pool, such as a
    /// DestinationRule port-level override, instead of diluting the cap across
    /// unrelated targets on other ports.
    #[inline]
    fn compute_health_bitset_for_indices(
        &self,
        health: Option<&HealthContext<'_>>,
        indices: &[usize],
    ) -> HealthBitset {
        let Some(h) = health else {
            return bitset_for_indices(indices);
        };

        if h.active_unhealthy.is_empty()
            && h.proxy_passive
                .as_ref()
                .is_none_or(|ps| ps.unhealthy.is_empty())
        {
            return bitset_for_indices(indices);
        }

        let mut bitset = HealthBitset::empty();
        let mut passive_ejected: Vec<(usize, u64)> = Vec::new();

        for &i in indices {
            debug_assert!(i < self.targets.len());
            if i >= self.targets.len() {
                continue;
            }
            if h.active_unhealthy.contains_key(&self.target_keys[i]) {
                continue;
            }
            if let Some(ref ps) = h.proxy_passive
                && let Some(entry) = ps.unhealthy.get(&self.host_port_keys[i])
            {
                passive_ejected.push((i, entry.ejected_at_ms));
                continue;
            }
            bitset.set(i);
        }

        let to_readmit = passive_ejections_to_readmit(
            &mut passive_ejected,
            indices.len(),
            h.max_ejection_percent,
        );
        for &(idx, _) in passive_ejected.iter().take(to_readmit) {
            bitset.set(idx);
        }

        bitset
    }

    /// Alloc-free analogue of [`Self::compute_health_bitset_for_indices`] that
    /// takes a candidate `mask` (a stack `u128` bitset) instead of an index
    /// slice. The passive max-ejection cap is sized against the mask's popcount
    /// (`mask.count()`) — the candidate-pool size — so subset / subset∩port
    /// dispatches scope the cap to the actual candidates without allocating a
    /// per-request index `Vec`. The returned healthy bitset is a subset of
    /// `mask` (only candidates in the mask can be set).
    #[inline]
    fn compute_health_bitset_for_mask(
        &self,
        health: Option<&HealthContext<'_>>,
        mask: &HealthBitset,
    ) -> HealthBitset {
        let Some(h) = health else {
            return *mask;
        };

        if h.active_unhealthy.is_empty()
            && h.proxy_passive
                .as_ref()
                .is_none_or(|ps| ps.unhealthy.is_empty())
        {
            return *mask;
        }

        let candidate_count = mask.count();
        let mut bitset = HealthBitset::empty();
        let mut passive_ejected: Vec<(usize, u64)> = Vec::new();

        mask.for_each_set_bit(|i| {
            debug_assert!(i < self.targets.len());
            if i >= self.targets.len() {
                return;
            }
            if h.active_unhealthy.contains_key(&self.target_keys[i]) {
                return;
            }
            if let Some(ref ps) = h.proxy_passive
                && let Some(entry) = ps.unhealthy.get(&self.host_port_keys[i])
            {
                passive_ejected.push((i, entry.ejected_at_ms));
                return;
            }
            bitset.set(i);
        });

        let to_readmit = passive_ejections_to_readmit(
            &mut passive_ejected,
            candidate_count,
            h.max_ejection_percent,
        );
        for &(idx, _) in passive_ejected.iter().take(to_readmit) {
            bitset.set(idx);
        }

        bitset
    }

    /// Collect healthy targets into a Vec — fallback for upstreams with >128
    /// targets that cannot use the bitset fast path.
    ///
    /// Returned pairs are always ascending by original target index so WRR
    /// schedule keys stay membership-stable and hit resolution can
    /// `binary_search_by_key`.
    fn healthy_targets_vec(
        &self,
        health: Option<&HealthContext<'_>>,
    ) -> Vec<(usize, &Arc<UpstreamTarget>)> {
        let n = self.targets.len();
        let Some(h) = health else {
            return self.targets.iter().enumerate().collect();
        };

        let mut healthy: Vec<(usize, &Arc<UpstreamTarget>)> = Vec::new();
        let mut passive_ejected: Vec<(usize, u64)> = Vec::new();

        for (i, target) in self.targets.iter().enumerate() {
            if h.active_unhealthy.contains_key(&self.target_keys[i]) {
                continue;
            }
            if let Some(ref ps) = h.proxy_passive
                && let Some(entry) = ps.unhealthy.get(&self.host_port_keys[i])
            {
                passive_ejected.push((i, entry.ejected_at_ms));
                continue;
            }
            healthy.push((i, target));
        }

        let to_readmit =
            passive_ejections_to_readmit(&mut passive_ejected, n, h.max_ejection_percent);
        if to_readmit > 0 {
            for &(idx, _) in passive_ejected.iter().take(to_readmit) {
                healthy.push((idx, &self.targets[idx]));
            }
            // Readmits were appended out of enumeration order; restore the
            // ascending original-index invariant used by WRR Vec cache keys.
            healthy.sort_unstable_by_key(|(idx, _)| *idx);
        }

        healthy
    }

    /// Vec fallback equivalent of `compute_health_bitset_for_indices`.
    ///
    /// Like [`Self::healthy_targets_vec`], results are ascending by original
    /// index (input `indices` are already ascending from subset/port
    /// construction; readmits are re-sorted).
    fn healthy_targets_vec_for_indices(
        &self,
        health: Option<&HealthContext<'_>>,
        indices: &[usize],
    ) -> Vec<(usize, &Arc<UpstreamTarget>)> {
        let Some(h) = health else {
            return indices
                .iter()
                .copied()
                .filter_map(|idx| self.targets.get(idx).map(|target| (idx, target)))
                .collect();
        };

        let mut healthy: Vec<(usize, &Arc<UpstreamTarget>)> = Vec::new();
        let mut passive_ejected: Vec<(usize, u64)> = Vec::new();

        for &i in indices {
            let Some(target) = self.targets.get(i) else {
                continue;
            };
            if h.active_unhealthy.contains_key(&self.target_keys[i]) {
                continue;
            }
            if let Some(ref ps) = h.proxy_passive
                && let Some(entry) = ps.unhealthy.get(&self.host_port_keys[i])
            {
                passive_ejected.push((i, entry.ejected_at_ms));
                continue;
            }
            healthy.push((i, target));
        }

        let to_readmit = passive_ejections_to_readmit(
            &mut passive_ejected,
            indices.len(),
            h.max_ejection_percent,
        );
        if to_readmit > 0 {
            for &(idx, _) in passive_ejected.iter().take(to_readmit) {
                healthy.push((idx, &self.targets[idx]));
            }
            healthy.sort_unstable_by_key(|(idx, _)| *idx);
        }

        healthy
    }

    #[inline]
    fn locality_rank(&self, idx: usize) -> u8 {
        // Empty `target_locality_ranks` means no source locality is set, in
        // which case callers short-circuit before reaching this helper.
        self.target_locality_ranks.get(idx).copied().unwrap_or(3)
    }

    #[inline]
    /// Resolve the locality-preferred candidate subset for the bitset path.
    ///
    /// `candidates` is the health-filtered pool to prefer within; `scope` is the
    /// unfiltered candidate membership it was derived from (the full upstream,
    /// or a port/subset/exclude-scoped pool). `scope` is only consulted on the
    /// strict no-source path to decide whether configured-local endpoints exist
    /// in this scope, so strict mode can fail closed to (possibly unhealthy)
    /// local endpoints instead of widening to healthy remote-cluster endpoints.
    ///
    /// Returns `(preferred, degraded)`. `degraded` is true only when strict mode
    /// had no healthy local candidate and fell back to scope-local endpoints that
    /// were filtered out by health — i.e. the caller is serving an unhealthy
    /// local target and should mark the selection as a degraded fallback.
    fn preferred_locality_bitset(
        &self,
        candidates: &HealthBitset,
        scope: &HealthBitset,
        locality_lb: Option<&LocalityLbState>,
    ) -> (HealthBitset, bool) {
        // [R5-2]/[R6-1]/[R6-2] Cross-cluster east-west GATEWAY targets are
        // ALWAYS-failover: they must never share round-robin with healthy local
        // endpoints, regardless of locality-LB config — the `enabled: false`
        // short-circuit, distribute weights, ranked tiers, or the no-source path
        // each otherwise leak the gateway into the mixed pool. Pre-filter the
        // candidate pool to healthy LOCAL endpoints whenever any exist, so every
        // path below sees only locals; when NO healthy local remains, the gateway
        // stays and is selected (failover). Strict mode still runs below on the
        // filtered pool and keeps its own fail-closed-to-unhealthy-local contract
        // via `scope`.
        let failover_filtered;
        let candidates = if self.cross_cluster_failover_present {
            let mut healthy_local = HealthBitset::empty();
            for idx in 0..self.targets.len() {
                if candidates.contains(idx)
                    && self.local_locality_mask.get(idx).copied().unwrap_or(true)
                {
                    healthy_local.set(idx);
                }
            }
            if healthy_local.is_empty() {
                candidates
            } else {
                failover_filtered = healthy_local;
                &failover_filtered
            }
        } else {
            candidates
        };

        // Operator-disabled locality LB short-circuits the priority tier
        // preference entirely (Istio `localityLbSetting.enabled: false`).
        if locality_lb.is_some_and(|state| !state.enabled) {
            return (*candidates, false);
        }

        // distribute-mode: restrict the candidate set to targets the
        // operator put weight on. Algorithm dispatch later picks one weighted
        // distribute bucket inside this union and runs the configured endpoint
        // algorithm there. We do this before priority-tier preference because
        // Istio treats distribute and priority as mutually exclusive.
        if let Some(weights) = locality_lb.and_then(|state| state.distribute_weights.as_ref()) {
            let mut masked = HealthBitset::empty();
            for idx in 0..self.targets.len() {
                if candidates.contains(idx) && weights.get(idx).copied().unwrap_or(0) > 0 {
                    masked.set(idx);
                }
            }
            if !masked.is_empty() {
                return (masked, false);
            }
            // Operator typo or every weighted target unhealthy: keep
            // evaluating the normal locality tiers below so exact/zone/region
            // preference still applies before the final residual candidate
            // fallback.
        }

        // No source locality → no tier preference. Default (fail-open) returns
        // the input unchanged. Strict mode restricts to LOCAL endpoints and fails
        // CLOSED to unhealthy local rather than widening to remote
        // (`strict_local_bitset`). Cross-cluster failover already pre-filtered the
        // candidate pool above, so `candidates` here is local-only when healthy
        // local exists, or the gateway when it does not.
        if self.target_locality_ranks.is_empty() {
            if self.locality_lb_strict {
                return self.strict_local_bitset(candidates, scope);
            }
            return (*candidates, false);
        }

        let mut exact = HealthBitset::empty();
        let mut zone = HealthBitset::empty();
        let mut region = HealthBitset::empty();
        for idx in 0..self.targets.len() {
            if !candidates.contains(idx) {
                continue;
            }
            match self.locality_rank(idx) {
                0 => exact.set(idx),
                1 => zone.set(idx),
                2 => region.set(idx),
                _ => {}
            }
        }

        if !exact.is_empty() {
            return (exact, false);
        }
        if !zone.is_empty() {
            return (zone, false);
        }
        if !region.is_empty() {
            return (region, false);
        }

        // Failover override sits between the region tier and the unfiltered
        // candidate set: when the source region is exhausted, prefer the
        // operator-configured failover region before falling through.
        if let Some(matches) = locality_lb.and_then(|state| state.failover_target_matches.as_ref())
        {
            let mut failover = HealthBitset::empty();
            for idx in 0..self.targets.len() {
                if candidates.contains(idx) && matches.get(idx).copied().unwrap_or(false) {
                    failover.set(idx);
                }
            }
            if !failover.is_empty() {
                return (failover, false);
            }
        }

        (*candidates, false)
    }

    fn preferred_locality_candidates<'a>(
        &'a self,
        candidates: Vec<(usize, &'a Arc<UpstreamTarget>)>,
        scope_indices: &[usize],
        locality_lb: Option<&LocalityLbState>,
    ) -> (Vec<(usize, &'a Arc<UpstreamTarget>)>, bool) {
        // Mirror `preferred_locality_bitset` semantics on the Vec path so the
        // > 128-target fallback agrees with the bitset path. `scope_indices` is
        // the unfiltered candidate membership and is only consulted on the
        // strict no-source path. Returns `(preferred, degraded)` where `degraded`
        // marks a strict fail-closed fallback to unhealthy local endpoints.

        // [R5-2]/[R6-1]/[R6-2] Cross-cluster failover pre-filter (Vec counterpart
        // of the bitset path): restrict to healthy LOCAL endpoints whenever any
        // exist so the always-failover gateway never shares round-robin with
        // healthy locals — regardless of locality-LB config; when none remain,
        // keep the gateway so it is selected (failover).
        let candidates = if self.cross_cluster_failover_present {
            let healthy_local: Vec<(usize, &'a Arc<UpstreamTarget>)> = candidates
                .iter()
                .copied()
                .filter(|(idx, _)| self.local_locality_mask.get(*idx).copied().unwrap_or(true))
                .collect();
            if healthy_local.is_empty() {
                candidates
            } else {
                healthy_local
            }
        } else {
            candidates
        };

        if locality_lb.is_some_and(|state| !state.enabled) {
            return (candidates, false);
        }

        // distribute-mode: restrict to operator-weighted targets when any are
        // available. If every weighted target is missing, continue into the
        // normal locality tiers below.
        if let Some(weights) = locality_lb.and_then(|state| state.distribute_weights.as_ref()) {
            let masked: Vec<(usize, &'a Arc<UpstreamTarget>)> = candidates
                .iter()
                .copied()
                .filter(|(idx, _)| weights.get(*idx).copied().unwrap_or(0) > 0)
                .collect();
            if !masked.is_empty() {
                return (masked, false);
            }
        }

        // No source locality → no tier preference. Default returns the mixed
        // local + remote pool; STRICT mode fails closed to local
        // (`strict_local_candidates`). Cross-cluster failover already pre-filtered
        // the pool above. Vec-path counterpart of `preferred_locality_bitset`.
        if self.target_locality_ranks.is_empty() {
            if self.locality_lb_strict {
                return self.strict_local_candidates(candidates, scope_indices);
            }
            return (candidates, false);
        }

        let mut best_rank = 3;
        let mut preferred = Vec::new();
        for candidate in candidates.iter().copied() {
            let rank = self.locality_rank(candidate.0);
            if rank >= 3 {
                continue;
            }
            if rank < best_rank {
                preferred.clear();
                best_rank = rank;
            }
            if rank == best_rank {
                preferred.push(candidate);
            }
        }

        if !preferred.is_empty() {
            return (preferred, false);
        }

        if let Some(matches) = locality_lb.and_then(|state| state.failover_target_matches.as_ref())
        {
            let failover: Vec<(usize, &'a Arc<UpstreamTarget>)> = candidates
                .iter()
                .copied()
                .filter(|(idx, _)| matches.get(*idx).copied().unwrap_or(false))
                .collect();
            if !failover.is_empty() {
                return (failover, false);
            }
        }

        (candidates, false)
    }

    /// Log the "strict locality LB found no local endpoints" widen-to-full-pool
    /// warning at most once per balancer instance. Used only when the upstream
    /// has no configured local endpoints; strict mode must not widen merely
    /// because configured local endpoints are currently unhealthy/ejected.
    #[cold]
    fn warn_strict_locality_widen(&self) {
        if !self
            .locality_strict_widen_warned
            .swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                upstream = %self.upstream_id_log(),
                "FERRUM_MESH_LOCALITY_LB_STRICT is set but this upstream has no \
                 source locality AND no local-locality endpoints; widening to the \
                 full healthy pool (local + remote) to avoid black-holing traffic. \
                 Set the workload's topology.kubernetes.io/region|zone labels (or \
                 FERRUM_K8S_NODE_LOCALITY_ENABLED) so local-first preference can \
                 apply."
            );
        }
    }

    /// Best-effort upstream id for diagnostics, recovered from the precomputed
    /// `target_keys` (format `upstream_id::host:port`). Used only on the cold
    /// strict-widen warning path, so a linear peek at the first key is fine.
    fn upstream_id_log(&self) -> &str {
        self.target_keys
            .first()
            .and_then(|key| key.split("::").next())
            .unwrap_or("<unknown>")
    }

    /// Strict local-first restriction for the bitset path: keep only candidates
    /// whose locality marks them LOCAL (precomputed in `local_locality_mask`).
    ///
    /// `candidates` is the health-filtered pool; `scope` is the unfiltered
    /// candidate membership it was derived from. Behavior when no *healthy*
    /// local candidate exists:
    /// - If this scope has configured-local endpoints (present in `scope` but
    ///   filtered out by health), fail closed to those unhealthy local
    ///   endpoints — return them with `degraded = true` — instead of widening to
    ///   healthy remote-cluster endpoints.
    /// - If this scope has no local endpoint at all, widen back to the input
    ///   (warn once) to preserve availability for genuinely remote-only scopes.
    ///
    /// Returns `(set, degraded)`. The set is non-empty whenever `scope` is
    /// non-empty, so callers never have to re-widen a black-holed empty result.
    #[inline]
    fn strict_local_bitset(
        &self,
        candidates: &HealthBitset,
        scope: &HealthBitset,
    ) -> (HealthBitset, bool) {
        if self.local_locality_mask.is_empty() {
            // Defensive: mask is always populated when strict mode is on, but if
            // it is somehow empty there is no local/remote signal — return the
            // input unchanged rather than dropping every candidate.
            return (*candidates, false);
        }
        let mut local = HealthBitset::empty();
        for idx in 0..self.targets.len() {
            if candidates.contains(idx)
                && self.local_locality_mask.get(idx).copied().unwrap_or(true)
            {
                local.set(idx);
            }
        }
        if !local.is_empty() {
            return (local, false);
        }
        // No healthy local. Decide between failing closed to unhealthy local and
        // widening to remote based on whether THIS scope has any local endpoint.
        let mut scope_local = HealthBitset::empty();
        for idx in 0..self.targets.len() {
            if scope.contains(idx) && self.local_locality_mask.get(idx).copied().unwrap_or(true) {
                scope_local.set(idx);
            }
        }
        if !scope_local.is_empty() {
            return (scope_local, true);
        }
        self.warn_strict_locality_widen();
        (*candidates, false)
    }

    /// Vec-path counterpart of [`Self::strict_local_bitset`] for the >128-target
    /// fallback. `scope_indices` is the unfiltered candidate membership.
    fn strict_local_candidates<'a>(
        &'a self,
        candidates: Vec<(usize, &'a Arc<UpstreamTarget>)>,
        scope_indices: &[usize],
    ) -> (Vec<(usize, &'a Arc<UpstreamTarget>)>, bool) {
        if self.local_locality_mask.is_empty() {
            return (candidates, false);
        }
        let local: Vec<(usize, &'a Arc<UpstreamTarget>)> = candidates
            .iter()
            .copied()
            .filter(|(idx, _)| self.local_locality_mask.get(*idx).copied().unwrap_or(true))
            .collect();
        if !local.is_empty() {
            return (local, false);
        }
        // No healthy local: fail closed to this scope's (unhealthy) local
        // endpoints when it has any, else widen to the input (remote-only scope).
        let scope_local: Vec<(usize, &'a Arc<UpstreamTarget>)> = scope_indices
            .iter()
            .copied()
            .filter(|idx| self.local_locality_mask.get(*idx).copied().unwrap_or(true))
            .map(|idx| (idx, &self.targets[idx]))
            .collect();
        if !scope_local.is_empty() {
            return (scope_local, true);
        }
        self.warn_strict_locality_widen();
        (candidates, false)
    }

    fn distribute_pick(
        &self,
        ctx_key: &str,
        total: u64,
        algorithm: LoadBalancerAlgorithm,
        distribute_counter: &AtomicU64,
    ) -> u64 {
        let raw = match algorithm {
            LoadBalancerAlgorithm::ConsistentHashing => fx_hash_str(ctx_key),
            _ => distribute_counter.fetch_add(1, Ordering::Relaxed),
        };
        golden_ratio_hash(raw) % total
    }

    /// Pick one distribute locality bucket that has at least one candidate,
    /// then return that bucket as a bitset. The caller still runs the configured
    /// endpoint algorithm inside the returned set.
    fn distribute_group_bitset(
        &self,
        healthy: &HealthBitset,
        ctx_key: &str,
        algorithm: LoadBalancerAlgorithm,
        locality_lb: Option<&LocalityLbState>,
    ) -> Option<HealthBitset> {
        let state = locality_lb?;
        let groups = state.distribute_groups.as_ref()?;
        let mut total = 0u64;
        for group in groups {
            if group
                .target_indices
                .iter()
                .any(|idx| healthy.contains(*idx))
            {
                total = total.saturating_add(group.weight);
            }
        }
        if total == 0 {
            return None;
        }

        let pick = self.distribute_pick(ctx_key, total, algorithm, &state.distribute_counter);
        let mut acc = 0u64;
        let mut first_eligible = None;
        for group in groups {
            let mut masked = HealthBitset::empty();
            for &idx in &group.target_indices {
                if healthy.contains(idx) {
                    masked.set(idx);
                }
            }
            if masked.is_empty() {
                continue;
            }
            if first_eligible.is_none() {
                first_eligible = Some(masked);
            }
            acc = acc.saturating_add(group.weight);
            if pick < acc {
                return Some(masked);
            }
        }
        first_eligible
    }

    /// Vec-path counterpart of `distribute_group_bitset` for the >128-target
    /// fallback. Returns candidates from one weighted locality bucket.
    fn distribute_group_candidates<'a>(
        &self,
        candidates: &[(usize, &'a Arc<UpstreamTarget>)],
        ctx_key: &str,
        algorithm: LoadBalancerAlgorithm,
        locality_lb: Option<&LocalityLbState>,
    ) -> Option<Vec<(usize, &'a Arc<UpstreamTarget>)>> {
        let state = locality_lb?;
        let groups = state.distribute_groups.as_ref()?;

        let mut total = 0u64;
        for group in groups {
            if candidates
                .iter()
                .any(|(idx, _)| group.target_membership.get(*idx).copied().unwrap_or(false))
            {
                total = total.saturating_add(group.weight);
            }
        }
        if total == 0 {
            return None;
        }

        let pick = self.distribute_pick(ctx_key, total, algorithm, &state.distribute_counter);
        let mut acc = 0u64;
        let mut first_eligible = None;
        for group in groups {
            let masked: Vec<(usize, &'a Arc<UpstreamTarget>)> = candidates
                .iter()
                .copied()
                .filter(|(idx, _)| group.target_membership.get(*idx).copied().unwrap_or(false))
                .collect();
            if masked.is_empty() {
                continue;
            }
            if first_eligible.is_none() {
                first_eligible = Some(masked.clone());
            }
            acc = acc.saturating_add(group.weight);
            if pick < acc {
                return Some(masked);
            }
        }
        first_eligible
    }

    /// Candidate mask for a port+subset dispatch: the indices present in BOTH
    /// `subset_indices` and `port_indices` (subset∩port), as a stack `u128`
    /// bitset. Used to scope the passive ejection cap to subset∩port instead of
    /// the whole port. Both slices hold in-bounds indices `< MAX_BITSET_TARGETS`
    /// (this is the ≤128-target bitset path), so the intersection is a register
    /// AND of two stack `u128`s — no per-request heap allocation.
    #[inline]
    fn subset_port_mask(&self, subset_indices: &[usize], port_indices: &[usize]) -> HealthBitset {
        bitset_for_indices(subset_indices).intersect(&bitset_for_indices(port_indices))
    }

    /// Vec-fallback (>128 targets) equivalent of [`Self::subset_port_mask`].
    /// Indices may be `>= MAX_BITSET_TARGETS`, so port membership is tested
    /// against a `Vec<bool>` mask sized to the full target count instead of a
    /// `u128` bitset.
    fn subset_port_intersection_vec(
        &self,
        subset_indices: &[usize],
        port_indices: &[usize],
    ) -> Vec<usize> {
        let port_mask = membership_mask_for_indices(self.targets.len(), port_indices);
        subset_indices
            .iter()
            .copied()
            .filter(|&idx| port_mask.get(idx).copied().unwrap_or(false))
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

        let scope = HealthBitset::all(n);
        if healthy.is_empty() {
            // All targets unhealthy — degraded mode fallback using all targets.
            let (all, _) =
                self.preferred_locality_bitset(&scope, &scope, self.locality_lb.as_ref());
            return self
                .select_with_bitset(ctx_key, &all)
                .map(|target| TargetSelection {
                    target,
                    is_fallback: true,
                });
        }

        let (healthy, degraded) =
            self.preferred_locality_bitset(&healthy, &scope, self.locality_lb.as_ref());
        self.select_with_bitset(ctx_key, &healthy)
            .map(|target| TargetSelection {
                target,
                is_fallback: degraded,
            })
    }

    /// Select a target from a named subset, intersecting subset membership
    /// with the health bitset. Unknown, empty, or fully unhealthy subsets
    /// return `None` so config typos and subset outages cannot silently route
    /// across the whole upstream.
    pub fn select_from_subset(
        &self,
        ctx_key: &str,
        subset_name: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let n = self.targets.len();
        if n == 0 {
            return None;
        }

        let subset_target_indices = match self.subset_indices.get(subset_name) {
            Some(indices) if !indices.is_empty() => indices,
            Some(_) => return None,
            None => return None,
        };
        let algorithm = self.subset_algorithm(subset_name);
        let wrr_state = self.subset_wrr_state(subset_name);
        let hash_ring = self.subset_hash_ring(subset_name);

        // For >128 targets, use the Vec path directly.
        if n > MAX_BITSET_TARGETS {
            return self.select_subset_vec_fallback(
                ctx_key,
                subset_name,
                subset_target_indices,
                health,
            );
        }

        // Compute the health bitset scoped to the subset's candidate pool, so a
        // subset-scoped ejection cap is sized against the subset target count —
        // not the full upstream (which would dilute the cap and let a
        // small-subset/large-upstream combination keep the whole subset ejected).
        // The returned bitset is already subset-scoped; no post-hoc intersect.
        let subset_healthy = self.compute_health_bitset_for_indices(health, subset_target_indices);

        if subset_healthy.is_empty() {
            return None;
        }

        let subset_scope = bitset_for_indices(subset_target_indices);
        let (subset_healthy, degraded) = self.preferred_locality_bitset(
            &subset_healthy,
            &subset_scope,
            self.locality_lb.as_ref(),
        );
        self.select_with_bitset_using(
            ctx_key,
            &subset_healthy,
            algorithm,
            &self.rr_counter,
            wrr_state,
            hash_ring,
            self.locality_lb.as_ref(),
        )
        .map(|target| TargetSelection {
            target,
            is_fallback: degraded,
        })
    }

    /// Select a target using a per-port override when one exists for `port`.
    /// Missing port state falls back to the upstream-level selector.
    pub fn select_for_port(
        &self,
        ctx_key: &str,
        port: u16,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let Some(port_state) = self.port_overrides.get(&port) else {
            return self.select(ctx_key, health);
        };
        let n = self.targets.len();
        if n == 0 || port_state.target_indices.is_empty() {
            return None;
        }

        if n > MAX_BITSET_TARGETS {
            return self.select_port_vec_fallback(ctx_key, port_state, health);
        }

        let port_healthy =
            self.compute_health_bitset_for_indices(health, &port_state.target_indices);
        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());

        let port_scope = bitset_for_indices(&port_state.target_indices);
        if port_healthy.is_empty() {
            let (all_port_targets, _) =
                self.preferred_locality_bitset(&port_scope, &port_scope, port_locality);
            return self
                .select_with_bitset_using(
                    ctx_key,
                    &all_port_targets,
                    port_state.algorithm,
                    &port_state.rr_counter,
                    &port_state.wrr_state,
                    &port_state.hash_ring,
                    port_locality,
                )
                .map(|target| TargetSelection {
                    target,
                    is_fallback: true,
                });
        }

        let (port_healthy, degraded) =
            self.preferred_locality_bitset(&port_healthy, &port_scope, port_locality);
        self.select_with_bitset_using(
            ctx_key,
            &port_healthy,
            port_state.algorithm,
            &port_state.rr_counter,
            &port_state.wrr_state,
            &port_state.hash_ring,
            port_locality,
        )
        .map(|target| TargetSelection {
            target,
            is_fallback: degraded,
        })
    }

    /// Select a target from a named subset using a per-port override when one
    /// exists for `port`. Unknown, empty, or fully unhealthy subset/port
    /// intersections return `None`, matching `select_from_subset`.
    pub fn select_for_port_from_subset(
        &self,
        ctx_key: &str,
        port: u16,
        subset_name: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let Some(port_state) = self.port_overrides.get(&port) else {
            return self.select_from_subset(ctx_key, subset_name, health);
        };
        let n = self.targets.len();
        if n == 0 || port_state.target_indices.is_empty() {
            return None;
        }
        let subset_target_indices = match self.subset_indices.get(subset_name) {
            Some(indices) if !indices.is_empty() => indices,
            Some(_) => return None,
            None => return None,
        };

        if n > MAX_BITSET_TARGETS {
            return self.select_port_subset_vec_fallback(
                ctx_key,
                port_state,
                subset_name,
                subset_target_indices,
                health,
            );
        }

        // The candidate pool for a port+subset dispatch is subset∩port, so the
        // ejection cap must be sized against that intersection — not the whole
        // port (which would over-count the denominator and keep too many
        // subset∩port targets ejected). Build the intersection as an alloc-free
        // stack `u128` mask (no per-request `Vec`); the returned bitset is
        // already scoped to it, so no post-hoc subset mask is needed.
        let intersection = self.subset_port_mask(subset_target_indices, &port_state.target_indices);
        if intersection.is_empty() {
            return None;
        }
        let port_subset_healthy = self.compute_health_bitset_for_mask(health, &intersection);

        if port_subset_healthy.is_empty() {
            return None;
        }

        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        let (port_subset_healthy, degraded) =
            self.preferred_locality_bitset(&port_subset_healthy, &intersection, port_locality);
        self.select_with_bitset_using(
            ctx_key,
            &port_subset_healthy,
            self.port_subset_algorithm(port_state, subset_name),
            self.port_subset_rr_counter(port_state),
            self.port_subset_wrr_state(port_state, subset_name),
            self.port_subset_hash_ring(port_state, subset_name),
            port_locality,
        )
        .map(|target| TargetSelection {
            target,
            is_fallback: degraded,
        })
    }

    fn select_port_vec_fallback(
        &self,
        ctx_key: &str,
        port_state: &PortLbState,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let mut candidates =
            self.healthy_targets_vec_for_indices(health, &port_state.target_indices);
        let is_fallback = candidates.is_empty();
        if is_fallback {
            candidates = port_state
                .target_indices
                .iter()
                .map(|&idx| (idx, &self.targets[idx]))
                .collect();
        }
        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        let (candidates, degraded) = self.preferred_locality_candidates(
            candidates,
            &port_state.target_indices,
            port_locality,
        );

        self.select_from_candidates_vec_using(
            ctx_key,
            &candidates,
            port_state.algorithm,
            &port_state.rr_counter,
            &port_state.wrr_state,
            &port_state.hash_ring,
            port_locality,
        )
        .map(|target| TargetSelection {
            target,
            is_fallback: is_fallback || degraded,
        })
    }

    fn select_port_subset_vec_fallback(
        &self,
        ctx_key: &str,
        port_state: &PortLbState,
        subset_name: &str,
        subset_indices: &[usize],
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        // Cap against subset∩port (mirrors the bitset path), not the whole port.
        let intersection =
            self.subset_port_intersection_vec(subset_indices, &port_state.target_indices);
        if intersection.is_empty() {
            return None;
        }
        let candidates = self.healthy_targets_vec_for_indices(health, &intersection);
        if candidates.is_empty() {
            return None;
        }
        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        let (candidates, degraded) =
            self.preferred_locality_candidates(candidates, &intersection, port_locality);

        self.select_from_candidates_vec_using(
            ctx_key,
            &candidates,
            self.port_subset_algorithm(port_state, subset_name),
            self.port_subset_rr_counter(port_state),
            self.port_subset_wrr_state(port_state, subset_name),
            self.port_subset_hash_ring(port_state, subset_name),
            port_locality,
        )
        .map(|target| TargetSelection {
            target,
            is_fallback: degraded,
        })
    }

    /// Vec-based subset selection fallback for >128 targets.
    fn select_subset_vec_fallback(
        &self,
        ctx_key: &str,
        subset_name: &str,
        subset_indices: &[usize],
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        // Scope the ejection cap to the subset candidate pool (mirrors the
        // bitset path's `compute_health_bitset_for_indices`): cap against the
        // subset target count, not the full upstream.
        let subset_healthy = self.healthy_targets_vec_for_indices(health, subset_indices);

        if subset_healthy.is_empty() {
            return None;
        }
        let (subset_healthy, degraded) = self.preferred_locality_candidates(
            subset_healthy,
            subset_indices,
            self.locality_lb.as_ref(),
        );

        self.select_from_candidates_vec_using(
            ctx_key,
            &subset_healthy,
            self.subset_algorithm(subset_name),
            &self.rr_counter,
            self.subset_wrr_state(subset_name),
            self.subset_hash_ring(subset_name),
            self.locality_lb.as_ref(),
        )
        .map(|target| TargetSelection {
            target,
            is_fallback: degraded,
        })
    }

    /// Return the pre-computed subset indices for a given subset name, if any.
    #[inline]
    pub fn subset_indices(&self, subset_name: &str) -> Option<&[usize]> {
        self.subset_indices.get(subset_name).map(|v| v.as_slice())
    }

    #[inline]
    fn subset_algorithm(&self, subset_name: &str) -> LoadBalancerAlgorithm {
        self.subset_algorithms
            .get(subset_name)
            .copied()
            .unwrap_or(self.algorithm)
    }

    #[inline]
    fn hash_on_strategy_for_subset(&self, subset_name: &str) -> HashOnStrategy {
        self.subset_hash_on_strategies
            .get(subset_name)
            .cloned()
            .unwrap_or_else(|| self.hash_on_strategy.clone())
    }

    #[inline]
    fn hash_on_strategy_for_selection(
        &self,
        port: Option<u16>,
        subset_name: Option<&str>,
    ) -> HashOnStrategy {
        if let Some(port) = port
            && let Some(state) = self.port_overrides.get(&port)
        {
            if state.algorithm_overridden || subset_name.is_none() {
                return state.hash_on_strategy.clone();
            }
            if let Some(subset_name) = subset_name
                && self.subset_algorithm(subset_name) == LoadBalancerAlgorithm::ConsistentHashing
                && let Some(strategy) = &state.hash_on_override_strategy
            {
                return strategy.clone();
            }
        }
        if let Some(subset_name) = subset_name {
            return self.hash_on_strategy_for_subset(subset_name);
        }
        self.hash_on_strategy.clone()
    }

    /// Resolve the effective algorithm a selection for `(port_override, subset)`
    /// would use, with the SAME precedence as the `select*` family: an explicit
    /// per-port algorithm wins over a subset override, which wins over the
    /// upstream-level algorithm. Port overrides that only carry non-algorithm
    /// policy (for example locality) keep the subset algorithm while scoping the
    /// candidate/locality lane to the port. Used by `select_upstream_target` to
    /// decide whether to attempt PASSTHROUGH orig-dst matching before dispatching.
    #[inline]
    pub fn effective_algorithm(
        &self,
        port: Option<u16>,
        subset_name: Option<&str>,
    ) -> LoadBalancerAlgorithm {
        if let Some(p) = port
            && let Some(port_state) = self.port_overrides.get(&p)
            && (port_state.algorithm_overridden || subset_name.is_none())
        {
            return port_state.algorithm;
        }
        match subset_name {
            Some(name) => self.subset_algorithm(name),
            None => self.algorithm,
        }
    }

    #[inline]
    fn port_subset_algorithm(
        &self,
        port_state: &PortLbState,
        subset_name: &str,
    ) -> LoadBalancerAlgorithm {
        if port_state.algorithm_overridden {
            port_state.algorithm
        } else {
            self.subset_algorithm(subset_name)
        }
    }

    #[inline]
    fn port_subset_rr_counter<'a>(&'a self, port_state: &'a PortLbState) -> &'a AtomicU64 {
        if port_state.algorithm_overridden {
            &port_state.rr_counter
        } else {
            &self.rr_counter
        }
    }

    #[inline]
    fn port_subset_wrr_state<'a>(
        &'a self,
        port_state: &'a PortLbState,
        subset_name: &str,
    ) -> &'a WrrLaneState {
        if port_state.algorithm_overridden {
            &port_state.wrr_state
        } else {
            self.subset_wrr_state(subset_name)
        }
    }

    #[inline]
    fn port_subset_hash_ring<'a>(
        &'a self,
        port_state: &'a PortLbState,
        subset_name: &str,
    ) -> &'a [(u64, usize)] {
        if port_state.algorithm_overridden {
            &port_state.hash_ring
        } else {
            self.subset_hash_ring(subset_name)
        }
    }

    #[inline]
    fn subset_wrr_state(&self, subset_name: &str) -> &WrrLaneState {
        self.subset_wrr_state
            .get(subset_name)
            .unwrap_or(&self.wrr_state)
    }

    #[inline]
    fn subset_hash_ring(&self, subset_name: &str) -> &[(u64, usize)] {
        self.subset_hash_rings
            .get(subset_name)
            .map(Vec::as_slice)
            .unwrap_or(&self.hash_ring)
    }

    #[inline]
    fn has_port_override_state(&self, port: u16) -> bool {
        self.port_overrides.contains_key(&port)
    }

    #[inline]
    fn hash_on_strategy_for_port(&self, port: u16) -> HashOnStrategy {
        self.port_overrides
            .get(&port)
            .map(|state| state.hash_on_strategy.clone())
            .unwrap_or_else(|| self.hash_on_strategy.clone())
    }

    /// Dispatch to the algorithm-specific selector using a pre-computed bitset.
    /// No heap allocation on any code path.
    fn select_with_bitset(
        &self,
        ctx_key: &str,
        healthy: &HealthBitset,
    ) -> Option<Arc<UpstreamTarget>> {
        self.select_with_bitset_using(
            ctx_key,
            healthy,
            self.algorithm,
            &self.rr_counter,
            &self.wrr_state,
            &self.hash_ring,
            self.locality_lb.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn select_with_bitset_using(
        &self,
        ctx_key: &str,
        healthy: &HealthBitset,
        algorithm: LoadBalancerAlgorithm,
        rr_counter: &AtomicU64,
        wrr_state: &WrrLaneState,
        hash_ring: &[(u64, usize)],
        locality_lb: Option<&LocalityLbState>,
    ) -> Option<Arc<UpstreamTarget>> {
        if healthy.is_empty() {
            return None;
        }
        let distributed;
        let healthy = if let Some(mask) =
            self.distribute_group_bitset(healthy, ctx_key, algorithm, locality_lb)
        {
            distributed = mask;
            &distributed
        } else {
            healthy
        };
        let all = healthy.is_all(self.targets.len());
        match algorithm {
            // `Passthrough` reaches the balancer only as the fallback after the
            // request path's orig-dst match missed; behave as round-robin.
            LoadBalancerAlgorithm::RoundRobin | LoadBalancerAlgorithm::Passthrough => {
                let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                let target_idx = if all {
                    idx % self.targets.len()
                } else {
                    healthy.nth_set_bit(idx)
                };
                Some(Arc::clone(&self.targets[target_idx]))
            }
            LoadBalancerAlgorithm::Random => {
                let idx = rr_counter.fetch_add(1, Ordering::Relaxed);
                let hash = golden_ratio_hash(idx) as usize;
                let target_idx = if all {
                    hash % self.targets.len()
                } else {
                    healthy.nth_set_bit(hash)
                };
                Some(Arc::clone(&self.targets[target_idx]))
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr_bitset(healthy, wrr_state),
            LoadBalancerAlgorithm::LeastConnections => {
                self.select_least_connections_bitset(healthy)
            }
            LoadBalancerAlgorithm::LeastLatency => {
                self.select_least_latency_bitset(healthy, rr_counter)
            }
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash_bitset_with_ring(ctx_key, healthy, hash_ring)
            }
        }
    }

    /// Vec-based fallback for select() when targets.len() > MAX_BITSET_TARGETS.
    fn select_vec_fallback(
        &self,
        ctx_key: &str,
        health: Option<&HealthContext<'_>>,
    ) -> Option<TargetSelection> {
        let scope_indices: Vec<usize> = (0..self.targets.len()).collect();
        let healthy = self.healthy_targets_vec(health);
        if healthy.is_empty() {
            let all: Vec<(usize, &Arc<UpstreamTarget>)> = self.targets.iter().enumerate().collect();
            let (all, _) =
                self.preferred_locality_candidates(all, &scope_indices, self.locality_lb.as_ref());
            return self
                .select_from_candidates_vec(ctx_key, &all)
                .map(|target| TargetSelection {
                    target,
                    is_fallback: true,
                });
        }
        let (healthy, degraded) =
            self.preferred_locality_candidates(healthy, &scope_indices, self.locality_lb.as_ref());
        self.select_from_candidates_vec(ctx_key, &healthy)
            .map(|target| TargetSelection {
                target,
                is_fallback: degraded,
            })
    }

    /// Vec-based algorithm dispatch (fallback for >128 targets).
    fn select_from_candidates_vec(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        self.select_from_candidates_vec_using(
            ctx_key,
            candidates,
            self.algorithm,
            &self.rr_counter,
            &self.wrr_state,
            &self.hash_ring,
            self.locality_lb.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn select_from_candidates_vec_using(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        algorithm: LoadBalancerAlgorithm,
        rr_counter: &AtomicU64,
        wrr_state: &WrrLaneState,
        hash_ring: &[(u64, usize)],
        locality_lb: Option<&LocalityLbState>,
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }
        let distributed;
        let candidates = if let Some(masked) =
            self.distribute_group_candidates(candidates, ctx_key, algorithm, locality_lb)
        {
            distributed = masked;
            distributed.as_slice()
        } else {
            candidates
        };
        match algorithm {
            // `Passthrough` reaches the balancer only as the round-robin
            // fallback after the request path's orig-dst match missed.
            LoadBalancerAlgorithm::RoundRobin | LoadBalancerAlgorithm::Passthrough => {
                let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                Some(Arc::clone(candidates[idx % candidates.len()].1))
            }
            LoadBalancerAlgorithm::Random => {
                let idx = rr_counter.fetch_add(1, Ordering::Relaxed);
                let hash = golden_ratio_hash(idx) as usize;
                Some(Arc::clone(candidates[hash % candidates.len()].1))
            }
            LoadBalancerAlgorithm::WeightedRoundRobin => self.select_wrr_vec(candidates, wrr_state),
            LoadBalancerAlgorithm::LeastConnections => {
                self.select_least_connections_vec(candidates)
            }
            LoadBalancerAlgorithm::LeastLatency => {
                self.select_least_latency_vec(candidates, rr_counter)
            }
            LoadBalancerAlgorithm::ConsistentHashing => {
                self.select_consistent_hash_vec_with_ring(ctx_key, candidates, hash_ring)
            }
        }
    }

    /// PASSTHROUGH selection: dial the target whose canonical `(IP, port)`
    /// equals the captured original destination, bypassing load balancing
    /// (Istio `loadBalancer.simple=PASSTHROUGH`).
    ///
    /// `port` / `subset_name` scope the candidate pool exactly like the
    /// `select*` family (subset∩port-aware): a passthrough target must be a
    /// member of the same pool a load-balanced selection would have drawn from,
    /// so passthrough composes with subset/port-override routing instead of
    /// reaching past it.
    ///
    /// Returns `Some(target)` only when the orig-dst matches a pool target AND
    /// that target is currently healthy (active + passive). On no match or an
    /// unhealthy match it returns `None`, signalling the caller to fall back to
    /// round-robin — an ejected orig-dst target must not be dialed. The passive
    /// `max_ejection_percent` cap is sized against the SAME candidate pool the
    /// match is scoped to (subset / port / subset∩port), so ejections outside
    /// the pool cannot dilute the cap and readmit/keep-ejected the matched
    /// target against the outlier policy.
    ///
    /// Hot-path clean: a single match scan over the (already small) target set,
    /// no per-request allocation. The orig-dst IP is canonicalized the SAME way
    /// the mesh VIP / by-workload routing keys are (`IpAddr::to_canonical`), so
    /// an IPv4-mapped-IPv6 capture matches an IPv4 target host and vice-versa.
    pub fn select_passthrough(
        &self,
        orig_dst: std::net::SocketAddr,
        port: Option<u16>,
        subset_name: Option<&str>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        if self.targets.is_empty() {
            return None;
        }
        let want_ip = orig_dst.ip().to_canonical();
        let want_port = orig_dst.port();

        // Restrict the candidate pool to the subset∩port the caller would have
        // load-balanced over, so passthrough never escapes subset/port scoping.
        let port_indices = port
            .and_then(|p| self.port_overrides.get(&p))
            .map(|ps| ps.target_indices.as_slice());
        let subset_indices = subset_name.and_then(|name| {
            self.subset_indices
                .get(name)
                .filter(|indices| !indices.is_empty())
                .map(Vec::as_slice)
        });
        // A named-but-unknown/empty subset has no candidate pool at all.
        if subset_name.is_some() && subset_indices.is_none() {
            return None;
        }

        let in_pool = |idx: usize| -> bool {
            port_indices.is_none_or(|p| p.contains(&idx))
                && subset_indices.is_none_or(|s| s.contains(&idx))
        };

        let matched_idx = self.targets.iter().enumerate().find_map(|(idx, t)| {
            if !in_pool(idx) {
                return None;
            }
            if t.port != want_port {
                return None;
            }
            // Targets carry host strings; only an IP-literal host can be an
            // original-destination match (mesh capture dials concrete IPs).
            let host_ip = t.host.parse::<std::net::IpAddr>().ok()?.to_canonical();
            (host_ip == want_ip).then_some(idx)
        })?;

        // Respect active + passive health: never dial an ejected orig-dst
        // target. Compute health over the SAME candidate pool the load-balanced
        // path would select from (subset / port / subset∩port), so the passive
        // `max_ejection_percent` cap is sized against THAT pool — mirroring
        // `select_from_subset` / `select_for_port` / `select_for_port_from_subset`.
        // Scoping the match to the pool but the cap to the whole upstream would
        // let ejections OUTSIDE the pool dilute the cap and wrongly readmit (or
        // keep ejected) the matched orig-dst target, contrary to the outlier
        // policy. The Vec path covers the rare >128-target pool the bitset
        // can't represent.
        let matched_healthy = if self.targets.len() > MAX_BITSET_TARGETS {
            // >128 targets: cap against the candidate-pool index set.
            match (subset_indices, port_indices) {
                (Some(s), Some(p)) => {
                    let intersection = self.subset_port_intersection_vec(s, p);
                    self.healthy_targets_vec_for_indices(health, &intersection)
                        .iter()
                        .any(|(idx, _)| *idx == matched_idx)
                }
                (Some(indices), None) | (None, Some(indices)) => self
                    .healthy_targets_vec_for_indices(health, indices)
                    .iter()
                    .any(|(idx, _)| *idx == matched_idx),
                (None, None) => self
                    .healthy_targets_vec(health)
                    .iter()
                    .any(|(idx, _)| *idx == matched_idx),
            }
        } else {
            // ≤128 targets: cap against the candidate-pool bitset/mask
            // (alloc-free stack `u128`s, no per-request `Vec`).
            match (subset_indices, port_indices) {
                (Some(s), Some(p)) => {
                    let intersection = self.subset_port_mask(s, p);
                    self.compute_health_bitset_for_mask(health, &intersection)
                        .contains(matched_idx)
                }
                (Some(indices), None) | (None, Some(indices)) => self
                    .compute_health_bitset_for_indices(health, indices)
                    .contains(matched_idx),
                (None, None) => self.compute_health_bitset(health).contains(matched_idx),
            }
        };
        if !matched_healthy {
            return None;
        }

        Some(Arc::clone(&self.targets[matched_idx]))
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
            .position(|t| retry_exclude_target_matches(t, exclude));

        // For >128 targets, fall back to Vec-based path.
        if n > MAX_BITSET_TARGETS {
            return self.select_excluding_vec_fallback(ctx_key, exclude_idx, health);
        }

        // Drop the excluded (previously tried) target from the candidate mask
        // BEFORE sizing the passive ejection cap. Otherwise a readmission
        // budget can be spent on the excluded target, and clearing it afterward
        // leaves viable retry candidates ejected.
        let scope = HealthBitset::all(n);
        let mut candidate_mask = scope;
        if let Some(ei) = exclude_idx {
            candidate_mask.clear(ei);
        }
        if candidate_mask.is_empty() {
            return None;
        }
        let healthy = self.compute_health_bitset_for_mask(health, &candidate_mask);

        // Strict locality must decide local presence from the unexcluded lane:
        // excluding a previously tried local target for retry must not make a
        // local-containing upstream look remote-only and widen to remote.
        if healthy.is_empty() {
            return None;
        }

        let (healthy, _) =
            self.preferred_locality_bitset(&healthy, &scope, self.locality_lb.as_ref());
        self.select_with_bitset(ctx_key, &healthy)
    }

    pub fn select_excluding_for_port(
        &self,
        ctx_key: &str,
        port: u16,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let Some(port_state) = self.port_overrides.get(&port) else {
            return self.select_excluding(ctx_key, exclude, health);
        };
        let n = self.targets.len();
        if n == 0 || port_state.target_indices.is_empty() {
            return None;
        }

        let exclude_idx = self
            .targets
            .iter()
            .position(|t| retry_exclude_target_matches(t, exclude));

        if n > MAX_BITSET_TARGETS {
            return self.select_excluding_port_vec_fallback(
                ctx_key,
                port_state,
                exclude_idx,
                health,
            );
        }

        let scope = bitset_for_indices(&port_state.target_indices);
        let mut candidate_mask = scope;
        if let Some(ei) = exclude_idx {
            candidate_mask.clear(ei);
        }
        if candidate_mask.is_empty() {
            return None;
        }
        let healthy = self.compute_health_bitset_for_mask(health, &candidate_mask);

        // Strict locality must decide local presence from the unexcluded port
        // lane; retry exclusion only applies to selectable candidates.
        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        if healthy.is_empty() {
            return None;
        }

        let (healthy, _) = self.preferred_locality_bitset(&healthy, &scope, port_locality);
        self.select_with_bitset_using(
            ctx_key,
            &healthy,
            port_state.algorithm,
            &port_state.rr_counter,
            &port_state.wrr_state,
            &port_state.hash_ring,
            port_locality,
        )
    }

    pub fn select_excluding_from_subset(
        &self,
        ctx_key: &str,
        subset_name: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let n = self.targets.len();
        if n == 0 {
            return None;
        }
        let subset_target_indices = match self.subset_indices.get(subset_name) {
            Some(indices) if !indices.is_empty() => indices,
            Some(_) => return None,
            None => return None,
        };

        let exclude_idx = self
            .targets
            .iter()
            .position(|t| retry_exclude_target_matches(t, exclude));

        if n > MAX_BITSET_TARGETS {
            return self.select_excluding_subset_vec_fallback(
                ctx_key,
                subset_name,
                subset_target_indices,
                exclude_idx,
                health,
            );
        }

        // Drop the excluded (previously tried) target from the candidate mask
        // BEFORE sizing the ejection cap, so the cap's denominator and
        // readmission budget evaluate over the actual retry candidates. If the
        // excluded target were the earliest-ejected one, capping first would
        // spend the readmission on it and then clearing it would leave the
        // remaining candidate ejected — wrongly returning None. Building the
        // mask is an alloc-free stack `u128` (no per-request `Vec`).
        let strict_scope = bitset_for_indices(subset_target_indices);
        let mut candidate_mask = strict_scope;
        if let Some(ei) = exclude_idx {
            candidate_mask.clear(ei);
        }
        if candidate_mask.is_empty() {
            return None;
        }
        let subset_healthy = self.compute_health_bitset_for_mask(health, &candidate_mask);

        if subset_healthy.is_empty() {
            return None;
        }

        let (subset_healthy, _) = self.preferred_locality_bitset(
            &subset_healthy,
            &strict_scope,
            self.locality_lb.as_ref(),
        );
        self.select_with_bitset_using(
            ctx_key,
            &subset_healthy,
            self.subset_algorithm(subset_name),
            &self.rr_counter,
            self.subset_wrr_state(subset_name),
            self.subset_hash_ring(subset_name),
            self.locality_lb.as_ref(),
        )
    }

    pub fn select_excluding_for_port_from_subset(
        &self,
        ctx_key: &str,
        port: u16,
        subset_name: &str,
        exclude: &UpstreamTarget,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        let Some(port_state) = self.port_overrides.get(&port) else {
            return self.select_excluding_from_subset(ctx_key, subset_name, exclude, health);
        };
        let n = self.targets.len();
        if n == 0 || port_state.target_indices.is_empty() {
            return None;
        }
        let subset_target_indices = match self.subset_indices.get(subset_name) {
            Some(indices) if !indices.is_empty() => indices,
            Some(_) => return None,
            None => return None,
        };

        let exclude_idx = self
            .targets
            .iter()
            .position(|t| retry_exclude_target_matches(t, exclude));

        if n > MAX_BITSET_TARGETS {
            return self.select_excluding_port_subset_vec_fallback(
                ctx_key,
                port_state,
                subset_name,
                subset_target_indices,
                exclude_idx,
                health,
            );
        }

        // Build the subset∩port candidate mask alloc-free (stack `u128`) and
        // drop the excluded (previously tried) target from it BEFORE sizing the
        // ejection cap, so the cap's denominator and readmission budget evaluate
        // over the actual retry candidates rather than spending the budget on
        // the excluded target (see `select_excluding_from_subset`).
        let strict_scope = self.subset_port_mask(subset_target_indices, &port_state.target_indices);
        let mut candidate_mask = strict_scope;
        if let Some(ei) = exclude_idx {
            candidate_mask.clear(ei);
        }
        if candidate_mask.is_empty() {
            return None;
        }
        let port_subset_healthy = self.compute_health_bitset_for_mask(health, &candidate_mask);

        if port_subset_healthy.is_empty() {
            return None;
        }

        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        let (port_subset_healthy, _) =
            self.preferred_locality_bitset(&port_subset_healthy, &strict_scope, port_locality);
        self.select_with_bitset_using(
            ctx_key,
            &port_subset_healthy,
            self.port_subset_algorithm(port_state, subset_name),
            self.port_subset_rr_counter(port_state),
            self.port_subset_wrr_state(port_state, subset_name),
            self.port_subset_hash_ring(port_state, subset_name),
            port_locality,
        )
    }

    /// Vec-based fallback for select_excluding() when targets.len() > MAX_BITSET_TARGETS.
    fn select_excluding_vec_fallback(
        &self,
        ctx_key: &str,
        exclude_idx: Option<usize>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        // Strict locality uses the unexcluded lane for local-presence decisions;
        // retry exclusion only applies to selectable candidates.
        let scope_indices: Vec<usize> = (0..self.targets.len()).collect();
        let candidate_indices: Vec<usize> = match exclude_idx {
            Some(ei) => scope_indices
                .iter()
                .copied()
                .filter(|&idx| idx != ei)
                .collect(),
            None => scope_indices.clone(),
        };
        if candidate_indices.is_empty() {
            return None;
        }
        let healthy = self.healthy_targets_vec_for_indices(health, &candidate_indices);
        if healthy.is_empty() {
            return None;
        }

        let (healthy, _) =
            self.preferred_locality_candidates(healthy, &scope_indices, self.locality_lb.as_ref());
        self.select_from_candidates_vec(ctx_key, &healthy)
    }

    fn select_excluding_port_vec_fallback(
        &self,
        ctx_key: &str,
        port_state: &PortLbState,
        exclude_idx: Option<usize>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        // Strict locality uses the unexcluded port lane for local-presence
        // decisions; retry exclusion only applies to selectable candidates.
        let scope_indices: Vec<usize> = port_state.target_indices.clone();
        let candidate_indices: Vec<usize> = match exclude_idx {
            Some(ei) => port_state
                .target_indices
                .iter()
                .copied()
                .filter(|&idx| idx != ei)
                .collect(),
            None => scope_indices.clone(),
        };
        if candidate_indices.is_empty() {
            return None;
        }
        let candidates = self.healthy_targets_vec_for_indices(health, &candidate_indices);
        if candidates.is_empty() {
            return None;
        }
        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        let (candidates, _) =
            self.preferred_locality_candidates(candidates, &scope_indices, port_locality);

        self.select_from_candidates_vec_using(
            ctx_key,
            &candidates,
            port_state.algorithm,
            &port_state.rr_counter,
            &port_state.wrr_state,
            &port_state.hash_ring,
            port_locality,
        )
    }

    fn select_excluding_port_subset_vec_fallback(
        &self,
        ctx_key: &str,
        port_state: &PortLbState,
        subset_name: &str,
        subset_indices: &[usize],
        exclude_idx: Option<usize>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        // Build subset∩port, then drop the excluded (previously tried) target
        // from the candidate list BEFORE sizing the ejection cap (mirrors the
        // bitset path), so the cap's denominator/budget evaluate over the actual
        // retry candidates rather than spending the readmission on the excluded
        // target. A `Vec` here is acceptable — this is the >128-target fallback.
        let strict_scope =
            self.subset_port_intersection_vec(subset_indices, &port_state.target_indices);
        let mut intersection = strict_scope.clone();
        if let Some(ei) = exclude_idx {
            intersection.retain(|&idx| idx != ei);
        }
        if intersection.is_empty() {
            return None;
        }
        let candidates = self.healthy_targets_vec_for_indices(health, &intersection);
        if candidates.is_empty() {
            return None;
        }
        let port_locality = port_state
            .locality_lb
            .as_ref()
            .or(self.locality_lb.as_ref());
        let (candidates, _) =
            self.preferred_locality_candidates(candidates, &strict_scope, port_locality);

        self.select_from_candidates_vec_using(
            ctx_key,
            &candidates,
            self.port_subset_algorithm(port_state, subset_name),
            self.port_subset_rr_counter(port_state),
            self.port_subset_wrr_state(port_state, subset_name),
            self.port_subset_hash_ring(port_state, subset_name),
            port_locality,
        )
    }

    fn select_excluding_subset_vec_fallback(
        &self,
        ctx_key: &str,
        subset_name: &str,
        subset_indices: &[usize],
        exclude_idx: Option<usize>,
        health: Option<&HealthContext<'_>>,
    ) -> Option<Arc<UpstreamTarget>> {
        // Drop the excluded (previously tried) target from the subset candidate
        // list BEFORE sizing the ejection cap (mirrors the bitset path), so the
        // cap's denominator/budget evaluate over the actual retry candidates
        // rather than spending the readmission on the excluded target. A `Vec`
        // here is acceptable — this is the >128-target fallback.
        let strict_scope = subset_indices.to_vec();
        let candidate_indices: Vec<usize> = match exclude_idx {
            Some(ei) => subset_indices
                .iter()
                .copied()
                .filter(|&idx| idx != ei)
                .collect(),
            None => strict_scope.clone(),
        };
        if candidate_indices.is_empty() {
            return None;
        }
        let subset_healthy = self.healthy_targets_vec_for_indices(health, &candidate_indices);

        if subset_healthy.is_empty() {
            return None;
        }
        let (subset_healthy, _) = self.preferred_locality_candidates(
            subset_healthy,
            &strict_scope,
            self.locality_lb.as_ref(),
        );

        self.select_from_candidates_vec_using(
            ctx_key,
            &subset_healthy,
            self.subset_algorithm(subset_name),
            &self.rr_counter,
            self.subset_wrr_state(subset_name),
            self.subset_hash_ring(subset_name),
            self.locality_lb.as_ref(),
        )
    }

    // ─── Bitset-based algorithm implementations (zero-alloc hot path) ────────

    /// Smooth weighted round-robin (NGINX algorithm) using bitset.
    ///
    /// Steady-state path is wait-free: hit a precomputed order for the current
    /// healthy fingerprint in the bounded slot cache and advance a sharded
    /// atomic counter. Schedule rebuild runs only on rate-sampled / cold-fill
    /// fingerprint misses — see [`WrrLaneState`].
    fn select_wrr_bitset(
        &self,
        healthy: &HealthBitset,
        wrr_state: &WrrLaneState,
    ) -> Option<Arc<UpstreamTarget>> {
        if !wrr_state.is_active() || healthy.is_empty() {
            return None;
        }

        let fingerprint = healthy.bits;
        if let Some(schedule) = wrr_state.hit_bitset_schedule(fingerprint)
            && let Some(target) = self.pick_wrr_bitset_schedule(healthy, &schedule)
        {
            return Some(target);
        }

        self.rebuild_wrr_schedule_bitset(healthy, wrr_state, fingerprint)
    }

    fn pick_wrr_bitset_schedule(
        &self,
        healthy: &HealthBitset,
        schedule: &WrrSchedule,
    ) -> Option<Arc<UpstreamTarget>> {
        if schedule.zero_weight {
            let ticket = schedule.counters[wrr_counter_shard()].fetch_add(1, Ordering::Relaxed);
            let target_idx = healthy.nth_set_bit(ticket as usize);
            return Some(Arc::clone(&self.targets[target_idx]));
        }
        if schedule.is_lottery_only() {
            let ticket = schedule.counters[wrr_counter_shard()].fetch_add(1, Ordering::Relaxed);
            return self.pick_wrr_lottery_bitset(healthy, ticket);
        }
        Self::pick_from_wrr_schedule(schedule, |idx| {
            healthy
                .contains(idx)
                .then(|| Arc::clone(&self.targets[idx]))
        })
    }

    /// Allocation-free weighted lottery / all-zero RR over a bitset healthy set.
    ///
    /// Shared by the miss path and by lottery-only schedule hits (work-budget
    /// sentinel). `ticket` is the selection entropy (miss counter or shard).
    fn pick_wrr_lottery_bitset(
        &self,
        healthy: &HealthBitset,
        ticket: u64,
    ) -> Option<Arc<UpstreamTarget>> {
        let healthy_count = healthy.count();
        if healthy_count == 0 {
            return None;
        }

        let mut total_weight = 0u64;
        healthy.for_each_set_bit(|idx| {
            total_weight = total_weight.saturating_add(u64::from(self.targets[idx].weight));
        });

        if total_weight == 0 {
            let target_idx = healthy.nth_set_bit((ticket % healthy_count as u64) as usize);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        let mut cursor = golden_ratio_hash(ticket) % total_weight;
        let mut chosen = None;
        healthy.for_each_set_bit(|idx| {
            if chosen.is_some() {
                return;
            }
            let weight = u64::from(self.targets[idx].weight);
            if weight == 0 {
                return;
            }
            if cursor < weight {
                chosen = Some(idx);
            } else {
                cursor = cursor.saturating_sub(weight);
            }
        });
        chosen.map(|idx| Arc::clone(&self.targets[idx]))
    }

    /// Allocation-free miss path: O(healthy) scan, no smooth-schedule build.
    ///
    /// Positive-weight targets use a weighted lottery over current weights;
    /// all-zero sets keep the historical round-robin fallback. This is the
    /// contention / churn tradeoff vs exact smooth-WRR interleaving.
    fn pick_wrr_miss_fallback_bitset(
        &self,
        healthy: &HealthBitset,
        wrr_state: &WrrLaneState,
    ) -> Option<Arc<UpstreamTarget>> {
        let ticket = wrr_state.next_miss_fallback();
        self.pick_wrr_lottery_bitset(healthy, ticket)
    }

    fn build_wrr_schedule_bitset(
        &self,
        healthy: &HealthBitset,
        wrr_state: &WrrLaneState,
        fingerprint: u128,
    ) -> Arc<WrrSchedule> {
        let mut weighted = Vec::with_capacity(healthy.count());
        healthy.for_each_set_bit(|idx| {
            weighted.push((idx, self.targets[idx].weight));
        });
        let seed = wrr_state.next_schedule_seed();
        let key = WrrScheduleKey::Bitset(fingerprint);
        match build_smooth_wrr_order(&weighted) {
            WrrOrderBuild::Smooth(order) => {
                Arc::new(WrrSchedule::with_seed(key, order, false, seed, 0))
            }
            WrrOrderBuild::ZeroWeight => Arc::new(WrrSchedule::with_seed(
                key,
                Box::new([]),
                true,
                seed,
                healthy.count(),
            )),
            WrrOrderBuild::LotteryOnly => {
                // Exact-key sentinel: subsequent hits skip the quadratic build.
                Arc::new(WrrSchedule::with_seed(key, Box::new([]), false, seed, 0))
            }
        }
    }

    fn rebuild_wrr_schedule_bitset(
        &self,
        healthy: &HealthBitset,
        wrr_state: &WrrLaneState,
        fingerprint: u128,
    ) -> Option<Arc<UpstreamTarget>> {
        // Contention-bounded: try_lock only. Contending / unsampled misses never
        // build an ephemeral schedule — they use the allocation-free scan.
        if let Ok(_guard) = wrr_state.rebuild.try_lock() {
            if let Some(schedule) = wrr_state.lookup_bitset_schedule(fingerprint) {
                return self.pick_wrr_bitset_schedule(healthy, &schedule);
            }
            if wrr_state.should_publish_on_miss() {
                let new_schedule = self.build_wrr_schedule_bitset(healthy, wrr_state, fingerprint);
                wrr_state.publish_schedule(Arc::clone(&new_schedule));
                return self.pick_wrr_bitset_schedule(healthy, &new_schedule);
            }
        } else if let Some(schedule) = wrr_state.lookup_bitset_schedule(fingerprint) {
            return self.pick_wrr_bitset_schedule(healthy, &schedule);
        }

        self.pick_wrr_miss_fallback_bitset(healthy, wrr_state)
    }

    #[inline]
    fn pick_from_wrr_schedule(
        schedule: &WrrSchedule,
        resolve: impl Fn(usize) -> Option<Arc<UpstreamTarget>>,
    ) -> Option<Arc<UpstreamTarget>> {
        if schedule.order.is_empty() {
            return None;
        }
        let ticket = schedule.counters[wrr_counter_shard()].fetch_add(1, Ordering::Relaxed);
        let idx = schedule.order[(ticket % schedule.order.len() as u64) as usize];
        resolve(idx)
    }

    /// Smooth weighted round-robin (NGINX algorithm) — Vec fallback for >128
    /// targets. Same wait-free multi-fingerprint schedule + sharded per-schedule
    /// atomic counter model as the bitset path; cache identity compares the
    /// healthy original indices exactly.
    fn select_wrr_vec(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        wrr_state: &WrrLaneState,
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() || !wrr_state.is_active() {
            return None;
        }

        if let Some(schedule) = wrr_state.hit_vec_schedule(candidates)
            && let Some(target) = Self::pick_wrr_vec_schedule(candidates, &schedule)
        {
            return Some(target);
        }

        self.rebuild_wrr_schedule_vec(candidates, wrr_state)
    }

    fn pick_wrr_vec_schedule(
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        schedule: &WrrSchedule,
    ) -> Option<Arc<UpstreamTarget>> {
        if schedule.zero_weight {
            let ticket = schedule.counters[wrr_counter_shard()].fetch_add(1, Ordering::Relaxed);
            return Some(Arc::clone(candidates[ticket as usize % candidates.len()].1));
        }
        if schedule.is_lottery_only() {
            let ticket = schedule.counters[wrr_counter_shard()].fetch_add(1, Ordering::Relaxed);
            return Self::pick_wrr_lottery_vec(candidates, ticket);
        }
        Self::pick_from_wrr_schedule(schedule, |orig_idx| {
            resolve_wrr_vec_candidate(candidates, orig_idx).map(Arc::clone)
        })
    }

    /// Allocation-free weighted lottery / all-zero RR over a Vec candidate slice.
    fn pick_wrr_lottery_vec(
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        ticket: u64,
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }

        let mut total_weight = 0u64;
        for (_, target) in candidates {
            total_weight = total_weight.saturating_add(u64::from(target.weight));
        }

        if total_weight == 0 {
            return Some(Arc::clone(
                candidates[(ticket as usize) % candidates.len()].1,
            ));
        }

        let mut cursor = golden_ratio_hash(ticket) % total_weight;
        for (_, target) in candidates {
            let weight = u64::from(target.weight);
            if weight == 0 {
                continue;
            }
            if cursor < weight {
                return Some(Arc::clone(target));
            }
            cursor = cursor.saturating_sub(weight);
        }
        None
    }

    /// Allocation-free Vec miss path — same lottery / all-zero RR contract as
    /// the bitset fallback, scanning only the current candidate slice.
    fn pick_wrr_miss_fallback_vec(
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        wrr_state: &WrrLaneState,
    ) -> Option<Arc<UpstreamTarget>> {
        let ticket = wrr_state.next_miss_fallback();
        Self::pick_wrr_lottery_vec(candidates, ticket)
    }

    fn build_wrr_schedule_vec(
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        wrr_state: &WrrLaneState,
    ) -> Arc<WrrSchedule> {
        let weighted: Vec<(usize, u32)> = candidates
            .iter()
            .map(|&(idx, target)| (idx, target.weight))
            .collect();
        let seed = wrr_state.next_schedule_seed();
        let key = WrrScheduleKey::Indices(
            candidates
                .iter()
                .map(|(idx, _)| *idx)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        match build_smooth_wrr_order(&weighted) {
            WrrOrderBuild::Smooth(order) => {
                Arc::new(WrrSchedule::with_seed(key, order, false, seed, 0))
            }
            WrrOrderBuild::ZeroWeight => Arc::new(WrrSchedule::with_seed(
                key,
                Box::new([]),
                true,
                seed,
                candidates.len(),
            )),
            WrrOrderBuild::LotteryOnly => {
                Arc::new(WrrSchedule::with_seed(key, Box::new([]), false, seed, 0))
            }
        }
    }

    fn rebuild_wrr_schedule_vec(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        wrr_state: &WrrLaneState,
    ) -> Option<Arc<UpstreamTarget>> {
        if let Ok(_guard) = wrr_state.rebuild.try_lock() {
            if let Some(schedule) = wrr_state.lookup_vec_schedule(candidates) {
                return Self::pick_wrr_vec_schedule(candidates, &schedule);
            }
            if wrr_state.should_publish_on_miss() {
                let new_schedule = Self::build_wrr_schedule_vec(candidates, wrr_state);
                wrr_state.publish_schedule(Arc::clone(&new_schedule));
                return Self::pick_wrr_vec_schedule(candidates, &new_schedule);
            }
        } else if let Some(schedule) = wrr_state.lookup_vec_schedule(candidates) {
            return Self::pick_wrr_vec_schedule(candidates, &schedule);
        }

        Self::pick_wrr_miss_fallback_vec(candidates, wrr_state)
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
    fn select_least_latency_bitset(
        &self,
        healthy: &HealthBitset,
        rr_counter: &AtomicU64,
    ) -> Option<Arc<UpstreamTarget>> {
        let hcount = healthy.count();
        if hcount == 0 {
            return None;
        }

        let mut warmed_count = 0usize;
        let mut any_has_data = false;
        let mut unwarmed_count = 0usize;

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
            } else {
                unwarmed_count += 1;
            }
            if samples > 0 {
                any_has_data = true;
            }
        }

        // Initial warm-up: round-robin so all targets get baseline measurements.
        if warmed_count == 0 || !any_has_data {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let target_idx = healthy.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        let all_warmed_up = unwarmed_count == 0;

        // Mixed warm-up: bound exploration of sub-threshold targets so a
        // never-sampled / persistently failing peer cannot pin all traffic.
        // Explore with a fixed permille of selections via RR among unwarmed;
        // otherwise pick the best warmed EWMA.
        if !all_warmed_up {
            let ticket = rr_counter.fetch_add(1, Ordering::Relaxed);
            if let Some(mut skip) = unwarmed_explore_slot(ticket, unwarmed_count) {
                // Round-robin among unwarmed healthy targets only.
                for i in 0..self.targets.len() {
                    if !healthy.contains(i) {
                        continue;
                    }
                    let samples = self
                        .latency_sample_count
                        .get(&self.host_port_keys[i])
                        .map(|v| v.load(Ordering::Relaxed))
                        .unwrap_or(0);
                    if samples >= LATENCY_WARMUP_THRESHOLD {
                        continue;
                    }
                    if skip == 0 {
                        return Some(Arc::clone(&self.targets[i]));
                    }
                    skip -= 1;
                }
                // Fall through to warmed selection if unwarmed set raced empty.
            }

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
                if samples < LATENCY_WARMUP_THRESHOLD {
                    continue;
                }
                let latency = self
                    .latency_ewma
                    .get(key)
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(LATENCY_UNSET);
                if !found || latency < best_latency {
                    best_latency = latency;
                    best_idx = i;
                    found = true;
                }
            }
            if found && best_latency != LATENCY_UNSET {
                return Some(Arc::clone(&self.targets[best_idx]));
            }
            // No usable warmed EWMA — fall back to RR across healthy set.
            let idx = ticket as usize;
            let target_idx = healthy.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        // Steady-state: all healthy candidates are warmed — pick lowest EWMA.
        let mut best_latency = u64::MAX;
        let mut best_idx = 0;
        let mut found = false;

        for i in 0..self.targets.len() {
            if !healthy.contains(i) {
                continue;
            }
            let key = &self.host_port_keys[i];
            let latency = self
                .latency_ewma
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(LATENCY_UNSET);
            if !found || latency < best_latency {
                best_latency = latency;
                best_idx = i;
                found = true;
            }
        }

        if best_latency == LATENCY_UNSET {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            let target_idx = healthy.nth_set_bit(idx);
            return Some(Arc::clone(&self.targets[target_idx]));
        }

        Some(Arc::clone(&self.targets[best_idx]))
    }

    /// Consistent hash: find the target on the ring closest to the hash of
    /// `ctx_key`. Uses the bitset for O(1) candidate membership check per
    /// ring position instead of O(candidates) linear scan.
    #[cfg(test)]
    fn select_consistent_hash_bitset(
        &self,
        ctx_key: &str,
        healthy: &HealthBitset,
    ) -> Option<Arc<UpstreamTarget>> {
        self.select_consistent_hash_bitset_with_ring(ctx_key, healthy, &self.hash_ring)
    }

    fn select_consistent_hash_bitset_with_ring(
        &self,
        ctx_key: &str,
        healthy: &HealthBitset,
        hash_ring: &[(u64, usize)],
    ) -> Option<Arc<UpstreamTarget>> {
        if healthy.is_empty() || hash_ring.is_empty() {
            return None;
        }

        let hash = fx_hash_str(ctx_key);

        // Binary search on the ring
        let pos = match hash_ring.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(p) => p,
            Err(p) => p % hash_ring.len(),
        };

        // Walk the ring from pos — O(1) bitset check per position.
        for i in 0..hash_ring.len() {
            let ring_idx = (pos + i) % hash_ring.len();
            let target_idx = hash_ring[ring_idx].1;
            if healthy.contains(target_idx) {
                return Some(Arc::clone(&self.targets[target_idx]));
            }
        }

        // Fallback: first healthy target
        let target_idx = healthy.nth_set_bit(0);
        Some(Arc::clone(&self.targets[target_idx]))
    }

    // ─── Vec-based algorithm implementations (fallback for >128 targets) ─────

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
    /// **Late joiners / recovery**: Sub-threshold targets receive a bounded
    /// fraction of selections (see `LATENCY_WARMUP_EXPLORE_PERMILLE`) via
    /// round-robin among unwarmed peers — never an unconditional preference
    /// over warmed targets. Failed attempts count toward the warm-up threshold
    /// with a penalty EWMA sample.
    ///
    /// **Steady-state**: Selects the candidate with the lowest EWMA value.
    ///
    /// **No data**: Falls back to round-robin.
    fn select_least_latency_vec(
        &self,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        rr_counter: &AtomicU64,
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() {
            return None;
        }

        let mut warmed_count = 0usize;
        let mut any_has_data = false;
        let mut unwarmed_count = 0usize;
        for (idx, _) in candidates {
            let key = &self.host_port_keys[*idx];
            let samples = self
                .latency_sample_count
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(0);
            if samples >= LATENCY_WARMUP_THRESHOLD {
                warmed_count += 1;
            } else {
                unwarmed_count += 1;
            }
            if samples > 0 {
                any_has_data = true;
            }
        }

        if warmed_count == 0 || !any_has_data {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(Arc::clone(candidates[idx % candidates.len()].1));
        }

        let all_warmed_up = unwarmed_count == 0;

        if !all_warmed_up {
            let ticket = rr_counter.fetch_add(1, Ordering::Relaxed);
            if let Some(mut skip) = unwarmed_explore_slot(ticket, unwarmed_count) {
                for candidate in candidates {
                    let samples = self
                        .latency_sample_count
                        .get(&self.host_port_keys[candidate.0])
                        .map(|v| v.load(Ordering::Relaxed))
                        .unwrap_or(0);
                    if samples >= LATENCY_WARMUP_THRESHOLD {
                        continue;
                    }
                    if skip == 0 {
                        return Some(Arc::clone(candidate.1));
                    }
                    skip -= 1;
                }
            }

            let mut best_latency = u64::MAX;
            let mut best = candidates[0];
            let mut found = false;
            for candidate in candidates {
                let key = &self.host_port_keys[candidate.0];
                let samples = self
                    .latency_sample_count
                    .get(key)
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(0);
                if samples < LATENCY_WARMUP_THRESHOLD {
                    continue;
                }
                let latency = self
                    .latency_ewma
                    .get(key)
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(LATENCY_UNSET);
                if !found || latency < best_latency {
                    best_latency = latency;
                    best = *candidate;
                    found = true;
                }
            }
            if found && best_latency != LATENCY_UNSET {
                return Some(Arc::clone(best.1));
            }
            let idx = ticket as usize;
            return Some(Arc::clone(candidates[idx % candidates.len()].1));
        }

        let mut best_latency = u64::MAX;
        let mut best = candidates[0];

        for candidate in candidates {
            let key = &self.host_port_keys[candidate.0];
            let latency = self
                .latency_ewma
                .get(key)
                .map(|v| v.load(Ordering::Relaxed))
                .unwrap_or(LATENCY_UNSET);
            if latency < best_latency {
                best_latency = latency;
                best = *candidate;
            }
        }

        if best_latency == LATENCY_UNSET {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
            return Some(Arc::clone(candidates[idx % candidates.len()].1));
        }

        Some(Arc::clone(best.1))
    }

    /// Consistent hash — Vec fallback. Uses bitset for O(1) candidate
    /// membership check instead of the previous O(candidates) linear scan.
    #[cfg(test)]
    fn select_consistent_hash_vec(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
    ) -> Option<Arc<UpstreamTarget>> {
        self.select_consistent_hash_vec_with_ring(ctx_key, candidates, &self.hash_ring)
    }

    fn select_consistent_hash_vec_with_ring(
        &self,
        ctx_key: &str,
        candidates: &[(usize, &Arc<UpstreamTarget>)],
        hash_ring: &[(u64, usize)],
    ) -> Option<Arc<UpstreamTarget>> {
        if candidates.is_empty() || hash_ring.is_empty() {
            return None;
        }

        let hash = fx_hash_str(ctx_key);

        // Build a membership set for O(1) candidate check during ring walk.
        // For the >128-target Vec fallback, use a HashSet.
        let candidate_set: std::collections::HashSet<usize> =
            candidates.iter().map(|(i, _)| *i).collect();

        let pos = match hash_ring.binary_search_by_key(&hash, |&(h, _)| h) {
            Ok(p) => p,
            Err(p) => p % hash_ring.len(),
        };

        for i in 0..hash_ring.len() {
            let ring_idx = (pos + i) % hash_ring.len();
            let target_idx = hash_ring[ring_idx].1;
            if candidate_set.contains(&target_idx) {
                return Some(Arc::clone(&self.targets[target_idx]));
            }
        }

        Some(Arc::clone(candidates[0].1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_smooth_wrr_order_matches_nginx_sequence() {
        // Classic NGINX smooth WRR for weights 5:1:2 over indices 0,1,2.
        match build_smooth_wrr_order(&[(0, 5), (1, 1), (2, 2)]) {
            WrrOrderBuild::Smooth(order) => {
                assert_eq!(&order[..], &[0, 2, 0, 0, 1, 0, 2, 0]);
            }
            other => panic!("ordinary weights must build exact smooth order, got {other:?}"),
        }
    }

    #[test]
    fn bounded_wrr_period_does_not_starve_extreme_low_weight_target() {
        // Two candidates × 8192 steps = 16384 work units ≪ budget → exact SWRR.
        match build_smooth_wrr_order(&[(7, 65_535), (9, 1)]) {
            WrrOrderBuild::Smooth(order) => {
                assert_eq!(order.len(), WRR_MAX_SCHEDULE_LEN);
                assert_eq!(order.iter().filter(|&&idx| idx == 7).count(), 8_191);
                assert_eq!(order.iter().filter(|&&idx| idx == 9).count(), 1);
            }
            other => panic!("two-target capped period must stay exact, got {other:?}"),
        }
    }

    #[test]
    fn oversized_smooth_wrr_build_returns_lottery_only_sentinel() {
        // 1000 positive candidates × 8192 capped steps exceeds
        // WRR_SMOOTH_BUILD_MAX_WORK (8192 × 128); construction must refuse the
        // quadratic loop so callers can publish a lottery-only key sentinel.
        let weighted: Vec<(usize, u32)> = (0..1_000)
            .map(|idx| (idx, if idx == 0 { 65_535 } else { 1 }))
            .collect();
        assert!(
            matches!(
                build_smooth_wrr_order(&weighted),
                WrrOrderBuild::LotteryOnly
            ),
            "pathological candidate×period work must be lottery-only"
        );
        // Work estimate uses checked mul; prove the threshold itself.
        let work = (WRR_MAX_SCHEDULE_LEN as u64).saturating_mul(1_000);
        assert!(work > WRR_SMOOTH_BUILD_MAX_WORK);
    }

    #[test]
    fn zero_weight_build_is_explicit() {
        assert!(matches!(
            build_smooth_wrr_order(&[(0, 0), (1, 0)]),
            WrrOrderBuild::ZeroWeight
        ));
    }

    #[test]
    fn zero_weight_shard_phases_are_offset_across_healthy_count() {
        let healthy_count = 32usize;
        let seed = 7u64;
        let schedule = WrrSchedule::with_seed(
            WrrScheduleKey::Bitset(0xabc),
            Box::new([]),
            true,
            seed,
            healthy_count,
        );
        let stride = (healthy_count / WRR_COUNTER_SHARDS).max(1) as u64;
        for (i, counter) in schedule.counters.iter().enumerate() {
            assert_eq!(
                counter.load(Ordering::Relaxed),
                seed.wrapping_add((i as u64).wrapping_mul(stride)),
                "shard {i} phase"
            );
        }
        // Distinct shards must not all share the same starting phase.
        let first = schedule.counters[0].load(Ordering::Relaxed);
        assert!(
            schedule
                .counters
                .iter()
                .any(|c| c.load(Ordering::Relaxed) != first),
            "zero-weight shards must be phase-distributed"
        );
    }

    #[test]
    fn resolve_wrr_vec_candidate_first_middle_last_and_absent() {
        let t0 = Arc::new(make_target("h0", 8080));
        let t1 = Arc::new(make_target("h1", 8080));
        let t2 = Arc::new(make_target("h2", 8080));
        // Ascending original indices with a gap (as after an exclusion).
        let candidates: Vec<(usize, &Arc<UpstreamTarget>)> = vec![(0, &t0), (5, &t1), (12, &t2)];

        assert!(Arc::ptr_eq(
            resolve_wrr_vec_candidate(&candidates, 0).expect("first"),
            &t0
        ));
        assert!(Arc::ptr_eq(
            resolve_wrr_vec_candidate(&candidates, 5).expect("middle"),
            &t1
        ));
        assert!(Arc::ptr_eq(
            resolve_wrr_vec_candidate(&candidates, 12).expect("last"),
            &t2
        ));
        assert!(resolve_wrr_vec_candidate(&candidates, 3).is_none());
        assert!(resolve_wrr_vec_candidate(&candidates, 99).is_none());
    }

    // ── HealthBitset tests ──────────────────────────────────────────────

    #[test]
    fn bitset_all_zero_is_empty() {
        let bs = HealthBitset::all(0);
        assert!(bs.is_empty());
        assert_eq!(bs.count(), 0);
        assert!(bs.is_all(0));
    }

    #[test]
    fn bitset_all_sets_correct_bits() {
        let bs = HealthBitset::all(5);
        assert_eq!(bs.count(), 5);
        assert!(bs.is_all(5));
        for i in 0..5 {
            assert!(bs.contains(i), "bit {} should be set", i);
        }
        assert!(!bs.contains(5));
    }

    #[test]
    fn bitset_all_128_is_max() {
        let bs = HealthBitset::all(128);
        assert_eq!(bs.count(), 128);
        assert!(bs.is_all(128));
        assert!(bs.contains(0));
        assert!(bs.contains(127));
    }

    #[test]
    fn bitset_set_and_clear() {
        let mut bs = HealthBitset::empty();
        assert!(bs.is_empty());

        bs.set(0);
        bs.set(5);
        bs.set(127);
        assert_eq!(bs.count(), 3);
        assert!(bs.contains(0));
        assert!(bs.contains(5));
        assert!(bs.contains(127));
        assert!(!bs.contains(1));

        bs.clear(5);
        assert_eq!(bs.count(), 2);
        assert!(!bs.contains(5));

        // Clear already-cleared bit is a no-op
        bs.clear(5);
        assert_eq!(bs.count(), 2);
    }

    #[test]
    fn bitset_nth_set_bit_basic() {
        let mut bs = HealthBitset::empty();
        bs.set(2);
        bs.set(5);
        bs.set(10);

        assert_eq!(bs.nth_set_bit(0), 2);
        assert_eq!(bs.nth_set_bit(1), 5);
        assert_eq!(bs.nth_set_bit(2), 10);
        // Wraps around
        assert_eq!(bs.nth_set_bit(3), 2);
        assert_eq!(bs.nth_set_bit(6), 2);
    }

    #[test]
    fn bitset_nth_set_bit_single() {
        let mut bs = HealthBitset::empty();
        bs.set(42);
        // Any index should return 42 since there's only one set bit
        for i in 0..10 {
            assert_eq!(bs.nth_set_bit(i), 42);
        }
    }

    #[test]
    fn bitset_nth_set_bit_large_index() {
        let bs = HealthBitset::all(3);
        // Large index wraps: 1000 % 3 = 1
        assert_eq!(bs.nth_set_bit(1000), 1);
    }

    #[test]
    fn bitset_boundary_127() {
        // Test the boundary just below 128
        let bs = HealthBitset::all(127);
        assert_eq!(bs.count(), 127);
        assert!(bs.contains(126));
        assert!(!bs.contains(127));
    }

    #[test]
    fn bitset_from_bits_recomputes_len() {
        // len must reflect popcount, not the number of set() calls.
        let bs = HealthBitset::from_bits(0b1011);
        assert_eq!(bs.count(), 3);
        assert!(bs.contains(0));
        assert!(bs.contains(1));
        assert!(!bs.contains(2));
        assert!(bs.contains(3));

        let empty = HealthBitset::from_bits(0);
        assert!(empty.is_empty());
        assert_eq!(empty.count(), 0);
    }

    #[test]
    fn bitset_intersect_keeps_common_bits() {
        let a = bitset_for_indices(&[0, 1, 2, 5]);
        let b = bitset_for_indices(&[1, 5, 9]);
        let both = a.intersect(&b);
        assert_eq!(both.count(), 2);
        assert!(both.contains(1));
        assert!(both.contains(5));
        assert!(!both.contains(0));
        assert!(!both.contains(2));
        assert!(!both.contains(9));

        // Disjoint sets intersect to empty.
        let disjoint = bitset_for_indices(&[0, 1]).intersect(&bitset_for_indices(&[2, 3]));
        assert!(disjoint.is_empty());
    }

    #[test]
    fn bitset_for_each_set_bit_visits_ascending() {
        let bs = bitset_for_indices(&[5, 0, 127, 42]);
        let mut visited = Vec::new();
        bs.for_each_set_bit(|i| visited.push(i));
        assert_eq!(visited, vec![0, 5, 42, 127]);

        // Empty bitset invokes the closure zero times.
        let mut count = 0;
        HealthBitset::empty().for_each_set_bit(|_| count += 1);
        assert_eq!(count, 0);
    }

    // ── Golden ratio hash distribution ──────────────────────────────────

    #[test]
    fn golden_ratio_hash_distributes() {
        // Verify golden_ratio_hash produces diverse values
        let mut seen = std::collections::HashSet::new();
        for i in 0..100u64 {
            let h = golden_ratio_hash(i);
            seen.insert(h);
        }
        // All 100 hashes should be unique
        assert_eq!(seen.len(), 100);
    }

    // ── Consistent hash empty-ring guards ──────────────────────────────

    fn make_target(host: &str, port: u16) -> UpstreamTarget {
        UpstreamTarget {
            host: host.to_string(),
            port,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }
    }

    /// A consistent-hash LoadBalancer with zero targets must have an empty
    /// hash_ring, and `select()` must return `None` without panicking.
    #[test]
    fn consistent_hash_empty_targets_returns_none() {
        let lb = LoadBalancer::new(
            "upstream-empty",
            LoadBalancerAlgorithm::ConsistentHashing,
            &[],
            None,
        );
        assert!(lb.hash_ring.is_empty());
        let result = lb.select("any-key", None);
        assert!(result.is_none());
    }

    /// The bitset-path guard (`select_consistent_hash_bitset`) returns `None`
    /// when the healthy bitset is empty, even if the hash_ring is populated.
    /// This exercises the internal empty-bitset early-return, NOT the public
    /// `select()` all-unhealthy fallback (which rebuilds an all-target bitset).
    #[test]
    fn consistent_hash_empty_bitset_guard_returns_none() {
        let targets = vec![make_target("10.0.0.1", 8080), make_target("10.0.0.2", 8080)];
        let lb = LoadBalancer::new(
            "upstream-ch",
            LoadBalancerAlgorithm::ConsistentHashing,
            &targets,
            None,
        );
        assert!(!lb.hash_ring.is_empty());

        // With an empty HealthBitset the internal method returns None.
        let empty = HealthBitset::empty();
        let result = lb.select_consistent_hash_bitset("key", &empty);
        assert!(result.is_none());
    }

    /// The Vec-fallback guard (`select_consistent_hash_vec`) returns `None`
    /// when the candidate list is empty.
    #[test]
    fn consistent_hash_empty_candidates_vec_returns_none() {
        let targets = vec![make_target("10.0.0.1", 8080), make_target("10.0.0.2", 8080)];
        let lb = LoadBalancer::new(
            "upstream-ch",
            LoadBalancerAlgorithm::ConsistentHashing,
            &targets,
            None,
        );
        let empty_candidates: Vec<(usize, &Arc<UpstreamTarget>)> = vec![];
        let result = lb.select_consistent_hash_vec("key", &empty_candidates);
        assert!(result.is_none());
    }

    /// Non-consistent-hash algorithms have an empty hash_ring by construction.
    /// Calling `select()` must work without touching the ring.
    #[test]
    fn non_consistent_hash_has_empty_ring() {
        for algo in [
            LoadBalancerAlgorithm::RoundRobin,
            LoadBalancerAlgorithm::Random,
            LoadBalancerAlgorithm::WeightedRoundRobin,
            LoadBalancerAlgorithm::LeastConnections,
            LoadBalancerAlgorithm::LeastLatency,
        ] {
            let targets = vec![make_target("10.0.0.1", 8080)];
            let lb = LoadBalancer::new("upstream-rr", algo, &targets, None);
            assert!(
                lb.hash_ring.is_empty(),
                "{:?} should have empty hash_ring",
                algo
            );
            // select() still works for non-consistent-hash algorithms
            let result = lb.select("ignored", None);
            assert!(result.is_some());
        }
    }

    #[test]
    fn non_wrr_port_override_does_not_allocate_wrr_state() {
        let targets = vec![
            make_target("10.0.0.1", 8080),
            make_target("10.0.0.2", 8080),
            make_target("10.0.0.3", 9090),
        ];
        let mut port_overrides = HashMap::new();
        port_overrides.insert(
            8080,
            UpstreamPortOverride {
                algorithm: Some(LoadBalancerAlgorithm::Random),
                ..Default::default()
            },
        );
        port_overrides.insert(
            9090,
            UpstreamPortOverride {
                algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
                ..Default::default()
            },
        );

        let lb = LoadBalancer::with_subsets_and_port_overrides(
            "upstream-port-wrr-state",
            LoadBalancerAlgorithm::RoundRobin,
            &targets,
            None,
            None,
            Some(&port_overrides),
            None,
            None,
            false,
        );

        let random_state = lb.port_overrides.get(&8080).expect("random override");
        assert!(
            !random_state.wrr_state.is_active(),
            "non-WRR port override must leave WRR lane inactive"
        );

        let wrr_state = lb.port_overrides.get(&9090).expect("wrr override");
        assert!(wrr_state.wrr_state.is_active());
        assert_eq!(wrr_state.wrr_state.target_len, targets.len());
    }

    #[test]
    fn recovered_target_does_not_require_wrr_invalidate_flag() {
        // Schedules are fingerprint-pure for a LoadBalancer generation. Recovery
        // must not depend on a racy invalidate boolean; restoring a previously
        // seen healthy set must reuse the cached schedule (hit, not rebuild).
        let targets = vec![
            make_target("10.0.0.1", 8080),
            make_target("10.0.0.2", 8080),
            make_target("10.0.0.3", 8080),
        ];
        let lb = LoadBalancer::new(
            "upstream-wrr-recovery",
            LoadBalancerAlgorithm::WeightedRoundRobin,
            &targets,
            None,
        );

        let all = HealthBitset::all(targets.len());
        let _ = lb.select_wrr_bitset(&all, &lb.wrr_state);
        let (_, rebuilds_after_full) = lb.wrr_state.cache_stats();
        assert!(rebuilds_after_full >= 1);

        let mut without_first = HealthBitset::all(targets.len());
        without_first.clear(0);
        let _ = lb.select_wrr_bitset(&without_first, &lb.wrr_state);
        let (hits_before, rebuilds_before) = lb.wrr_state.cache_stats();

        // Recovery restores the full healthy set — must hit the cached schedule.
        let _ = lb.select_wrr_bitset(&all, &lb.wrr_state);
        let (hits_after, rebuilds_after) = lb.wrr_state.cache_stats();
        assert_eq!(
            rebuilds_after, rebuilds_before,
            "restoring a cached fingerprint must not publish a new schedule"
        );
        assert!(
            hits_after > hits_before,
            "restored full healthy set must be a steady cache hit"
        );

        // Latency reset remains independent of WRR cache state.
        lb.reset_recovered_target_latency(&targets[0]);
    }

    /// Consistent hash with targets produces a non-empty ring and selects
    /// deterministically for the same key.
    #[test]
    fn consistent_hash_deterministic_selection() {
        let targets = vec![
            make_target("10.0.0.1", 8080),
            make_target("10.0.0.2", 8080),
            make_target("10.0.0.3", 8080),
        ];
        let lb = LoadBalancer::new(
            "upstream-ch",
            LoadBalancerAlgorithm::ConsistentHashing,
            &targets,
            None,
        );
        // 3 targets * 150 vnodes = 450 ring entries
        assert_eq!(lb.hash_ring.len(), 450);

        // Same key must always select the same target
        let first = lb.select("user-123", None).unwrap();
        for _ in 0..100 {
            let again = lb.select("user-123", None).unwrap();
            assert_eq!(first.target.host, again.target.host);
            assert_eq!(first.target.port, again.target.port);
        }
    }

    /// Public `select()` with consistent hashing where all targets are marked
    /// unhealthy via `HealthContext`. The method should rebuild an all-target
    /// bitset and return `Some(... is_fallback: true)`.
    #[test]
    fn consistent_hash_all_unhealthy_select_returns_fallback() {
        let targets = vec![
            make_target("10.0.0.1", 8080),
            make_target("10.0.0.2", 8080),
            make_target("10.0.0.3", 8080),
        ];
        let lb = LoadBalancer::new(
            "upstream-ch",
            LoadBalancerAlgorithm::ConsistentHashing,
            &targets,
            None,
        );

        // Mark every target as active-unhealthy.
        let active_unhealthy: DashMap<String, u64> = DashMap::new();
        for t in &targets {
            active_unhealthy.insert(target_key("upstream-ch", t), 1);
        }
        let health = HealthContext {
            active_unhealthy: &active_unhealthy,
            proxy_passive: None,
            max_ejection_percent: None,
        };

        let result = lb.select("some-key", Some(&health));
        let selection = result.expect("all-unhealthy should still return a fallback target");
        assert!(
            selection.is_fallback,
            "selection must be flagged as fallback when all targets are unhealthy"
        );

        // Determinism: same key always picks the same fallback target.
        for _ in 0..50 {
            let again = lb
                .select("some-key", Some(&health))
                .expect("fallback must be stable");
            assert_eq!(selection.target.host, again.target.host);
            assert_eq!(selection.target.port, again.target.port);
            assert!(again.is_fallback);
        }
    }

    /// Public `select()` with >128 targets exercises the Vec-based fallback
    /// path for consistent hashing when all targets are unhealthy.
    #[test]
    fn consistent_hash_all_unhealthy_vec_fallback_returns_fallback() {
        let target_count = 130; // exceeds MAX_BITSET_TARGETS (128)
        let targets: Vec<UpstreamTarget> = (0..target_count)
            .map(|i| make_target(&format!("10.0.{}.{}", i / 256, i % 256), 8080))
            .collect();
        let lb = LoadBalancer::new(
            "upstream-large",
            LoadBalancerAlgorithm::ConsistentHashing,
            &targets,
            None,
        );
        assert!(!lb.hash_ring.is_empty());

        // Mark every target as active-unhealthy.
        let active_unhealthy: DashMap<String, u64> = DashMap::new();
        for t in &targets {
            active_unhealthy.insert(target_key("upstream-large", t), 1);
        }
        let health = HealthContext {
            active_unhealthy: &active_unhealthy,
            proxy_passive: None,
            max_ejection_percent: None,
        };

        let result = lb.select("vec-key", Some(&health));
        let selection =
            result.expect("Vec fallback should return a target even when all unhealthy");
        assert!(
            selection.is_fallback,
            "Vec fallback selection must be flagged as fallback"
        );

        // Determinism across repeated calls.
        for _ in 0..50 {
            let again = lb
                .select("vec-key", Some(&health))
                .expect("Vec fallback must be stable");
            assert_eq!(selection.target.host, again.target.host);
            assert_eq!(selection.target.port, again.target.port);
            assert!(again.is_fallback);
        }
    }

    // ── PASSTHROUGH (loadBalancer.simple=PASSTHROUGH) ──────────────────

    /// `Passthrough` builds no hash ring / WRR state and selects like
    /// round-robin via the public `select()` (the orig-dst match lives in
    /// `select_passthrough`, not `select`).
    #[test]
    fn passthrough_algorithm_constructs_like_round_robin() {
        let targets = vec![make_target("10.0.0.1", 8080), make_target("10.0.0.2", 8080)];
        let lb = LoadBalancer::new(
            "upstream-pt",
            LoadBalancerAlgorithm::Passthrough,
            &targets,
            None,
        );
        assert!(lb.hash_ring.is_empty(), "Passthrough must have empty ring");
        // select() (the LB fallback) still returns a target, RR-style.
        assert!(lb.select("ignored", None).is_some());
    }

    /// orig-dst matching a pool target selects exactly that target, bypassing
    /// round-robin (repeated calls always return the matched target).
    #[test]
    fn passthrough_matches_pool_target_and_bypasses_rr() {
        let targets = vec![make_target("10.0.0.1", 8080), make_target("10.0.0.2", 8080)];
        let lb = LoadBalancer::new(
            "upstream-pt",
            LoadBalancerAlgorithm::Passthrough,
            &targets,
            None,
        );
        let orig: std::net::SocketAddr = "10.0.0.2:8080".parse().unwrap();
        for _ in 0..20 {
            let target = lb
                .select_passthrough(orig, None, None, None)
                .expect("orig-dst matches a pool target");
            assert_eq!(target.host, "10.0.0.2");
            assert_eq!(target.port, 8080);
        }
    }

    /// orig-dst that matches no pool target returns `None` (caller falls back
    /// to round-robin). Both a wrong IP and a wrong port miss.
    #[test]
    fn passthrough_unmatched_orig_dst_returns_none() {
        let targets = vec![make_target("10.0.0.1", 8080), make_target("10.0.0.2", 8080)];
        let lb = LoadBalancer::new(
            "upstream-pt",
            LoadBalancerAlgorithm::Passthrough,
            &targets,
            None,
        );
        // Wrong IP.
        let wrong_ip: std::net::SocketAddr = "10.9.9.9:8080".parse().unwrap();
        assert!(lb.select_passthrough(wrong_ip, None, None, None).is_none());
        // Right IP, wrong port.
        let wrong_port: std::net::SocketAddr = "10.0.0.1:9999".parse().unwrap();
        assert!(
            lb.select_passthrough(wrong_port, None, None, None)
                .is_none()
        );
    }

    /// An IPv4-mapped-IPv6 capture of an IPv4 target host still matches
    /// (canonicalized the same way the mesh VIP / by-workload keys are).
    #[test]
    fn passthrough_matches_ipv4_mapped_ipv6_capture() {
        let targets = vec![make_target("10.0.0.5", 8080)];
        let lb = LoadBalancer::new(
            "upstream-pt",
            LoadBalancerAlgorithm::Passthrough,
            &targets,
            None,
        );
        // ::ffff:10.0.0.5 is the IPv4-mapped form of 10.0.0.5.
        let mapped: std::net::SocketAddr = "[::ffff:10.0.0.5]:8080".parse().unwrap();
        let target = lb
            .select_passthrough(mapped, None, None, None)
            .expect("mapped-IPv6 capture matches the IPv4 target");
        assert_eq!(target.host, "10.0.0.5");
    }

    /// A passthrough-selected target that is active-unhealthy returns `None`
    /// (caller falls back to round-robin among healthy targets).
    #[test]
    fn passthrough_unhealthy_target_falls_back() {
        let targets = vec![make_target("10.0.0.1", 8080), make_target("10.0.0.2", 8080)];
        let lb = LoadBalancer::new(
            "upstream-pt",
            LoadBalancerAlgorithm::Passthrough,
            &targets,
            None,
        );
        // Eject the orig-dst target via active health.
        let active_unhealthy: DashMap<String, u64> = DashMap::new();
        active_unhealthy.insert(target_key("upstream-pt", &targets[1]), 1);
        let health = HealthContext {
            active_unhealthy: &active_unhealthy,
            proxy_passive: None,
            max_ejection_percent: None,
        };
        let orig: std::net::SocketAddr = "10.0.0.2:8080".parse().unwrap();
        assert!(
            lb.select_passthrough(orig, None, None, Some(&health))
                .is_none(),
            "an ejected orig-dst target must not be passthrough-selected"
        );
        // A healthy orig-dst target on the same upstream still passes through.
        let healthy_orig: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let target = lb
            .select_passthrough(healthy_orig, None, None, Some(&health))
            .expect("healthy orig-dst still passes through");
        assert_eq!(target.host, "10.0.0.1");
    }

    /// Passthrough composes with subset scoping: a match must be a member of
    /// the named subset, and an orig-dst outside the subset misses.
    #[test]
    fn passthrough_respects_subset_scope() {
        let mut t_v1 = make_target("10.0.0.1", 8080);
        t_v1.tags.insert("version".to_string(), "v1".to_string());
        let mut t_v2 = make_target("10.0.0.2", 8080);
        t_v2.tags.insert("version".to_string(), "v2".to_string());
        let targets = vec![t_v1, t_v2];
        let subsets = vec![SubsetDefinition {
            name: "v1".to_string(),
            labels: HashMap::from([("version".to_string(), "v1".to_string())]),
            traffic_policy: None,
        }];
        let lb = LoadBalancer::with_subsets(
            "upstream-pt",
            LoadBalancerAlgorithm::Passthrough,
            &targets,
            None,
            Some(&subsets),
        );
        // In-subset orig-dst matches.
        let in_subset: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let target = lb
            .select_passthrough(in_subset, None, Some("v1"), None)
            .expect("in-subset orig-dst matches");
        assert_eq!(target.host, "10.0.0.1");
        // Out-of-subset orig-dst (the v2 target) misses when scoped to v1.
        let out_subset: std::net::SocketAddr = "10.0.0.2:8080".parse().unwrap();
        assert!(
            lb.select_passthrough(out_subset, None, Some("v1"), None)
                .is_none(),
            "orig-dst outside the named subset must miss"
        );
    }
}
