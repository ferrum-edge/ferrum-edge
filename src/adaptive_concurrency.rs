//! Adaptive backend concurrency limiter.
//!
//! The limiter answers one question on the backend dispatch path: is the
//! selected destination currently healthy enough to accept one more in-flight
//! request? Proxy, proxy-group, and global plugin scopes control how state is
//! shared, and compatible cache generations reuse that state across reloads.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::config::db_backend::write_namespaced_runtime_key;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugins::{BackendAdmissionOutcome, BackendAdmissionPermit};

thread_local! {
    /// Reusable scratch buffer for the `namespace|id` scope-cache lookup key.
    ///
    /// Taken out of the cell for the duration of the lookup and put back
    /// afterwards, so a re-entrant call simply starts from an empty buffer
    /// instead of panicking on a nested borrow (mirrors `adaptive_buffer`).
    static SCOPE_KEY_SCRATCH: std::cell::Cell<String> =
        const { std::cell::Cell::new(String::new()) };
}

/// Run `f` with the namespace-qualified `namespace|id` scope-cache key.
///
/// Hot-path contract: no allocation after the calling thread's scratch buffer
/// has grown once. `f` must not call back into `with_namespaced_key` — a
/// re-entrant call is still correct, it just allocates a fresh buffer.
#[inline]
fn with_namespaced_key<R>(namespace: &str, proxy_id: &str, f: impl FnOnce(&str) -> R) -> R {
    SCOPE_KEY_SCRATCH.with(|slot| {
        let mut key = slot.take();
        write_namespaced_runtime_key(&mut key, namespace, proxy_id);
        let result = f(&key);
        slot.set(key);
        result
    })
}

const EWMA_PREVIOUS_WEIGHT: u64 = 8;
const EWMA_SAMPLE_WEIGHT: u64 = 2;
const EWMA_WEIGHT_SUM: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_SAMPLE_WEIGHT;
const POLICY_STATE_BITS: u32 = 1;
const POLICY_STATE_MASK: u64 = (1_u64 << POLICY_STATE_BITS) - 1;
const POLICY_ACTIVE: u64 = 0;
const POLICY_RESETTING: u64 = 1;
const MAX_POLICY_TRANSITION_EPOCH: u64 = u64::MAX >> POLICY_STATE_BITS;

#[derive(Clone, Copy)]
pub(crate) struct AdaptiveConcurrencyResetEpoch {
    resetting_word: u64,
    can_reactivate: bool,
}

/// Epoch-tagged structural lifecycle.
///
/// The state and its reset epoch share one atomic word so only the exact reset
/// owner can reactivate admission. A structural writer never overwrites a
/// `RESETTING` owner; this keeps a stale map rotation from crossing a newer
/// writer's commit boundary.
pub(crate) struct AdaptiveConcurrencyPolicyTransition {
    word: AtomicU64,
}

impl AdaptiveConcurrencyPolicyTransition {
    pub(crate) fn new() -> Self {
        Self {
            word: AtomicU64::new(policy_transition_word(0, POLICY_ACTIVE)),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        policy_transition_state(self.word.load(Ordering::Acquire)) == POLICY_ACTIVE
    }

    /// Claim a new structural reset epoch. Reset ownership is exclusive: a
    /// newer writer waits for an existing resetter to finish instead of
    /// replacing an indistinguishable `RESETTING` value.
    pub(crate) fn begin_structural_reset(&self) -> AdaptiveConcurrencyResetEpoch {
        let mut spins = 0_u8;
        loop {
            if let Some(reset) = self.try_begin_structural_reset() {
                return reset;
            }
            wait_for_policy_transition(&mut spins);
        }
    }

    /// Attempt one exact writer claim; the blocking production path retries
    /// when another reset owner or lifecycle transition wins.
    pub(crate) fn try_begin_structural_reset(&self) -> Option<AdaptiveConcurrencyResetEpoch> {
        let observed = self.word.load(Ordering::Acquire);
        if policy_transition_state(observed) == POLICY_RESETTING {
            return None;
        }
        let current_epoch = policy_transition_epoch(observed);
        let (next_epoch, can_reactivate) = if current_epoch == MAX_POLICY_TRANSITION_EPOCH {
            // More than 2^63 structural resets cannot occur in a process in
            // practice. If the counter is nevertheless exhausted, claim the
            // reset but leave the lifecycle fail-closed rather than permit an
            // ABA reactivation with a reused epoch.
            (current_epoch, false)
        } else {
            (current_epoch + 1, true)
        };
        let resetting_word = policy_transition_word(next_epoch, POLICY_RESETTING);
        self.word
            .compare_exchange(
                observed,
                resetting_word,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| AdaptiveConcurrencyResetEpoch {
                resetting_word,
                can_reactivate,
            })
    }

    /// Release exclusive reset ownership to active admission.
    /// The exact epoch CAS is the publication edge for the completed map clear.
    pub(crate) fn finish_reset(&self, reset: AdaptiveConcurrencyResetEpoch) -> bool {
        if !reset.can_reactivate {
            return false;
        }
        let next =
            policy_transition_word(policy_transition_epoch(reset.resetting_word), POLICY_ACTIVE);
        self.word
            .compare_exchange(
                reset.resetting_word,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

fn policy_transition_word(epoch: u64, state: u64) -> u64 {
    (epoch << POLICY_STATE_BITS) | state
}

fn policy_transition_epoch(word: u64) -> u64 {
    word >> POLICY_STATE_BITS
}

fn policy_transition_state(word: u64) -> u64 {
    word & POLICY_STATE_MASK
}

fn wait_for_policy_transition(spins: &mut u8) {
    if *spins < 64 {
        std::hint::spin_loop();
        *spins = spins.saturating_add(1);
    } else {
        std::thread::yield_now();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveConcurrencyKeyBy {
    /// Separate limit per proxy and selected backend endpoint.
    Proxy,
    /// Separate limit per upstream and selected backend endpoint; direct
    /// backends fall back to proxy-target scoping.
    Upstream,
    /// Shared limit per backend endpoint across every proxy using this plugin
    /// instance.
    Backend,
}

#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencyConfig {
    pub key_by: AdaptiveConcurrencyKeyBy,
    pub max_tracked_keys: usize,
    pub min_limit: u64,
    pub initial_limit: u64,
    pub max_limit: u64,
    pub min_samples: u64,
    pub target_latency_multiplier: f64,
    pub decrease_ratio: f64,
    pub increase_step: u64,
    pub shadow_mode: bool,
    pub expose_headers: bool,
}

#[derive(Clone, Debug, Eq)]
pub struct AdaptiveConcurrencyKey {
    // `Arc<str>` (not `String`): the scope is request-independent and resolved
    // through a per-proxy cache, so building a key on the hot path is a refcount
    // bump rather than a fresh allocation. `Hash`/`PartialEq` below stay
    // content-based (`Arc<str>` hashes/compares the `str`), so distinct `Arc`
    // instances carrying the same scope still collide/compare equal.
    scope: Arc<str>,
    host: String,
    port: u16,
}

impl PartialEq for AdaptiveConcurrencyKey {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && self.host == other.host && self.port == other.port
    }
}

impl Hash for AdaptiveConcurrencyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scope.hash(state);
        self.host.hash(state);
        self.port.hash(state);
    }
}

struct AdaptiveConcurrencyState {
    in_flight: CachePadded<AtomicU64>,
    limit: CachePadded<AtomicU64>,
    /// Recovery cohort. A decrease advances this epoch so requests admitted
    /// before the decrease cannot use their later successes to immediately
    /// restore the old limit.
    feedback_epoch: AtomicU64,
    baseline_latency_us: AtomicU64,
    latency_ewma_us: AtomicU64,
    samples: AtomicU64,
    rejections: AtomicU64,
}

impl AdaptiveConcurrencyState {
    fn new(initial_limit: u64) -> Self {
        Self {
            in_flight: CachePadded::new(AtomicU64::new(0)),
            limit: CachePadded::new(AtomicU64::new(initial_limit)),
            feedback_epoch: AtomicU64::new(1),
            baseline_latency_us: AtomicU64::new(0),
            latency_ewma_us: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
        }
    }
}

struct AdaptiveConcurrencyPolicyLifecycle {
    /// Serializes cold generation commits sharing this lifecycle. Request
    /// admission never takes this lock; it only prevents overlapping config/LB
    /// writers from dropping each other's feedback barrier or reset ownership.
    commit_lock: Mutex<()>,
    /// Plugin-cache generation currently authorized to admit and train.
    active_generation: AtomicU64,
    /// Oldest compatible plugin-cache generation still authorized to admit.
    /// Requests can pin a cache view before a reload and reach backend
    /// admission afterward, so compatible commits retain this floor. A
    /// structural key-space change advances it to the replacement generation.
    minimum_admission_generation: AtomicU64,
    /// Load-balancer snapshot generation currently authorized for admission.
    active_lb_generation: AtomicU64,
    /// Oldest compatible load-balancer generation still authorized. An
    /// affected service-discovery target-set change advances this floor.
    minimum_lb_admission_generation: AtomicU64,
    /// Replacement load-balancer generation staged around request-epoch
    /// publication.
    pending_lb_generation: AtomicU64,
    pending_lb_requires_reset: AtomicBool,
    /// Validated replacement generation staged around the cache's atomic
    /// publication. Compatible old/new plugins can both admit during this
    /// handoff because they share the same target counters.
    pending_generation: AtomicU64,
    pending_requires_reset: AtomicBool,
    /// Latest committed admission configuration. A request pinned to an older
    /// compatible plugin view must use these bounds instead of reviving its
    /// retired minimum, initial limit, key cap, or shadow-mode setting.
    active_config: ArcSwapOption<AdaptiveConcurrencyPolicyConfig>,
    /// Feedback callbacks that linearized under the active generation. Reload
    /// waits for this short synchronous critical section before clamping and
    /// publishing replacement policy bounds.
    feedback_in_progress: AtomicU64,
    /// Brief commit barrier preventing feedback from crossing the generation
    /// cutover while admission continues against generation-local bounds.
    feedback_blocked: AtomicBool,
    /// Brief structural reset barrier. Replacement generations rotate to a
    /// fresh target-tracking space while retired permits finish against the
    /// detached space they acquired from; they never hold this barrier open.
    transition: AdaptiveConcurrencyPolicyTransition,
}

struct AdaptiveConcurrencyPolicyConfig {
    generation: u64,
    config: Arc<AdaptiveConcurrencyConfig>,
}

impl AdaptiveConcurrencyPolicyLifecycle {
    fn new() -> Self {
        Self {
            commit_lock: Mutex::new(()),
            active_generation: AtomicU64::new(1),
            minimum_admission_generation: AtomicU64::new(1),
            active_lb_generation: AtomicU64::new(1),
            minimum_lb_admission_generation: AtomicU64::new(1),
            pending_lb_generation: AtomicU64::new(0),
            pending_lb_requires_reset: AtomicBool::new(false),
            pending_generation: AtomicU64::new(0),
            pending_requires_reset: AtomicBool::new(false),
            active_config: ArcSwapOption::empty(),
            feedback_in_progress: AtomicU64::new(0),
            feedback_blocked: AtomicBool::new(false),
            transition: AdaptiveConcurrencyPolicyTransition::new(),
        }
    }
}

struct AdaptiveConcurrencyFeedbackGuard<'a> {
    policy: &'a AdaptiveConcurrencyPolicyLifecycle,
}

impl Drop for AdaptiveConcurrencyFeedbackGuard<'_> {
    fn drop(&mut self) {
        self.policy
            .feedback_in_progress
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct AdaptiveConcurrencyTrackingSpace {
    inner: DashMap<AdaptiveConcurrencyKey, Arc<AdaptiveConcurrencyState>>,
    /// Per-proxy scope cache for `proxy` scoping, keyed by the
    /// namespace-qualified `namespace|id` runtime key. A bare `proxy.id` key
    /// would collide across tenants — a shared (global / proxy-group) limiter
    /// instance serves proxies from every namespace, so the first tenant to
    /// warm the cache would hand its own `proxy:{ns}:{id}` scope to another
    /// tenant's same-id proxy and merge both into one limiter row (issue
    /// #3094). `upstream` scoping is intentionally not cached.
    scope_cache: DashMap<Box<str>, Arc<str>>,
    tracked_keys: AtomicUsize,
}

impl AdaptiveConcurrencyTrackingSpace {
    fn new(shards: usize) -> Self {
        Self {
            inner: DashMap::with_shard_amount(shards),
            scope_cache: DashMap::with_shard_amount(shards),
            tracked_keys: AtomicUsize::new(0),
        }
    }
}

pub struct AdaptiveConcurrencyLimiter {
    /// Compatible generations retain this accounting domain. Structural policy
    /// or load-balancer generations atomically publish a fresh domain, while
    /// retired permits keep their target state alive directly until they finish.
    tracking_space: ArcSwap<AdaptiveConcurrencyTrackingSpace>,
    shard_amount: usize,
    /// Shared scope for `key_by = backend_target` (a single constant string).
    backend_scope: Arc<str>,
    policy: Arc<AdaptiveConcurrencyPolicyLifecycle>,
}

impl AdaptiveConcurrencyLimiter {
    pub fn new(shards: usize) -> Self {
        Self {
            // Both maps are on backend admission, so fresh structural spaces
            // preserve the operator-configured shard count.
            tracking_space: ArcSwap::from_pointee(AdaptiveConcurrencyTrackingSpace::new(shards)),
            shard_amount: shards,
            backend_scope: Arc::from("backend"),
            policy: Arc::new(AdaptiveConcurrencyPolicyLifecycle::new()),
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.tracking_space.load().inner.len()
    }

    // Public convenience entrypoint used by the library's external tests and
    // custom integrations. The binary crate uses the generation-aware path
    // through `AdaptiveConcurrency::try_backend_admission` instead.
    #[allow(dead_code)]
    pub fn try_acquire(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        config: Arc<AdaptiveConcurrencyConfig>,
    ) -> Result<Arc<AdaptiveConcurrencyPermit>, AdaptiveConcurrencyLimitExceeded> {
        let generation = self.policy.active_generation.load(Ordering::Acquire);
        let lb_generation = self.policy.active_lb_generation.load(Ordering::Acquire);
        self.try_acquire_for_generation(proxy, target, config, generation, lb_generation)
    }

    pub(crate) fn try_acquire_for_generation(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        request_config: Arc<AdaptiveConcurrencyConfig>,
        generation: u64,
        lb_generation: u64,
    ) -> Result<Arc<AdaptiveConcurrencyPermit>, AdaptiveConcurrencyLimitExceeded> {
        'admission: loop {
            // Pin one target/accounting domain before validating generation
            // ownership. Structural publication can then detach this entire
            // space without an old admission repopulating the replacement map.
            let tracking_space = self.tracking_space.load();
            let (config, config_generation) =
                self.admission_config(generation, Arc::clone(&request_config));
            self.ensure_policy_generation_admitted(generation, lb_generation)?;
            let key = build_key(
                self.resolve_scope(&tracking_space, proxy, config.key_by),
                proxy,
                target,
            );
            let state = match tracking_space.inner.entry(key) {
                Entry::Occupied(entry) => Arc::clone(entry.get()),
                Entry::Vacant(entry) => {
                    if self.reserve_key_slot(&tracking_space, config.max_tracked_keys) {
                        let state = Arc::new(AdaptiveConcurrencyState::new(config.initial_limit));
                        entry.insert(Arc::clone(&state));
                        state
                    } else {
                        // Key-cardinality cap reached. Fail OPEN with a per-request,
                        // untracked state rather than rejecting: `max_tracked_keys`
                        // only bounds the limiter's own memory, so a target beyond
                        // the cap must still be admitted (never black-holed by a
                        // blanket 503). `shadow_mode` likewise stays fail-open for
                        // current-generation capacity decisions; the separate
                        // generation-ownership checks still fail closed.
                        // This state is NOT inserted into the map (memory stays
                        // bounded) and dies with the permit, so overflow targets run
                        // without adaptive limiting until the policy is removed and
                        // recreated (or a structural key-space change resets it).
                        // Starting at `in_flight = 0` it always admits below.
                        drop(entry);
                        Arc::new(AdaptiveConcurrencyState::new(config.initial_limit))
                    }
                }
            };

            loop {
                let current = state.in_flight.load(Ordering::Relaxed);
                // During the two-phase cache handoff, compatible old/new plugin
                // objects can briefly admit together. After commit, an old view
                // uses the replacement admission configuration.
                let limit = state
                    .limit
                    .load(Ordering::Acquire)
                    .max(config.min_limit)
                    .min(config.max_limit);
                if current >= limit && !config.shadow_mode {
                    let generation_admitted =
                        self.policy_generation_admitted(generation, lb_generation);
                    let tracking_space_current = self.tracking_space_is_current(&tracking_space);
                    let config_current = self.admission_config_current(config_generation);
                    if !generation_admitted || !tracking_space_current {
                        return Err(self.generation_handoff_rejection());
                    }
                    if !config_current {
                        self.clamp_to_active_config(&state);
                        continue 'admission;
                    }
                    state.rejections.fetch_add(1, Ordering::Relaxed);
                    return Err(AdaptiveConcurrencyLimitExceeded::TargetLimit {
                        current_in_flight: current,
                        limit,
                        expose_headers: config.expose_headers,
                    });
                }

                match state.in_flight.compare_exchange_weak(
                    current,
                    current.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // A cache activation may race this cold target lookup/CAS.
                        // Roll back instead of returning a permit owned by a
                        // retired policy generation, crossing a structural reset,
                        // or applying an admission config superseded by commit.
                        let generation_admitted =
                            self.policy_generation_admitted(generation, lb_generation);
                        let tracking_space_current =
                            self.tracking_space_is_current(&tracking_space);
                        let config_current = self.admission_config_current(config_generation);
                        if !generation_admitted || !tracking_space_current || !config_current {
                            state.in_flight.fetch_sub(1, Ordering::AcqRel);
                            if generation_admitted && tracking_space_current && !config_current {
                                self.clamp_to_active_config(&state);
                                continue 'admission;
                            }
                            return Err(self.generation_handoff_rejection());
                        }
                        let feedback_epoch = state.feedback_epoch.load(Ordering::Acquire);
                        return Ok(Arc::new(AdaptiveConcurrencyPermit {
                            state,
                            config,
                            policy: Arc::clone(&self.policy),
                            policy_generation: generation,
                            lb_generation,
                            feedback_epoch,
                            recorded: AtomicBool::new(false),
                        }));
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    fn admission_config(
        &self,
        generation: u64,
        config: Arc<AdaptiveConcurrencyConfig>,
    ) -> (Arc<AdaptiveConcurrencyConfig>, u64) {
        let active = self.policy.active_config.load();
        match active
            .as_ref()
            .filter(|active| active.generation > generation)
        {
            Some(active) => (Arc::clone(&active.config), active.generation),
            None => (config, generation),
        }
    }

    fn admission_config_current(&self, config_generation: u64) -> bool {
        self.policy
            .active_config
            .load()
            .as_ref()
            .is_none_or(|active| active.generation <= config_generation)
    }

    fn clamp_to_active_config(&self, state: &AdaptiveConcurrencyState) {
        if let Some(active) = self.policy.active_config.load().as_ref() {
            clamp_limit(
                &state.limit,
                active.config.min_limit,
                active.config.max_limit,
            );
        }
    }

    fn tracking_space_is_current(
        &self,
        tracking_space: &Arc<AdaptiveConcurrencyTrackingSpace>,
    ) -> bool {
        let current = self.tracking_space.load();
        Arc::ptr_eq(tracking_space, &current)
    }

    fn reset_tracking_space(&self) {
        self.tracking_space
            .store(Arc::new(AdaptiveConcurrencyTrackingSpace::new(
                self.shard_amount,
            )));
    }

    fn ensure_policy_generation_admitted(
        &self,
        generation: u64,
        lb_generation: u64,
    ) -> Result<(), AdaptiveConcurrencyLimitExceeded> {
        if self.policy_generation_admitted(generation, lb_generation) {
            Ok(())
        } else {
            Err(self.generation_handoff_rejection())
        }
    }

    fn policy_generation_admitted(&self, generation: u64, lb_generation: u64) -> bool {
        if !self.policy.transition.is_active() {
            return false;
        }
        self.policy_generation_current(generation, lb_generation)
    }

    fn policy_generation_current(&self, generation: u64, lb_generation: u64) -> bool {
        let active = self.policy.active_generation.load(Ordering::Acquire);
        let minimum = self
            .policy
            .minimum_admission_generation
            .load(Ordering::Acquire);
        let config_current = (generation >= minimum && generation <= active)
            || (self.policy.pending_generation.load(Ordering::Acquire) == generation
                && generation != 0
                && !self.policy.pending_requires_reset.load(Ordering::Acquire));
        if !config_current {
            return false;
        }

        let active_lb = self.policy.active_lb_generation.load(Ordering::Acquire);
        let minimum_lb = self
            .policy
            .minimum_lb_admission_generation
            .load(Ordering::Acquire);
        (lb_generation >= minimum_lb && lb_generation <= active_lb)
            || (self.policy.pending_lb_generation.load(Ordering::Acquire) == lb_generation
                && lb_generation != 0
                && !self
                    .policy
                    .pending_lb_requires_reset
                    .load(Ordering::Acquire))
    }

    fn generation_handoff_rejection(&self) -> AdaptiveConcurrencyLimitExceeded {
        AdaptiveConcurrencyLimitExceeded::GenerationHandoff
    }

    /// Stage a fully validated generation immediately before its plugin-cache
    /// snapshot is published. The active generation remains authorized until
    /// the snapshot store, avoiding a fail-closed gap for compatible reloads.
    pub(crate) fn prepare_policy_generation(&self, generation: u64, reset_tracking_space: bool) {
        if generation <= self.policy.active_generation.load(Ordering::Acquire) {
            return;
        }
        self.policy
            .pending_requires_reset
            .store(reset_tracking_space, Ordering::Release);
        self.policy
            .pending_generation
            .store(generation, Ordering::Release);
    }

    /// Commit the staged generation immediately after its cache snapshot is
    /// published. Already-linearized feedback completes before retained bounds
    /// are clamped or a structural tracking space rotates; later retired
    /// feedback is ignored.
    pub(crate) fn commit_policy_generation(
        &self,
        generation: u64,
        config: Arc<AdaptiveConcurrencyConfig>,
        reset_tracking_space: bool,
    ) {
        // Poison only means an earlier cold writer panicked. The atomic
        // lifecycle remains fail-closed, so recover the guard and inspect the
        // published generations instead of making the request path take a lock.
        let _commit_guard = self
            .policy
            .commit_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut current = self.policy.active_generation.load(Ordering::Acquire);
        if generation <= current {
            return;
        }

        self.policy.feedback_blocked.store(true, Ordering::Release);

        // A callback that acquired its guard before the commit barrier is
        // ordered before this activation. Later callbacks fail the barrier or
        // generation checks and cannot mutate stale sampling or limit state.
        let mut spins = 0_u8;
        while self.policy.feedback_in_progress.load(Ordering::Acquire) != 0 {
            if spins < 64 {
                std::hint::spin_loop();
                spins = spins.saturating_add(1);
            } else {
                std::thread::yield_now();
            }
        }

        let structural_reset = if reset_tracking_space {
            // Exclusively block admission before retiring the older key-space
            // generations. The epoch claim waits for an in-progress structural
            // writer rather than stealing its RESETTING state.
            let reset = self.policy.transition.begin_structural_reset();
            self.policy
                .minimum_admission_generation
                .fetch_max(generation, Ordering::AcqRel);
            Some(reset)
        } else {
            None
        };

        let replacement_config = Arc::new(AdaptiveConcurrencyPolicyConfig {
            generation,
            config: Arc::clone(&config),
        });
        self.policy.active_config.rcu(|current| {
            if current
                .as_ref()
                .is_some_and(|active| active.generation >= generation)
            {
                current.clone()
            } else {
                Some(Arc::clone(&replacement_config))
            }
        });

        loop {
            if generation <= current {
                self.policy.feedback_blocked.store(false, Ordering::Release);
                return;
            }
            match self.policy.active_generation.compare_exchange(
                current,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        if self
            .policy
            .pending_generation
            .compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.policy
                .pending_requires_reset
                .store(false, Ordering::Release);
        }

        if let Some(reset) = structural_reset {
            // Structural commits retire this entire space, so scanning up to
            // max_tracked_keys entries to clamp it would only extend the
            // fail-closed reset window. The mutually exclusive branch below is
            // the only commit path that clamps retained target state.
            debug_assert!(reset_tracking_space);
            self.reset_tracking_space();
            // Retired permits own their detached target states directly. The
            // replacement can therefore reopen immediately without waiting
            // for those permits, while retired generation views stay rejected.
            let _ = self.policy.transition.finish_reset(reset);
        } else {
            debug_assert!(!reset_tracking_space);
            // Learned state and in-flight accounting survive compatible config
            // changes, but the replacement bounds become authoritative at
            // commit.
            let tracking_space = self.tracking_space.load();
            for entry in &tracking_space.inner {
                clamp_limit(&entry.value().limit, config.min_limit, config.max_limit);
            }
        }
        self.policy.feedback_blocked.store(false, Ordering::Release);
    }

    /// Stage the load-balancer generation that will be published in the next
    /// request epoch. Policies whose referenced upstream endpoint sets changed
    /// require a fresh target space; unrelated policies keep old pinned request
    /// views compatible with the replacement snapshot.
    pub(crate) fn prepare_lb_generation(&self, generation: u64, reset_tracking_space: bool) {
        if generation <= self.policy.active_lb_generation.load(Ordering::Acquire) {
            return;
        }
        self.policy
            .pending_lb_requires_reset
            .store(reset_tracking_space, Ordering::Release);
        self.policy
            .pending_lb_generation
            .store(generation, Ordering::Release);
    }

    /// Commit a staged load-balancer generation after request-epoch
    /// publication. An affected target-set change advances the admission floor
    /// and atomically rotates the target space, so old permits cannot pin the
    /// replacement and old pinned requests cannot repopulate it.
    pub(crate) fn commit_lb_generation(&self, generation: u64, reset_tracking_space: bool) {
        let _commit_guard = self
            .policy
            .commit_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut current = self.policy.active_lb_generation.load(Ordering::Acquire);
        if generation <= current {
            return;
        }

        self.policy.feedback_blocked.store(true, Ordering::Release);
        let mut spins = 0_u8;
        while self.policy.feedback_in_progress.load(Ordering::Acquire) != 0 {
            if spins < 64 {
                std::hint::spin_loop();
                spins = spins.saturating_add(1);
            } else {
                std::thread::yield_now();
            }
        }

        let structural_reset = if reset_tracking_space {
            let reset = self.policy.transition.begin_structural_reset();
            self.policy
                .minimum_lb_admission_generation
                .fetch_max(generation, Ordering::AcqRel);
            Some(reset)
        } else {
            None
        };

        loop {
            if generation <= current {
                self.policy.feedback_blocked.store(false, Ordering::Release);
                return;
            }
            match self.policy.active_lb_generation.compare_exchange(
                current,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        if self
            .policy
            .pending_lb_generation
            .compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.policy
                .pending_lb_requires_reset
                .store(false, Ordering::Release);
        }

        if let Some(reset) = structural_reset {
            self.reset_tracking_space();
            // An old service-discovery permit remains attached to the retired
            // space and cannot pin or repopulate the replacement target map.
            let _ = self.policy.transition.finish_reset(reset);
        }
        self.policy.feedback_blocked.store(false, Ordering::Release);
    }

    fn reserve_key_slot(
        &self,
        tracking_space: &AdaptiveConcurrencyTrackingSpace,
        max_tracked_keys: usize,
    ) -> bool {
        let mut current = tracking_space.tracked_keys.load(Ordering::Acquire);
        loop {
            if current >= max_tracked_keys {
                return false;
            }
            match tracking_space.tracked_keys.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    #[allow(dead_code)]
    pub fn snapshot(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        key_by: AdaptiveConcurrencyKeyBy,
    ) -> Option<AdaptiveConcurrencySnapshot> {
        let tracking_space = self.tracking_space.load();
        let key = build_key(
            self.resolve_scope(&tracking_space, proxy, key_by),
            proxy,
            target,
        );
        tracking_space
            .inner
            .get(&key)
            .map(|entry| AdaptiveConcurrencySnapshot::from_state(key, entry.value()))
    }

    /// Resolve the scope component of the key for `proxy` under `key_by`.
    /// `backend` scoping returns one shared constant. `proxy` scoping caches a
    /// reused `Arc<str>` per namespace-qualified `namespace|id` runtime key —
    /// which uniquely and stably identifies the proxy, so the cached
    /// `proxy:{ns}:{id}` scope never goes stale and never crosses tenants.
    /// `upstream` scoping is computed per call: its `upstream:{ns}:{upstream_id}`
    /// depends on the proxy's upstream, which can change across a reload while a
    /// shared (global/proxy_group) limiter instance — and this cache — is
    /// preserved, so caching it by proxy identity would serve a stale upstream
    /// scope. The string is short, and the admission path already allocates the
    /// full key in `build_key`.
    fn resolve_scope(
        &self,
        tracking_space: &AdaptiveConcurrencyTrackingSpace,
        proxy: &Proxy,
        key_by: AdaptiveConcurrencyKeyBy,
    ) -> Arc<str> {
        match key_by {
            AdaptiveConcurrencyKeyBy::Backend => Arc::clone(&self.backend_scope),
            AdaptiveConcurrencyKeyBy::Upstream => Arc::from(adaptive_concurrency_scope(
                key_by,
                proxy,
                proxy.upstream_id.as_deref(),
            )),
            AdaptiveConcurrencyKeyBy::Proxy => {
                with_namespaced_key(&proxy.namespace, &proxy.id, |cache_key| {
                    if let Some(cached) = tracking_space.scope_cache.get(cache_key) {
                        return Arc::clone(cached.value());
                    }
                    let scope: Arc<str> = Arc::from(adaptive_concurrency_scope(
                        key_by,
                        proxy,
                        proxy.upstream_id.as_deref(),
                    ));
                    tracking_space
                        .scope_cache
                        .insert(cache_key.into(), Arc::clone(&scope));
                    scope
                })
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencySnapshot {
    pub key: AdaptiveConcurrencyKey,
    pub in_flight: u64,
    pub limit: u64,
    pub baseline_latency_us: u64,
    pub latency_ewma_us: u64,
    pub samples: u64,
    pub rejections: u64,
}

impl AdaptiveConcurrencySnapshot {
    fn from_state(key: AdaptiveConcurrencyKey, state: &AdaptiveConcurrencyState) -> Self {
        Self {
            key,
            in_flight: state.in_flight.load(Ordering::Relaxed),
            limit: state.limit.load(Ordering::Acquire),
            baseline_latency_us: state.baseline_latency_us.load(Ordering::Acquire),
            latency_ewma_us: state.latency_ewma_us.load(Ordering::Acquire),
            samples: state.samples.load(Ordering::Acquire),
            rejections: state.rejections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub enum AdaptiveConcurrencyLimitExceeded {
    TargetLimit {
        current_in_flight: u64,
        limit: u64,
        /// A request pinned to an older compatible plugin view uses the active
        /// configuration's header policy for genuine target-limit rejections.
        expose_headers: bool,
    },
    /// Policy/LB generation handoffs have no truthful per-target values.
    GenerationHandoff,
}

pub struct AdaptiveConcurrencyPermit {
    state: Arc<AdaptiveConcurrencyState>,
    config: Arc<AdaptiveConcurrencyConfig>,
    policy: Arc<AdaptiveConcurrencyPolicyLifecycle>,
    policy_generation: u64,
    lb_generation: u64,
    feedback_epoch: u64,
    recorded: AtomicBool,
}

impl AdaptiveConcurrencyPermit {
    fn begin_feedback(&self) -> Option<AdaptiveConcurrencyFeedbackGuard<'_>> {
        if self.policy.feedback_blocked.load(Ordering::Acquire)
            || !self.feedback_generation_current()
        {
            return None;
        }
        self.policy
            .feedback_in_progress
            .fetch_add(1, Ordering::AcqRel);
        if self.policy.feedback_blocked.load(Ordering::Acquire)
            || !self.feedback_generation_current()
        {
            self.policy
                .feedback_in_progress
                .fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(AdaptiveConcurrencyFeedbackGuard {
            policy: self.policy.as_ref(),
        })
    }

    fn feedback_generation_current(&self) -> bool {
        let config_current = self.policy.active_generation.load(Ordering::Acquire)
            == self.policy_generation
            || self.policy.pending_generation.load(Ordering::Acquire) == self.policy_generation;
        let lb_current = self.policy.active_lb_generation.load(Ordering::Acquire)
            == self.lb_generation
            || self.policy.pending_lb_generation.load(Ordering::Acquire) == self.lb_generation;
        config_current && lb_current
    }

    /// Feed one healthy backend sample into the limiter.
    ///
    /// `backend_elapsed` is the dispatch-relative backend latency. For buffered
    /// responses it is the full backend round trip; for streamed responses it is
    /// TTFB (headers), recorded at body completion — so for streaming backends
    /// the latency signal is TTFB while the slot is held for the whole body.
    /// That asymmetry is acceptable because a streamed slot is still transient
    /// (it frees when the body completes), unlike a WebSocket session, which is
    /// why streaming keeps `allow_increase = true` rather than using the holding
    /// variant.
    ///
    /// Heuristic caveat: `baseline_latency_us` is a monotonically-decreasing
    /// minimum that never decays back up, so a single unusually-fast response
    /// (a tiny 200, a 304, a cache hit) permanently lowers `target_latency` and
    /// can keep the limit pinned low. A windowed/decaying minimum would avoid
    /// this; it is left as a documented sensitivity for now.
    fn record_success_latency(&self, backend_elapsed: Duration, allow_increase: bool) {
        let latency_us = (backend_elapsed.as_micros() as u64).max(1);
        update_min(&self.state.baseline_latency_us, latency_us);
        let ewma = update_ewma(&self.state.latency_ewma_us, latency_us);
        let samples = self.state.samples.fetch_add(1, Ordering::AcqRel) + 1;
        if samples < self.config.min_samples {
            return;
        }

        let baseline = self.state.baseline_latency_us.load(Ordering::Acquire);
        if baseline == 0 {
            return;
        }
        let target_latency = (baseline as f64 * self.config.target_latency_multiplier)
            .round()
            .max(1.0) as u64;
        let current_limit = self.state.limit.load(Ordering::Acquire);
        let current_in_flight = self.state.in_flight.load(Ordering::Acquire);
        if ewma > target_latency {
            invalidate_recovery_cohort_and_decrease(&self.state, &self.config);
        } else if allow_increase && current_in_flight >= current_limit {
            increase_limit_for_epoch(
                &self.state.limit,
                &self.state.feedback_epoch,
                self.feedback_epoch,
                &self.config,
            );
        }
    }

    /// Shared outcome accounting. `allow_increase` is `false` for long-lived
    /// admissions (WebSocket sessions) whose in-flight slot is still held when
    /// the outcome is recorded: every concurrent handshake then observes
    /// `in_flight >= limit`, so growing the limit there would ratchet it up to
    /// `max_limit` and defeat the in-flight session cap.
    fn record(&self, outcome: BackendAdmissionOutcome, allow_increase: bool) {
        if self.recorded.swap(true, Ordering::AcqRel) {
            return;
        }
        // Config changes publish a new feedback generation. Retired permits
        // still release their shared in-flight slots on Drop, but must not
        // train the replacement policy with stale bounds or sampling controls.
        // The guard makes this check coherent with concurrent activation.
        let Some(_feedback_guard) = self.begin_feedback() else {
            return;
        };
        // Client-/gateway-side outcomes do not reflect backend health: release
        // the slot without feeding a latency, growth, or shrink signal. An
        // oversized *client* upload surfaces as a gateway 413
        // (`RequestBodyTooLarge`), a client abort as `ClientDisconnect`, and a
        // pre-dial dispatch-policy shed (backend-TLS-SNI reject, or an
        // `http1MaxPendingRequests` in-flight-overflow 503) as
        // `DispatchPolicyRejected`; none is the backend's fault, so they must
        // not train the limiter. Shares `client_side_no_backend_signal` with the
        // circuit-breaker / passive-health accounting so an overflow shed's
        // synthetic 503 cannot reach the `>= 500` shrink branch below and shrink
        // a backend that was never dialed — the predicates cannot drift.
        if crate::proxy::backend_dispatch::client_side_no_backend_signal(outcome.error_class) {
            return;
        }
        // Backend faults shrink the limit. Besides connection errors and 5xx,
        // this covers post-wire backend failures — a stream that returned healthy
        // 2xx headers and then timed out / reset mid-body (`ReadWriteTimeout` /
        // `ConnectionReset` / `ConnectionClosed` / `ProtocolError`) or over-sent
        // past the response-size cap (`ResponseBodyTooLarge`). Without them the
        // limiter would treat a post-header backend stall as a fast success and
        // grow the limit. Shares the predicate with the circuit-breaker /
        // passive-health accounting so the two cannot drift.
        if outcome.connection_error
            || outcome.response_status >= 500
            || crate::proxy::backend_dispatch::error_class_is_post_wire_backend_failure(
                outcome.error_class,
            )
        {
            invalidate_recovery_cohort_and_decrease(&self.state, &self.config);
            return;
        }
        self.record_success_latency(outcome.backend_elapsed, allow_increase);
    }
}

impl BackendAdmissionPermit for AdaptiveConcurrencyPermit {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        self.record(outcome, true);
    }

    fn record_backend_outcome_holding(&self, outcome: BackendAdmissionOutcome) {
        self.record(outcome, false);
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn build_key(
    scope: Arc<str>,
    proxy: &Proxy,
    target: Option<&UpstreamTarget>,
) -> AdaptiveConcurrencyKey {
    // Only host/port vary per request; `scope` is resolved (and cached) by the
    // caller via `resolve_scope`.
    let (host, port) = target
        .map(|target| (target.host.as_str(), target.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));

    AdaptiveConcurrencyKey {
        scope,
        host: host.to_string(),
        port,
    }
}

/// Canonical scope formatter shared by request admission and cold route-key
/// inventory. `upstream_id` may be an effective route override; `None` uses the
/// direct-backend proxy fallback required by `upstream_target` scoping.
pub(crate) fn adaptive_concurrency_scope(
    key_by: AdaptiveConcurrencyKeyBy,
    proxy: &Proxy,
    upstream_id: Option<&str>,
) -> String {
    match key_by {
        AdaptiveConcurrencyKeyBy::Proxy => scoped_proxy(proxy),
        AdaptiveConcurrencyKeyBy::Upstream => upstream_id
            .map(|upstream_id| {
                let mut scope = String::with_capacity(
                    "upstream::".len() + proxy.namespace.len() + upstream_id.len(),
                );
                scope.push_str("upstream:");
                scope.push_str(&proxy.namespace);
                scope.push(':');
                scope.push_str(upstream_id);
                scope
            })
            .unwrap_or_else(|| scoped_proxy(proxy)),
        // `backend` scope is served as a shared constant by `resolve_scope` and
        // never reaches this function in practice.
        AdaptiveConcurrencyKeyBy::Backend => "backend".to_string(),
    }
}

fn scoped_proxy(proxy: &Proxy) -> String {
    let mut scope = String::with_capacity("proxy::".len() + proxy.namespace.len() + proxy.id.len());
    scope.push_str("proxy:");
    scope.push_str(&proxy.namespace);
    scope.push(':');
    scope.push_str(&proxy.id);
    scope
}

fn update_min(atomic: &AtomicU64, candidate: u64) {
    let mut current = atomic.load(Ordering::Acquire);
    loop {
        if current != 0 && current <= candidate {
            return;
        }
        match atomic.compare_exchange(current, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn update_ewma(atomic: &AtomicU64, sample: u64) -> u64 {
    let mut current = atomic.load(Ordering::Acquire);
    loop {
        let next = if current == 0 {
            sample
        } else {
            current
                .saturating_mul(EWMA_PREVIOUS_WEIGHT)
                .saturating_add(sample.saturating_mul(EWMA_SAMPLE_WEIGHT))
                / EWMA_WEIGHT_SUM
        };
        match atomic.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

fn invalidate_recovery_cohort_and_decrease(
    state: &AdaptiveConcurrencyState,
    config: &AdaptiveConcurrencyConfig,
) {
    let limit_before_invalidation = state.limit.load(Ordering::Acquire);
    // This increment is the recovery-ordering linearization point. A success
    // racing after it cannot pass `increase_limit_for_epoch` with its stale
    // epoch. A success that passed its epoch check just before this increment
    // may still win its limit CAS afterward, so the decrease uses the
    // pre-invalidation limit as a fixed ceiling rather than multiplying that
    // stale increase into a weaker backoff.
    state.feedback_epoch.fetch_add(1, Ordering::AcqRel);
    decrease_limit(&state.limit, config, limit_before_invalidation);
}

pub(crate) fn decrease_limit(
    limit: &AtomicU64,
    config: &AdaptiveConcurrencyConfig,
    limit_before_invalidation: u64,
) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        // The callback's pre-invalidation observation is a ceiling, not a
        // fixed target. It prevents a stale success CAS from weakening this
        // backoff, while recomputing from a lower observed value makes every
        // racing failure/high-latency callback apply its own decrease.
        let decrease_base = current.min(limit_before_invalidation);
        let decreased = ((decrease_base as f64) * config.decrease_ratio).floor() as u64;
        let next = decreased.max(config.min_limit).min(config.max_limit);
        if next >= current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn increase_limit_for_epoch(
    limit: &AtomicU64,
    feedback_epoch: &AtomicU64,
    expected_epoch: u64,
    config: &AdaptiveConcurrencyConfig,
) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        if feedback_epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
        if current >= config.max_limit {
            return;
        }
        let next = current
            .saturating_add(config.increase_step)
            .max(config.min_limit)
            .min(config.max_limit);
        if next == current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn clamp_limit(limit: &AtomicU64, min_limit: u64, max_limit: u64) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        let next = current.max(min_limit).min(max_limit);
        if next == current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
