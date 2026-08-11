//! Global JWKS key store cache shared across plugin instances.
//!
//! When multiple proxies (or multiple providers within one proxy) reference
//! the same JWKS URI, they share a single [`JwksKeyStore`] — avoiding
//! redundant HTTP fetches and duplicate background refresh tasks.
//!
//! The cache is keyed by the resolved `jwks_uri` string. It is lazily
//! initialized on first access and lives for the process lifetime.
//!
//! On config reload, [`retain_active_uris`] removes entries for JWKS URIs
//! that are no longer referenced by any active JWKS consumer, aborting their
//! background refresh tasks after any retired in-flight consumers finish.
//!
//! The active set has two contributors, unioned by
//! [`reconcile_active_requirements`]:
//!
//! * the exact requirement map of the last committed plugin generation
//!   ([`retain_active_requirements`]), and
//! * [`LateActiveRequirement`] registrations from committed consumers whose
//!   store was resolved asynchronously *after* that publication already ran
//!   (OIDC discovery). Without them a discovery-backed store an authenticator
//!   really uses would age into grace/expired while `/health`, `/status`, and
//!   the JWKS metrics still omitted it.
//!
//! Every mutation recomputes the whole union, so a publication, retirement,
//! discovery-URI replacement, or rejected staged generation reconciles only its
//! own contribution and can never deactivate a co-tenant of the same URI.

use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::info;

use super::PluginHttpClient;
use super::jwks_store::{
    JwksFailureClass, JwksKeyStore, JwksTrustState, redacted_jwks_uri, register_trust_change_hook,
};

/// Effective requirements contributed by one active shared-store consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JwksRefreshRequirement {
    pub refresh_interval: Duration,
    pub max_stale: Duration,
}

impl JwksRefreshRequirement {
    pub const fn new(refresh_interval: Duration, max_stale: Duration) -> Self {
        Self {
            refresh_interval,
            max_stale,
        }
    }

    pub fn strictest(self, other: Self) -> Self {
        Self {
            refresh_interval: self.refresh_interval.min(other.refresh_interval),
            max_stale: self.max_stale.min(other.max_stale),
        }
    }
}

/// Strictest active requirement per shared JWKS URI.
type JwksRequirementMap = HashMap<String, JwksRefreshRequirement>;

/// A cached JWKS entry: the key store plus its background refresh task handle.
struct JwksCacheEntry {
    store: Arc<JwksKeyStore>,
    refresh_handle: JoinHandle<()>,
    requirement: JwksRefreshRequirement,
    refresh_generation: u64,
    retirement_epoch: Arc<AtomicU64>,
    active: AtomicBool,
    reaper_generation: AtomicU64,
}

const RETIRED_STORE_REAP_INTERVAL: Duration = Duration::from_millis(100);

/// Fixed-cardinality, redacted aggregate of active remote JWKS trust stores.
///
/// Counts never include inline key material. Endpoints, credentials, `kid`
/// values, tokens, claims, and key bytes never appear here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JwksTrustHealthAggregate {
    pub fresh: u64,
    pub grace: u64,
    pub expired: u64,
    pub max_age_seconds_fresh: u64,
    pub max_age_seconds_grace: u64,
    pub max_age_seconds_expired: u64,
    /// Earliest monotonic expiry among currently non-expired active remotes.
    /// Readiness flips when `Instant::now() >= deadline` even before the
    /// background republish task runs.
    next_expiry_at: Option<Instant>,
    /// Earliest monotonic grace transition among currently fresh active remotes.
    next_grace_at: Option<Instant>,
    /// Monotonic observation time for the precomputed maximum ages below.
    age_observed_at: Option<Instant>,
    max_age_fresh_at_observation: Option<Duration>,
    max_age_grace_at_observation: Option<Duration>,
    max_age_expired_at_observation: Option<Duration>,
}

impl JwksTrustHealthAggregate {
    /// True when no active remote store is expired (or past its expiry deadline).
    pub fn ready(&self, now: Instant) -> bool {
        self.expired == 0 && self.next_expiry_at.is_none_or(|deadline| now < deadline)
    }

    /// True when any active remote is in grace, expired, or past a transition
    /// deadline that leaves the fleet less than fully fresh.
    pub fn degraded(&self, now: Instant) -> bool {
        self.grace > 0
            || self.expired > 0
            || self.next_grace_at.is_some_and(|deadline| now >= deadline)
            || self.next_expiry_at.is_some_and(|deadline| now >= deadline)
    }

    pub fn store_count_for(&self, state: JwksTrustState) -> u64 {
        match state {
            JwksTrustState::Fresh => self.fresh,
            JwksTrustState::Grace => self.grace,
            JwksTrustState::Expired => self.expired,
        }
    }

    pub fn max_age_seconds_for(&self, state: JwksTrustState) -> u64 {
        match state {
            JwksTrustState::Fresh => self.max_age_seconds_fresh,
            JwksTrustState::Grace => self.max_age_seconds_grace,
            JwksTrustState::Expired => self.max_age_seconds_expired,
        }
    }

    fn project_ages(mut self, now: Instant) -> Self {
        let Some(observed_at) = self.age_observed_at else {
            return self;
        };
        let elapsed = now.saturating_duration_since(observed_at);
        if self.fresh > 0
            && let Some(age) = self.max_age_fresh_at_observation
        {
            self.max_age_seconds_fresh = age.saturating_add(elapsed).as_secs();
        }
        if self.grace > 0
            && let Some(age) = self.max_age_grace_at_observation
        {
            self.max_age_seconds_grace = age.saturating_add(elapsed).as_secs();
        }
        if self.expired > 0
            && let Some(age) = self.max_age_expired_at_observation
        {
            self.max_age_seconds_expired = age.saturating_add(elapsed).as_secs();
        }
        self
    }
}

/// Global, process-wide cache of JWKS key stores keyed by `jwks_uri`.
static JWKS_CACHE: OnceLock<Arc<DashMap<String, JwksCacheEntry>>> = OnceLock::new();
/// Last successfully resolved JWKS URI for each OIDC discovery URL. This map
/// stores only URI strings; key material remains owned by `JWKS_CACHE` and its
/// generation-aware reaper.
static DISCOVERED_JWKS_URIS: OnceLock<DashMap<String, String>> = OnceLock::new();
/// Exact requirement set of the last committed plugin generation.
static COMMITTED_REQUIREMENTS: OnceLock<arc_swap::ArcSwap<JwksRequirementMap>> = OnceLock::new();
/// Live [`LateActiveRequirement`] contributions from committed consumers whose
/// store resolved after their generation was published.
static LATE_ACTIVE_REQUIREMENTS: OnceLock<DashMap<u64, (String, JwksRefreshRequirement)>> =
    OnceLock::new();
static LATE_ACTIVE_REQUIREMENT_IDS: AtomicU64 = AtomicU64::new(0);
/// Precomputed active-remote trust aggregate for O(1) `/health` and `/status`.
static TRUST_HEALTH: OnceLock<arc_swap::ArcSwap<JwksTrustHealthAggregate>> = OnceLock::new();
/// Generation for the deadline-watcher task; bumping invalidates a stale
/// sleeper before its callback can republish.
static TRUST_HEALTH_WATCH_GENERATION: AtomicU64 = AtomicU64::new(0);

/// The one scheduled trust-health deadline watcher.
///
/// Refresh failures and authenticated metrics scrapes may republish health far
/// more frequently than the next grace/expiry transition. Retaining an
/// abortable handle prevents those publications from accumulating one detached
/// sleeper apiece until the deadline.
struct TrustHealthWatch {
    generation: u64,
    deadline: Instant,
    abort_handle: tokio::task::AbortHandle,
}

static TRUST_HEALTH_WATCH: OnceLock<Mutex<Option<TrustHealthWatch>>> = OnceLock::new();

fn trust_health_watch_slot() -> &'static Mutex<Option<TrustHealthWatch>> {
    TRUST_HEALTH_WATCH.get_or_init(|| Mutex::new(None))
}

fn trust_health_slot() -> &'static arc_swap::ArcSwap<JwksTrustHealthAggregate> {
    TRUST_HEALTH
        .get_or_init(|| arc_swap::ArcSwap::from_pointee(JwksTrustHealthAggregate::default()))
}

fn ensure_trust_health_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        register_trust_change_hook(republish_trust_health);
    });
}

fn global_cache() -> &'static Arc<DashMap<String, JwksCacheEntry>> {
    ensure_trust_health_hook();
    JWKS_CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

fn discovered_jwks_uris() -> &'static DashMap<String, String> {
    DISCOVERED_JWKS_URIS.get_or_init(DashMap::new)
}

fn committed_requirements_slot() -> &'static arc_swap::ArcSwap<JwksRequirementMap> {
    COMMITTED_REQUIREMENTS
        .get_or_init(|| arc_swap::ArcSwap::from_pointee(JwksRequirementMap::new()))
}

fn late_active_requirements() -> &'static DashMap<u64, (String, JwksRefreshRequirement)> {
    LATE_ACTIVE_REQUIREMENTS.get_or_init(DashMap::new)
}

/// One committed consumer's asynchronously discovered contribution to the
/// active requirement set.
///
/// Registered only by a consumer whose owning plugin generation has already
/// been committed, so a staged, rejected, canceled, or unpublished generation
/// never reaches readiness or metrics. Dropping the guard removes exactly this
/// contribution and reconciles, which is what retires the store when the owning
/// generation goes away. The registry is keyed by a monotonic id, so an
/// identical URI registered twice stays two independent contributions and the
/// registry is bounded by the live discovery-backed consumers.
#[derive(Debug)]
pub struct LateActiveRequirement {
    id: u64,
}

impl LateActiveRequirement {
    /// Publish this consumer's requirement immediately, without waiting for
    /// another configuration reload.
    pub fn register(jwks_uri: &str, requirement: JwksRefreshRequirement) -> Self {
        let id = LATE_ACTIVE_REQUIREMENT_IDS.fetch_add(1, Ordering::Relaxed);
        late_active_requirements().insert(id, (jwks_uri.to_string(), requirement));
        reconcile_active_requirements();
        Self { id }
    }

    /// Re-point this contribution at a replacement discovery result. Only this
    /// consumer moves; a co-tenant of either URI keeps its own contribution.
    pub fn replace(&self, jwks_uri: &str, requirement: JwksRefreshRequirement) {
        late_active_requirements().insert(self.id, (jwks_uri.to_string(), requirement));
        reconcile_active_requirements();
    }
}

impl Drop for LateActiveRequirement {
    fn drop(&mut self) {
        late_active_requirements().remove(&self.id);
        reconcile_active_requirements();
    }
}

/// Make one consumer's exact requirement active on the shared store now,
/// without waiting for another configuration reload.
///
/// Re-pointing an existing contribution moves only this consumer, so a
/// co-tenant of either the previous or the replacement URI keeps its own
/// strictness. Callers own the slot for the lifetime of their plugin
/// generation; a poisoned lock is recovered rather than panicking.
pub fn publish_late_active_requirement(
    slot: &std::sync::Mutex<Option<LateActiveRequirement>>,
    jwks_uri: &str,
    requirement: JwksRefreshRequirement,
) {
    let mut guard = match slot.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(existing) = guard.as_ref() {
        existing.replace(jwks_uri, requirement);
        return;
    }
    *guard = Some(LateActiveRequirement::register(jwks_uri, requirement));
}

/// Withdraw one consumer's contribution — plugin retirement, or a publication
/// this generation discarded. Removes only this consumer's entry.
pub fn clear_late_active_requirement(slot: &std::sync::Mutex<Option<LateActiveRequirement>>) {
    let mut guard = match slot.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    drop(guard.take());
}

/// Spawn a cache-maintenance task when a Tokio runtime is available.
///
/// Reconciliation runs from plugin `Drop` as well as from the runtime, and a
/// bare `tokio::spawn` panics off-runtime. Skipping the timer is safe for both
/// callers: the trust aggregate carries monotonic deadlines that
/// [`JwksTrustHealthAggregate::ready`] evaluates at read time, and a retired
/// entry is reaped by the next reconciliation instead.
fn spawn_cache_maintenance<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(future);
    }
}

/// O(1) snapshot of active remote JWKS trust health for `/health` and `/status`.
///
/// Readiness and degraded flags incorporate monotonic deadlines so expiry makes
/// the gateway not-ready even if the background republish task has not yet run.
pub fn trust_health_snapshot() -> JwksTrustHealthAggregate {
    ensure_trust_health_hook();
    trust_health_slot().load().project_ages(Instant::now())
}

/// Rebuild the precomputed active-remote trust aggregate and arm the next
/// deadline watcher. Never inspects URLs for output — only closed-set counts.
pub fn republish_trust_health() {
    ensure_trust_health_hook();
    let now = Instant::now();
    let mut aggregate = JwksTrustHealthAggregate {
        age_observed_at: Some(now),
        ..JwksTrustHealthAggregate::default()
    };
    let mut next_watch: Option<Instant> = None;

    if let Some(cache) = JWKS_CACHE.get() {
        for entry in cache.iter() {
            if !entry.value().active.load(Ordering::Acquire) {
                continue;
            }
            let store = &entry.value().store;
            if !store.is_refreshable() {
                continue;
            }
            let health = store.health_snapshot();
            match health.trust_state {
                JwksTrustState::Fresh => {
                    aggregate.fresh = aggregate.fresh.saturating_add(1);
                    if let Some(age) = health.last_success_age {
                        aggregate.max_age_fresh_at_observation = Some(
                            aggregate
                                .max_age_fresh_at_observation
                                .map_or(age, |current| current.max(age)),
                        );
                        aggregate.max_age_seconds_fresh =
                            aggregate.max_age_seconds_fresh.max(age.as_secs());
                    }
                }
                JwksTrustState::Grace => {
                    aggregate.grace = aggregate.grace.saturating_add(1);
                    if let Some(age) = health.last_success_age {
                        aggregate.max_age_grace_at_observation = Some(
                            aggregate
                                .max_age_grace_at_observation
                                .map_or(age, |current| current.max(age)),
                        );
                        aggregate.max_age_seconds_grace =
                            aggregate.max_age_seconds_grace.max(age.as_secs());
                    }
                }
                JwksTrustState::Expired => {
                    aggregate.expired = aggregate.expired.saturating_add(1);
                    if let Some(age) = health.last_success_age {
                        aggregate.max_age_expired_at_observation = Some(
                            aggregate
                                .max_age_expired_at_observation
                                .map_or(age, |current| current.max(age)),
                        );
                        aggregate.max_age_seconds_expired =
                            aggregate.max_age_seconds_expired.max(age.as_secs());
                    }
                }
            }
            if health.trust_state != JwksTrustState::Expired
                && let Some(deadline) = store.expiry_deadline()
            {
                aggregate.next_expiry_at = Some(
                    aggregate
                        .next_expiry_at
                        .map_or(deadline, |current| current.min(deadline)),
                );
                if deadline > now {
                    next_watch = Some(next_watch.map_or(deadline, |current| current.min(deadline)));
                }
            }
            if health.trust_state == JwksTrustState::Fresh
                && let Some(deadline) = store.grace_deadline()
            {
                aggregate.next_grace_at = Some(
                    aggregate
                        .next_grace_at
                        .map_or(deadline, |current| current.min(deadline)),
                );
                if deadline > now {
                    next_watch = Some(next_watch.map_or(deadline, |current| current.min(deadline)));
                }
            }
        }
    }

    trust_health_slot().store(Arc::new(aggregate));
    schedule_trust_health_watch(next_watch);
}

fn schedule_trust_health_watch(next_watch: Option<Instant>) {
    let mut scheduled = match trust_health_watch_slot().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let Some(deadline) = next_watch else {
        let stale = scheduled.take();
        TRUST_HEALTH_WATCH_GENERATION.fetch_add(1, Ordering::AcqRel);
        drop(scheduled);
        if let Some(stale) = stale {
            stale.abort_handle.abort();
        }
        return;
    };

    // An already scheduled earlier transition is sufficient. When it fires it
    // republishes from live store state and arms whatever later deadline is
    // still relevant. This also makes identical high-frequency publications
    // allocation/task neutral.
    if scheduled
        .as_ref()
        .is_some_and(|current| current.deadline <= deadline)
    {
        return;
    }

    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        // Drop/teardown may reconcile off-runtime. Preserve an existing later
        // watcher rather than aborting it without a replacement; readiness
        // still evaluates monotonic deadlines directly at read time.
        return;
    };

    let generation = TRUST_HEALTH_WATCH_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    // Hold the new task behind a one-shot barrier until its abort handle is
    // installed in the singleton slot, avoiding a near-deadline startup race.
    let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
    let task = runtime.spawn(async move {
        if start_rx.await.is_err() {
            return;
        }
        tokio::time::sleep_until(deadline).await;
        if TRUST_HEALTH_WATCH_GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        let should_republish = {
            let mut scheduled = match trust_health_watch_slot().lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if scheduled
                .as_ref()
                .is_some_and(|current| current.generation == generation)
            {
                scheduled.take();
                true
            } else {
                false
            }
        };
        if should_republish {
            republish_trust_health();
        }
    });
    let abort_handle = task.abort_handle();
    drop(task);
    let stale = scheduled.replace(TrustHealthWatch {
        generation,
        deadline,
        abort_handle,
    });
    drop(scheduled);
    if let Some(stale) = stale {
        stale.abort_handle.abort();
    }
    let _ = start_tx.send(());
}

/// Current watcher generation for external regression tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn trust_health_watch_generation_for_test() -> u64 {
    TRUST_HEALTH_WATCH_GENERATION.load(Ordering::Acquire)
}

/// Get or create a shared [`JwksKeyStore`] for the given JWKS URI.
///
/// If a store already exists for this URI (created by another plugin instance
/// or another provider), the existing store is returned — no duplicate fetch
/// or background refresh task is spawned.
///
/// On first creation the store starts a single shared background refresh task.
/// That task performs the initial fetch and then continues periodic refreshes.
pub fn get_or_create_jwks_store(
    jwks_uri: &str,
    http_client: &PluginHttpClient,
    refresh_interval: Duration,
    max_stale: Duration,
) -> Arc<JwksKeyStore> {
    let cache = global_cache();
    let requested = JwksRefreshRequirement::new(refresh_interval, max_stale);

    // Fast path: store already exists. A newly observed stricter interval or
    // maximum-stale requirement takes effect immediately; relaxation is
    // applied only when the committed generation is reconciled, because
    // another active consumer may still require the stricter policy.
    if let Some(mut entry) = cache.get_mut(jwks_uri) {
        // A new consumer revives an entry that may have been marked retired by
        // a concurrent plugin-cache publication. Bumping the epoch invalidates
        // any pending last-owner reaper before cloning the store.
        entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
        let strictest = entry.requirement.strictest(requested);
        let policy_changed = strictest != entry.requirement;
        if policy_changed {
            reconfigure_refresh_policy(jwks_uri, entry.value_mut(), strictest);
        }
        let store = Arc::clone(&entry.value().store);
        drop(entry);
        if policy_changed {
            // Never republish while the get_mut guard above is held.
            republish_trust_health();
        }
        return store;
    }

    // Slow path: create new store (DashMap entry API handles races)
    let mut inserted = false;
    let mut entry = cache.entry(jwks_uri.to_string()).or_insert_with(|| {
        inserted = true;
        info!(
            "JWKS cache: creating shared store for {}",
            redacted_jwks_uri(jwks_uri)
        );
        let store = JwksKeyStore::new(jwks_uri.to_string(), http_client.clone());
        store.configure_trust_policy(refresh_interval, max_stale);
        let refresh_handle = store.start_background_refresh(refresh_interval);
        JwksCacheEntry {
            store: Arc::new(store),
            refresh_handle,
            requirement: requested,
            refresh_generation: 1,
            retirement_epoch: Arc::new(AtomicU64::new(0)),
            active: AtomicBool::new(false),
            reaper_generation: AtomicU64::new(0),
        }
    });
    entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
    let strictest = entry.requirement.strictest(requested);
    let policy_changed = strictest != entry.requirement;
    if policy_changed {
        reconfigure_refresh_policy(jwks_uri, entry.value_mut(), strictest);
    }
    let store = entry.value().store.clone();
    drop(entry);
    if inserted || policy_changed {
        // Never republish while the entry guard above is held.
        republish_trust_health();
    }
    store
}

/// Update the entry's effective policy and replace its refresh worker.
///
/// Caller must hold a mutable cache entry (or be inside `retain`) and must
/// call [`republish_trust_health`] only after that guard is released.
/// Publishing here would iterate the same `DashMap` under the held shard.
fn reconfigure_refresh_policy(
    jwks_uri: &str,
    entry: &mut JwksCacheEntry,
    requirement: JwksRefreshRequirement,
) {
    if entry.requirement == requirement {
        return;
    }
    if tokio::runtime::Handle::try_current().is_err() {
        // Reconciliation also runs from plugin `Drop`, which may land on a
        // non-runtime thread at teardown. Replacing the worker there would
        // panic in `tokio::spawn`, and aborting it without a replacement would
        // stop refreshes entirely, so keep the current policy and worker and
        // let the next on-runtime reconciliation apply the change. Every
        // consumer that could construct a store did so on a runtime, so this
        // is a teardown path; active-flag reconciliation still proceeds.
        return;
    }
    let previous = entry.requirement;
    entry
        .store
        .configure_trust_policy(requirement.refresh_interval, requirement.max_stale);
    entry.refresh_handle.abort();
    entry.refresh_handle = entry
        .store
        .start_background_refresh_after_policy_change(requirement.refresh_interval);
    entry.requirement = requirement;
    entry.refresh_generation = entry.refresh_generation.wrapping_add(1);
    info!(
        "JWKS cache: policy for {} changed from refresh={:?}/max-stale={:?} to refresh={:?}/max-stale={:?}",
        redacted_jwks_uri(jwks_uri),
        previous.refresh_interval,
        previous.max_stale,
        requirement.refresh_interval,
        requirement.max_stale
    );
}

/// Install the exact strictest requirement of the newly committed plugin
/// generation, then reconcile the shared cache against the full active union.
///
/// Trust-health republication runs only after `retain` returns so it never
/// iterates the map under the retain shard guard.
pub fn retain_active_requirements(active_requirements: &HashMap<String, JwksRefreshRequirement>) {
    committed_requirements_slot().store(Arc::new(active_requirements.clone()));
    reconcile_active_requirements();
}

/// Recompute the active set as `committed generation ∪ late contributions` and
/// apply it to the shared cache.
///
/// Every mutation path funnels through here, so relaxation of a shared store
/// happens only once *every* stricter committed consumer — published or
/// asynchronously discovered — is gone.
fn reconcile_active_requirements() {
    let mut effective: JwksRequirementMap = (**committed_requirements_slot().load()).clone();
    if let Some(late) = LATE_ACTIVE_REQUIREMENTS.get() {
        for entry in late.iter() {
            let (uri, requirement) = entry.value();
            effective
                .entry(uri.clone())
                .and_modify(|current| *current = current.strictest(*requirement))
                .or_insert(*requirement);
        }
    }

    let cache = global_cache();
    cache.retain(|uri, entry| {
        if let Some(requirement) = effective.get(uri) {
            entry.active.store(true, Ordering::Release);
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            reconfigure_refresh_policy(uri, entry, *requirement);
            true
        } else {
            entry.active.store(false, Ordering::Release);
            retain_retired_entry(uri, entry)
        }
    });
    republish_trust_health();
}

/// Remove JWKS cache entries whose URIs are not in `active_uris`.
///
/// Lower-level test-only helper: it decides activity from a bare URI set and
/// deliberately ignores both the committed requirement map and late
/// contributions. Production reconciliation goes through
/// [`retain_active_requirements`] / [`reconcile_active_requirements`].
///
/// Aborts the background refresh task for each removed entry so leaked tokio
/// tasks don't accumulate across config reloads. Stores still owned by a
/// retired plugin generation are reaped after their final external owner
/// drops. External unit tests use this lower-level helper to exercise
/// retirement independently from refresh-interval reconciliation.
#[allow(dead_code)] // exercised by external unit tests
pub fn retain_active_uris(active_uris: &HashSet<String>) {
    let cache = global_cache();
    cache.retain(|uri, entry| {
        if active_uris.contains(uri) {
            // Cancel a reaper scheduled by an older publication if this URI is
            // active again in the newly committed plugin generation.
            entry.active.store(true, Ordering::Release);
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            true
        } else {
            entry.active.store(false, Ordering::Release);
            retain_retired_entry(uri, entry)
        }
    });
    republish_trust_health();
}

fn retain_retired_entry(uri: &str, entry: &JwksCacheEntry) -> bool {
    if Arc::strong_count(&entry.store) > 1 {
        // Keep refreshes alive while an old plugin generation, an in-flight
        // request, or an asynchronously publishing discovery worker still
        // owns the store. The epoch-bound reaper removes it promptly after
        // the cache becomes the final owner, without requiring another
        // configuration reload.
        schedule_retired_store_reaper(uri.to_string(), entry);
        true
    } else {
        info!(
            "JWKS cache: removing stale store for {}",
            redacted_jwks_uri(uri)
        );
        entry.refresh_handle.abort();
        forget_discovered_jwks_uri(uri);
        false
    }
}

fn schedule_retired_store_reaper(uri: String, entry: &JwksCacheEntry) {
    let retirement_epoch = Arc::clone(&entry.retirement_epoch);
    let epoch = retirement_epoch
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    entry.reaper_generation.fetch_add(1, Ordering::AcqRel);
    let store = Arc::downgrade(&entry.store);
    let cache = Arc::clone(global_cache());

    spawn_cache_maintenance(async move {
        loop {
            tokio::time::sleep(RETIRED_STORE_REAP_INTERVAL).await;
            if retirement_epoch.load(Ordering::Acquire) != epoch {
                return;
            }
            if store.strong_count() > 1 {
                continue;
            }

            if let Some((_, stale)) = cache.remove_if(&uri, |_, current| {
                Arc::ptr_eq(&current.retirement_epoch, &retirement_epoch)
                    && retirement_epoch.load(Ordering::Acquire) == epoch
                    && !current.active.load(Ordering::Acquire)
                    && Arc::strong_count(&current.store) == 1
            }) {
                info!(
                    "JWKS cache: removing retired store for {}",
                    redacted_jwks_uri(&uri)
                );
                stale.refresh_handle.abort();
                forget_discovered_jwks_uri(&uri);
                republish_trust_health();
            }
            return;
        }
    });
}

/// A provisional discovery acquisition. Dropping it before the caller has
/// published or explicitly retired the candidate releases its store reference
/// first, then retires a cache entry that has no committed owner. This makes
/// task cancellation safe at every await point after acquisition.
pub(crate) struct DiscoveryStoreCandidate {
    jwks_uri: String,
    store: Option<Arc<JwksKeyStore>>,
}

impl DiscoveryStoreCandidate {
    pub(crate) fn acquire(
        jwks_uri: &str,
        http_client: &PluginHttpClient,
        refresh_interval: Duration,
        max_stale: Duration,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.to_string(),
            store: Some(get_or_create_jwks_store(
                jwks_uri,
                http_client,
                refresh_interval,
                max_stale,
            )),
        }
    }

    pub(crate) fn store(&self) -> Option<&Arc<JwksKeyStore>> {
        self.store.as_ref()
    }

    pub(crate) fn publish(&mut self) {
        drop(self.store.take());
    }
}

impl Drop for DiscoveryStoreCandidate {
    fn drop(&mut self) {
        let store = self.store.take();
        if store.is_none() {
            return;
        }
        drop(store);
        retire_jwks_store_if_unreferenced(&self.jwks_uri);
    }
}

/// Record a validated discovery result so an equivalent replacement plugin
/// generation can acquire the last-good store synchronously before rediscovery.
pub fn remember_discovered_jwks_uri(discovery_url: &str, jwks_uri: &str) {
    discovered_jwks_uris().insert(discovery_url.to_string(), jwks_uri.to_string());
}

/// Return the last validated JWKS URI for a discovery endpoint.
pub fn last_discovered_jwks_uri(discovery_url: &str) -> Option<String> {
    discovered_jwks_uris()
        .get(discovery_url)
        .map(|entry| entry.value().clone())
}

fn forget_discovered_jwks_uri(jwks_uri: &str) {
    if let Some(discoveries) = DISCOVERED_JWKS_URIS.get() {
        discoveries.retain(|_, resolved_uri| resolved_uri != jwks_uri);
    }
}

/// Retire a superseded or rejected discovery store. A sole-owner cache entry
/// is removed immediately; transient owners keep it alive until the epoch-bound
/// reaper can remove it safely. A URI retained by the committed plugin
/// generation is marked active and never gets a retirement reaper; transient
/// owners keep the reaper alive until their last reference drops.
pub fn retire_jwks_store_if_unreferenced(jwks_uri: &str) {
    let cache = global_cache();
    if let Some(entry) = cache.get(jwks_uri) {
        if entry.active.load(Ordering::Acquire) {
            return;
        }
        if Arc::strong_count(&entry.store) > 1 {
            // A prior plugin generation or in-flight authentication still owns
            // this superseded store. Reuse the epoch-bound reaper so its refresh
            // task stops as soon as those transient owners finish; a concurrent
            // active consumer revives the epoch and cancels this retirement.
            schedule_retired_store_reaper(jwks_uri.to_string(), entry.value());
            return;
        }
    }
    if let Some((_, stale)) = cache.remove_if(jwks_uri, |_, entry| {
        !entry.active.load(Ordering::Acquire) && Arc::strong_count(&entry.store) == 1
    }) {
        info!(
            "JWKS cache: removing superseded discovery store for {}",
            redacted_jwks_uri(jwks_uri)
        );
        stale.refresh_handle.abort();
        forget_discovered_jwks_uri(jwks_uri);
        republish_trust_health();
    }
}

/// Return the current interval and task generation for diagnostics and tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn cached_refresh_state(jwks_uri: &str) -> Option<(Duration, u64)> {
    global_cache().get(jwks_uri).map(|entry| {
        (
            entry.value().requirement.refresh_interval,
            entry.value().refresh_generation,
        )
    })
}

/// Return the current strict shared-store policy for diagnostics and tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn cached_requirement(jwks_uri: &str) -> Option<JwksRefreshRequirement> {
    global_cache()
        .get(jwks_uri)
        .map(|entry| entry.value().requirement)
}

/// Render fixed-cardinality JWKS trust and refresh observability.
///
/// Stores are aggregated by closed state/failure enums; endpoint URLs, key
/// identifiers, tokens, claims, and key material never enter this surface.
pub fn render_prometheus() -> String {
    // Keep metrics aligned with the readiness aggregate (active remotes only).
    republish_trust_health();
    let health = trust_health_snapshot();
    let mut max_consecutive_failures = [0u64; 6];

    if let Some(cache) = JWKS_CACHE.get() {
        for entry in cache.iter() {
            if !entry.value().active.load(Ordering::Acquire) {
                continue;
            }
            let snapshot = entry.value().store.health_snapshot();
            if let Some(class) = snapshot.last_failure {
                let class_index = class.index();
                max_consecutive_failures[class_index] = max_consecutive_failures[class_index]
                    .max(u64::from(snapshot.consecutive_failures));
            }
        }
    }

    let mut output = String::new();
    output.push_str(
        "# HELP ferrum_jwks_trust_stores Active remote JWKS stores by bounded trust state.\n",
    );
    output.push_str("# TYPE ferrum_jwks_trust_stores gauge\n");
    output.push_str(
        "# HELP ferrum_jwks_trust_age_seconds Maximum age of the last validated non-empty JWKS among active remote stores in each trust state.\n",
    );
    output.push_str("# TYPE ferrum_jwks_trust_age_seconds gauge\n");
    for state in JwksTrustState::ALL {
        let _ = writeln!(
            output,
            "ferrum_jwks_trust_stores{{state=\"{}\"}} {}",
            state.as_str(),
            health.store_count_for(state)
        );
        let _ = writeln!(
            output,
            "ferrum_jwks_trust_age_seconds{{state=\"{}\"}} {}",
            state.as_str(),
            health.max_age_seconds_for(state)
        );
    }

    output.push_str(
        "# HELP ferrum_jwks_refresh_failures_total Remote JWKS refresh failures by fixed failure class.\n",
    );
    output.push_str("# TYPE ferrum_jwks_refresh_failures_total counter\n");
    output.push_str(
        "# HELP ferrum_jwks_consecutive_failures Maximum current consecutive failures among active remote stores by fixed failure class.\n",
    );
    output.push_str("# TYPE ferrum_jwks_consecutive_failures gauge\n");
    let failure_counts = JwksKeyStore::refresh_failure_counts();
    for (index, class) in JwksFailureClass::ALL.iter().enumerate() {
        let _ = writeln!(
            output,
            "ferrum_jwks_refresh_failures_total{{class=\"{}\"}} {}",
            class.as_str(),
            failure_counts[index]
        );
        let _ = writeln!(
            output,
            "ferrum_jwks_consecutive_failures{{class=\"{}\"}} {}",
            class.as_str(),
            max_consecutive_failures[index]
        );
    }
    output
}

/// Return reaper-scheduling state for lifecycle tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn cached_reaper_generation(jwks_uri: &str) -> Option<u64> {
    global_cache()
        .get(jwks_uri)
        .map(|entry| entry.value().reaper_generation.load(Ordering::Acquire))
}

/// Clear the global JWKS cache. Used in tests to isolate state between runs.
#[allow(dead_code)]
pub fn clear_jwks_cache() {
    if let Some(cache) = JWKS_CACHE.get() {
        // Abort all background refresh tasks before clearing
        for entry in cache.iter() {
            entry.value().refresh_handle.abort();
        }
        cache.clear();
    }
    if let Some(discoveries) = DISCOVERED_JWKS_URIS.get() {
        discoveries.clear();
    }
    // Drop both contributors so a later test starts from an empty active set.
    // Outstanding `LateActiveRequirement` guards still remove their own id on
    // drop; the removal is simply a no-op after this clear.
    if let Some(late) = LATE_ACTIVE_REQUIREMENTS.get() {
        late.clear();
    }
    committed_requirements_slot().store(Arc::new(JwksRequirementMap::new()));
    republish_trust_health();
}
