//! Service-discovery task lifecycle and staleness health (issues #3717/#3721).
//!
//! Holds one bounded entry per *running* discovery task, keyed by the same
//! `namespace|upstream_id` ownership key the manager uses. Cardinality is
//! therefore exactly the number of configured service-discovery upstreams:
//! entries are created when a task starts and removed when its generation is
//! superseded or stopped, so a flapping registry cannot grow this map.
//!
//! Two consumers read it:
//!
//! * authenticated `/health` and `/status` — aggregate **plus** per-upstream
//!   detail (upstream identity is operator-configured, so it never reaches the
//!   unauthenticated tier);
//! * `/metrics` — fixed-cardinality process aggregates only. Upstream ids are
//!   never Prometheus labels.
//!
//! Every diagnostic here is a count, an age, or a closed-set reason token.
//! Registry URLs, Consul tokens, Kubernetes bearer tokens, response bodies, and
//! provider error strings never enter this module.

use std::sync::OnceLock;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::Serialize;
use tokio::time::Instant;

use crate::config::env_config::DiscoveryStalenessPolicy;
use crate::config::types::SdStalePolicy;

/// Consecutive unexpected exits (panic / early return) after which a task is
/// reported as crash-looping. The supervisor keeps retrying at the capped
/// backoff — the state exists so repeated crashes surface as a degraded signal
/// instead of an invisible hot loop.
pub const DISCOVERY_CRASH_LOOP_THRESHOLD: u64 = 3;

/// Multiple of the poll interval below which a configured staleness window is
/// floored. A window shorter than a couple of healthy poll cycles would report
/// permanent staleness on a slow-polling provider.
pub const DISCOVERY_MIN_STALE_POLL_INTERVALS: u64 = 3;

/// Lifecycle state of one supervised discovery task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryTaskState {
    /// Spawned; no poll outcome observed yet.
    Starting,
    /// Poller running normally.
    Running,
    /// Poller exited unexpectedly and the supervisor is waiting out its backoff.
    Restarting,
    /// Repeated unexpected exits without an intervening successful snapshot.
    CrashLooping,
    /// Cleanly canceled or shut down; retained only until the manager removes it.
    Stopped,
}

impl DiscoveryTaskState {
    /// Fixed-cardinality label for logs, status output, and metrics buckets.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Restarting => "restarting",
            Self::CrashLooping => "crash_looping",
            Self::Stopped => "stopped",
        }
    }
}

/// Closed-set failure reasons. Never derived from provider payloads or URLs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryFailureReason {
    /// `ServiceDiscoverer::discover()` returned an error.
    DiscoverFailed,
    /// The snapshot parsed but was refused by shared/atomic admission.
    SnapshotRejected,
    /// Admitted targets could not be published into the load balancer.
    PublishFailed,
    /// The poller task exited unexpectedly (panic or early return).
    TaskExited,
}

impl DiscoveryFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiscoverFailed => "discover_failed",
            Self::SnapshotRejected => "snapshot_rejected",
            Self::PublishFailed => "publish_failed",
            Self::TaskExited => "task_exited",
        }
    }
}

/// Resolved staleness bound for one task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryStaleness {
    /// `None` means unbounded last-known retention (explicit unsafe opt-in).
    pub max_stale: Option<Duration>,
    pub policy: SdStalePolicy,
}

impl DiscoveryStaleness {
    /// Unbounded retention — legacy behavior, only reachable via opt-in.
    pub const fn unbounded(policy: SdStalePolicy) -> Self {
        Self {
            max_stale: None,
            policy,
        }
    }

    /// Seconds for status output; `0` reports unbounded.
    pub fn max_stale_seconds(self) -> u64 {
        self.max_stale.map(|d| d.as_secs()).unwrap_or(0)
    }
}

#[derive(Debug)]
struct TaskHealth {
    generation: u64,
    state: DiscoveryTaskState,
    provider: &'static str,
    staleness: DiscoveryStaleness,
    /// Monotonic task start; the staleness anchor until the first success.
    started_at: Instant,
    /// Last successfully admitted **and** published (or confirmed) snapshot.
    last_success_at: Option<Instant>,
    consecutive_failures: u64,
    consecutive_crashes: u64,
    restarts: u64,
    last_error: Option<DiscoveryFailureReason>,
    /// Whether the expiry action for the current stale episode has already run.
    /// Suppresses the staleness timer so an expired task cannot hot-loop, and
    /// is cleared by the next successfully published snapshot.
    expiry_applied: bool,
    /// Whether discovered targets are currently withdrawn by the expiry policy.
    /// Always `false` under [`SdStalePolicy::Retain`].
    withdrawn: bool,
    /// Next bounded retry after a failed withdrawal publication. Leaving an
    /// expired deadline armed directly would hot-loop, while marking the
    /// expiry applied would retain stale dynamic targets forever.
    expiry_retry_at: Option<Instant>,
    expiry_retry_attempts: u64,
}

impl TaskHealth {
    /// Age of the staleness anchor: the last published snapshot, or task start
    /// when none has ever been admitted.
    fn anchor_age(&self, now: Instant) -> Duration {
        let anchor = self.last_success_at.unwrap_or(self.started_at);
        now.saturating_duration_since(anchor)
    }

    fn is_stale(&self, now: Instant) -> bool {
        self.staleness
            .max_stale
            .is_some_and(|max| self.anchor_age(now) >= max)
    }
}

/// Per-upstream lifecycle detail for authenticated `/health` and `/status`.
///
/// `upstream` is the operator-configured `namespace|id` ownership key. It is
/// deliberately absent from `/metrics` and from the unauthenticated health tier.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiscoveryTaskStatus {
    pub upstream: String,
    pub provider: &'static str,
    pub state: &'static str,
    pub stale: bool,
    pub withdrawn: bool,
    pub policy: &'static str,
    /// Effective staleness bound; `0` reports unbounded retention.
    pub max_stale_seconds: u64,
    /// Age of the last successfully admitted and published snapshot. `null`
    /// when the task has never published one.
    pub last_success_age_seconds: Option<u64>,
    /// Age of the current staleness anchor (task start when never successful).
    pub anchor_age_seconds: u64,
    pub consecutive_failures: u64,
    pub consecutive_crashes: u64,
    pub restarts: u64,
    pub last_error: Option<&'static str>,
}

/// Fixed-cardinality process aggregate of discovery task health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DiscoveryHealthAggregate {
    pub tasks: u64,
    pub running: u64,
    pub restarting: u64,
    pub crash_looping: u64,
    pub stale: u64,
    pub withdrawn: u64,
    /// Stale tasks whose policy requires failed readiness, including a
    /// `withdraw` task whose withdrawal has not yet published successfully.
    pub readiness_failing: u64,
    /// Tasks that have never published an admitted snapshot.
    pub never_succeeded: u64,
    /// Maximum staleness-anchor age across tasks, in seconds.
    pub max_anchor_age_seconds: u64,
}

impl DiscoveryHealthAggregate {
    /// Readiness fails under the explicit `fail_readiness` policy and while a
    /// fail-closed withdrawal has not yet published successfully.
    ///
    /// A crash-looping or stale task under `retain` degrades coarse health but
    /// stays ready. A successfully applied `withdraw` also stays ready because
    /// the unsafe routes are gone; publication failure is not allowed to make
    /// that assumption.
    pub fn ready(&self) -> bool {
        self.readiness_failing == 0
    }

    /// Any lifecycle or staleness condition an operator should see.
    pub fn degraded(&self) -> bool {
        self.restarting > 0
            || self.crash_looping > 0
            || self.stale > 0
            || self.withdrawn > 0
            || self.readiness_failing > 0
    }
}

/// Full authenticated projection: aggregate plus per-upstream detail.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DiscoveryHealthSnapshot {
    #[serde(flatten)]
    pub aggregate: DiscoveryHealthAggregate,
    pub upstreams: Vec<DiscoveryTaskStatus>,
}

static INSTALLED_STALENESS_POLICY: OnceLock<DiscoveryStalenessPolicy> = OnceLock::new();
static STALENESS_POLICY_OVERRIDE: std::sync::RwLock<Option<DiscoveryStalenessPolicy>> =
    std::sync::RwLock::new(None);

/// Install the process-wide discovery staleness policy from the accepted
/// `EnvConfig` snapshot, before any mode can start a poller.
///
/// Identical reinstall is accepted; a conflicting value fails closed so the
/// runtime policy cannot diverge from the parsed configuration.
pub fn install_discovery_staleness_policy(policy: DiscoveryStalenessPolicy) -> Result<(), String> {
    crate::config::env_config::parse_discovery_staleness_policy(
        Some(&policy.max_stale_seconds.to_string()),
        Some(policy.policy.as_str()),
        Some(if policy.allow_unbounded {
            "true"
        } else {
            "false"
        }),
    )?;
    match INSTALLED_STALENESS_POLICY.set(policy) {
        Ok(()) => Ok(()),
        Err(_) => match INSTALLED_STALENESS_POLICY.get() {
            Some(existing) if *existing == policy => Ok(()),
            Some(_) => Err(
                "service discovery staleness policy is already installed with a different \
                 value for this process"
                    .to_string(),
            ),
            None => Err(
                "service discovery staleness policy install raced and left no installed value"
                    .to_string(),
            ),
        },
    }
}

/// Effective process staleness policy: test override → installed snapshot →
/// bounded defaults.
pub fn effective_discovery_staleness_policy() -> DiscoveryStalenessPolicy {
    if let Ok(guard) = STALENESS_POLICY_OVERRIDE.read()
        && let Some(policy) = *guard
    {
        return policy;
    }
    INSTALLED_STALENESS_POLICY
        .get()
        .copied()
        .unwrap_or_else(DiscoveryStalenessPolicy::defaults)
}

/// Test-only override of the process staleness policy. `None` clears it.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn override_discovery_staleness_policy_for_test(policy: Option<DiscoveryStalenessPolicy>) {
    if let Ok(mut guard) = STALENESS_POLICY_OVERRIDE.write() {
        *guard = policy;
    }
}

/// Resolved staleness bound for one upstream, plus whether an unsafe unbounded
/// request had to be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedUpstreamStaleness {
    /// Effective bound and expiry policy for the task.
    pub staleness: DiscoveryStaleness,
    /// The upstream asked for unbounded retention (`max_stale_seconds: 0`)
    /// without the process opt-in, so the bounded default was applied instead.
    pub unbounded_request_refused: bool,
}

/// Resolve the effective staleness bound for one upstream, applying the
/// per-upstream override when present and the unsafe unbounded opt-in gate.
///
/// A per-upstream `max_stale_seconds: 0` without
/// `FERRUM_SERVICE_DISCOVERY_ALLOW_UNBOUNDED_STALE=true` is refused in favor of
/// the bounded process default: an unbounded window must never be reachable by
/// editing one upstream's row.
///
/// The refusal is *reported*, never logged here. This function runs from
/// `DiscoveryTaskSpec::build`, which reconcile calls for every discovery-backed
/// upstream on every config change — warning from inside it would repeat the
/// same operator message for unrelated config churn, forever. The manager emits
/// the warning once when it starts the task generation carrying the refused
/// request instead, so the message is bounded to one per active occurrence of
/// the condition and reappears only if the upstream is corrected (or removed)
/// and the invalid request is later reintroduced.
pub fn resolve_upstream_staleness(
    configured: Option<u64>,
    policy_override: Option<SdStalePolicy>,
    poll_interval_seconds: u64,
) -> ResolvedUpstreamStaleness {
    let process = effective_discovery_staleness_policy();
    let policy = policy_override.unwrap_or(process.policy);
    let unbounded_request_refused = configured == Some(0) && !process.allow_unbounded;
    let seconds = match configured {
        Some(0) if !process.allow_unbounded => process.max_stale_seconds,
        Some(configured) => configured,
        None => process.max_stale_seconds,
    };
    ResolvedUpstreamStaleness {
        staleness: resolve_staleness(seconds, policy, poll_interval_seconds),
        unbounded_request_refused,
    }
}

static REGISTRY: OnceLock<DashMap<String, TaskHealth>> = OnceLock::new();
static COARSE_AGGREGATE: OnceLock<ArcSwap<DiscoveryHealthAggregate>> = OnceLock::new();
static COARSE_AGGREGATE_REFRESH: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn registry() -> &'static DashMap<String, TaskHealth> {
    REGISTRY.get_or_init(DashMap::new)
}

fn coarse_aggregate_cache() -> &'static ArcSwap<DiscoveryHealthAggregate> {
    COARSE_AGGREGATE.get_or_init(|| ArcSwap::from_pointee(DiscoveryHealthAggregate::default()))
}

/// Mutate the entry for `key` only when it still owns `generation`.
///
/// This is the fence that keeps a superseded supervisor from publishing health
/// (or restarting) after a reconcile replaced it.
fn with_current<R>(key: &str, generation: u64, f: impl FnOnce(&mut TaskHealth) -> R) -> Option<R> {
    let mut entry = registry().get_mut(key)?;
    if entry.generation != generation {
        return None;
    }
    Some(f(entry.value_mut()))
}

/// Outcome of a generation-fenced publication attempt.
pub(crate) enum FencedPublish<T> {
    /// The generation still owned the key, so the publication closure ran.
    Published(T),
    /// The generation was superseded (or its entry already removed). The
    /// publication closure never ran.
    Superseded,
}

impl<T> FencedPublish<T> {
    /// `None` when the generation was superseded.
    #[allow(dead_code)] // reached from the external test crate; dead in the bin target
    pub(crate) fn published(self) -> Option<T> {
        match self {
            Self::Published(value) => Some(value),
            Self::Superseded => None,
        }
    }
}

/// Run `publish` only while `generation` still owns `key`, holding this key's
/// registry shard guard across the whole check-and-publish window.
///
/// This is the publication fence. [`register_task`] installs a replacement
/// generation through `DashMap::insert`, which must take the **same** shard
/// write lock, so a reconcile either completes before the ownership check here
/// (and `publish` never runs) or blocks until after the publication finished.
/// A bare [`generation_is_current`] call followed by a publication would leave
/// exactly that window open, letting a superseded task overwrite the
/// replacement's load-balancer / request-epoch state.
///
/// Contract for `publish`:
///
/// * synchronous — never `.await` while the shard guard is held;
/// * must not call back into this module (a re-entrant registry access on the
///   same shard would deadlock, and an aggregate recompute walks every shard);
/// * bounded — other keys hashing to this shard block for its duration.
///
/// Lock order is registry shard → publication locks (request-epoch write lock,
/// load-balancer/health-check maps). Nothing in those paths reads this
/// registry, so the order cannot invert.
pub(crate) fn publish_if_current<T>(
    key: &str,
    generation: u64,
    publish: impl FnOnce() -> T,
) -> FencedPublish<T> {
    let Some(entry) = registry().get_mut(key) else {
        return FencedPublish::Superseded;
    };
    if entry.generation != generation {
        return FencedPublish::Superseded;
    }
    let result = publish();
    // Explicit: the shard guard must outlive `publish()`, which is the whole
    // point of the fence.
    drop(entry);
    FencedPublish::Published(result)
}

/// What the caller's withdrawal closure did inside the fence.
pub(crate) enum WithdrawalAttempt<E> {
    /// Static-only targets were installed over the discovered set.
    Published,
    /// Installation was attempted and failed; discovered targets remain.
    Failed(E),
    /// Cancellation or global shutdown was observed inside the fence,
    /// immediately before the routing mutation, so nothing was written.
    Aborted,
}

/// Outcome of a fenced staleness withdrawal for a still-current generation.
pub(crate) enum FencedWithdrawal<E> {
    /// Static-only targets were installed. `claimed` is whether this call
    /// claimed the expiry episode (exactly one claim per episode).
    Published { claimed: bool },
    /// The installation failed; the episode stays unclaimed so the caller can
    /// keep failing closed and retry.
    Failed(E),
    /// A lifecycle signal won inside the fence: nothing published, nothing
    /// claimed, nothing to retry.
    Aborted,
}

/// Publish a staleness withdrawal and claim its expiry episode under one fence.
///
/// Returns what the closure did plus whether this call claimed the episode, so
/// the caller keeps emitting exactly one operator warning and one metric per
/// episode. Claiming inside the fence keeps a superseded generation from
/// consuming the replacement's episode, and gives the static-only
/// republication the same anti-race guarantee as [`publish_if_current`].
///
/// The closure decides *inside* the fence whether the withdrawal may still be
/// written at all: a task canceled (or a gateway shut down) after the staleness
/// timer fired must neither install static-only targets nor consume the
/// episode, and a [`WithdrawalAttempt::Aborted`] result is not a publication
/// failure — see [`FencedWithdrawal`].
pub(crate) fn publish_withdrawal_if_current<E>(
    key: &str,
    generation: u64,
    publish: impl FnOnce() -> WithdrawalAttempt<E>,
) -> FencedPublish<FencedWithdrawal<E>> {
    let outcome;
    let claimed;
    {
        let Some(mut entry) = registry().get_mut(key) else {
            return FencedPublish::Superseded;
        };
        if entry.generation != generation {
            return FencedPublish::Superseded;
        }
        match publish() {
            WithdrawalAttempt::Published => {
                claimed = !entry.expiry_applied;
                if claimed {
                    entry.expiry_applied = true;
                    entry.withdrawn = true;
                    entry.expiry_retry_at = None;
                    entry.expiry_retry_attempts = 0;
                }
                outcome = FencedWithdrawal::Published { claimed };
            }
            WithdrawalAttempt::Failed(error) => {
                claimed = false;
                outcome = FencedWithdrawal::Failed(error);
            }
            WithdrawalAttempt::Aborted => {
                claimed = false;
                outcome = FencedWithdrawal::Aborted;
            }
        }
    }
    if claimed {
        // Never inside the fence: the recompute walks every shard.
        refresh_coarse_aggregate();
    }
    FencedPublish::Published(outcome)
}

/// Register (or replace) the health entry for a newly started task generation.
pub(crate) fn register_task(
    key: &str,
    generation: u64,
    provider: &'static str,
    staleness: DiscoveryStaleness,
) {
    registry().insert(
        key.to_string(),
        TaskHealth {
            generation,
            state: DiscoveryTaskState::Starting,
            provider,
            staleness,
            started_at: Instant::now(),
            last_success_at: None,
            consecutive_failures: 0,
            consecutive_crashes: 0,
            restarts: 0,
            last_error: None,
            expiry_applied: false,
            withdrawn: false,
            expiry_retry_at: None,
            expiry_retry_attempts: 0,
        },
    );
    refresh_coarse_aggregate();
}

/// Remove the entry for `key` when `generation` still owns it.
///
/// A stale generation's removal is ignored so a slow supervisor teardown cannot
/// delete the health of the task that replaced it.
pub(crate) fn remove_task(key: &str, generation: u64) {
    if registry()
        .remove_if(key, |_, entry| entry.generation == generation)
        .is_some()
    {
        refresh_coarse_aggregate();
    }
}

/// Whether `generation` is still the owner of `key`.
pub(crate) fn generation_is_current(key: &str, generation: u64) -> bool {
    registry()
        .get(key)
        .is_some_and(|entry| entry.generation == generation)
}

/// Record a successfully admitted and published (or confirmed) snapshot.
pub(crate) fn record_success(key: &str, generation: u64) {
    let now = Instant::now();
    let affects_coarse = with_current(key, generation, |entry| {
        // `stale`, `readiness_failing`, and therefore `ready()` / `degraded()`
        // are derived from the staleness anchor at compute time rather than
        // stored, so a success that clears a stale window whose expiry episode
        // has not been claimed yet must invalidate the cache as well. A task is
        // stale-but-unclaimed while its poller is mid-publication: the deadline
        // is armed across asynchronous preparation, but a preparation step that
        // completes first wins that select and the anchor can still cross the
        // bound during the synchronous fenced installation. A coarse recompute
        // driven by any other task's transition inside that window would
        // otherwise latch `ready: false` on `/health` and `/status` long after
        // discovery recovered, with no further transition to clear it.
        let affects_coarse = entry.expiry_applied
            || entry.expiry_retry_at.is_some()
            || entry.is_stale(now)
            || matches!(
                entry.state,
                DiscoveryTaskState::Restarting
                    | DiscoveryTaskState::CrashLooping
                    | DiscoveryTaskState::Stopped
            );
        entry.state = DiscoveryTaskState::Running;
        entry.last_success_at = Some(now);
        entry.consecutive_failures = 0;
        entry.consecutive_crashes = 0;
        entry.last_error = None;
        entry.expiry_retry_at = None;
        entry.expiry_retry_attempts = 0;
        if entry.expiry_applied {
            entry.expiry_applied = false;
            entry.withdrawn = false;
            crate::plugins::prometheus_metrics::global_registry()
                .record_service_discovery_stale_recovery();
        }
        affects_coarse
    });
    if affects_coarse == Some(true) {
        refresh_coarse_aggregate();
    }
}

/// Record a poll that produced no new published snapshot.
pub(crate) fn record_failure(key: &str, generation: u64, reason: DiscoveryFailureReason) {
    with_current(key, generation, |entry| {
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_error = Some(reason);
        if entry.state == DiscoveryTaskState::Starting {
            entry.state = DiscoveryTaskState::Running;
        }
    });
}

/// Claim a non-withdrawing expiry episode (the `retain` policy).
///
/// Idempotent: returns `true` only for the transition into the expired state,
/// so the discovery loop applies exactly one expiry action per episode and
/// cannot hot-loop on an already-expired staleness deadline. Withdrawing
/// policies claim their episode inside the publication fence instead
/// ([`publish_withdrawal_if_current`]), so the claim cannot be separated from
/// the republication it describes.
pub(crate) fn claim_expiry(key: &str, generation: u64) -> bool {
    let claimed = with_current(key, generation, |entry| {
        if entry.expiry_applied {
            return false;
        }
        entry.expiry_applied = true;
        entry.withdrawn = false;
        entry.expiry_retry_at = None;
        entry.expiry_retry_attempts = 0;
        true
    })
    .unwrap_or(false);
    if claimed {
        refresh_coarse_aggregate();
    }
    claimed
}

/// Defer a failed staleness withdrawal with bounded exponential backoff.
///
/// The expiry remains unapplied so readiness continues to fail closed while
/// dynamic targets are still installed. The retry deadline prevents an elapsed
/// staleness timer from spinning.
pub(crate) fn defer_expiry_retry(key: &str, generation: u64) -> Option<Duration> {
    let backoff = with_current(key, generation, |entry| {
        entry.expiry_retry_attempts = entry.expiry_retry_attempts.saturating_add(1);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_error = Some(DiscoveryFailureReason::PublishFailed);
        let backoff = restart_backoff(entry.expiry_retry_attempts);
        entry.expiry_retry_at = Some(Instant::now() + backoff);
        backoff
    });
    if backoff.is_some() {
        refresh_coarse_aggregate();
    }
    backoff
}

/// Record an unexpected poller exit and return the supervisor's next backoff.
///
/// `None` means the generation was superseded and the supervisor must exit
/// without restarting.
pub(crate) fn record_unexpected_exit(key: &str, generation: u64) -> Option<Duration> {
    let crashes = with_current(key, generation, |entry| {
        entry.restarts = entry.restarts.saturating_add(1);
        entry.consecutive_crashes = entry.consecutive_crashes.saturating_add(1);
        entry.last_error = Some(DiscoveryFailureReason::TaskExited);
        entry.state = if entry.consecutive_crashes >= DISCOVERY_CRASH_LOOP_THRESHOLD {
            DiscoveryTaskState::CrashLooping
        } else {
            DiscoveryTaskState::Restarting
        };
        entry.consecutive_crashes
    })?;
    refresh_coarse_aggregate();
    Some(restart_backoff(crashes))
}

/// Mark a task as cleanly stopped (cancel or shutdown), never a crash.
pub(crate) fn record_clean_exit(key: &str, generation: u64) {
    let updated = with_current(key, generation, |entry| {
        entry.state = DiscoveryTaskState::Stopped;
    });
    if updated.is_some() {
        refresh_coarse_aggregate();
    }
}

/// Bounded exponential restart backoff with ±25% jitter.
///
/// Doubles from [`crate::util::backoff::BACKOFF_INITIAL_SECS`] and caps at
/// [`crate::util::backoff::BACKOFF_MAX_SECS`], so a poller that panics on every
/// iteration settles at one attempt per capped interval instead of hot-looping.
pub fn restart_backoff(consecutive_crashes: u64) -> Duration {
    let mut secs = crate::util::backoff::BACKOFF_INITIAL_SECS;
    for _ in 1..consecutive_crashes.min(16) {
        secs = crate::util::backoff::next_backoff_secs(secs, true);
    }
    crate::util::backoff::jittered_backoff(secs)
}

/// Effective staleness bound for one task.
///
/// Floors the configured window at [`DISCOVERY_MIN_STALE_POLL_INTERVALS`] poll
/// intervals so a slow-polling provider cannot be reported permanently stale,
/// and honors an explicit unbounded opt-in.
pub fn resolve_staleness(
    configured_max_stale_seconds: u64,
    policy: SdStalePolicy,
    poll_interval_seconds: u64,
) -> DiscoveryStaleness {
    if configured_max_stale_seconds == 0 {
        return DiscoveryStaleness::unbounded(policy);
    }
    // Field validation rejects out-of-range per-upstream values. Clamp again
    // at this runtime boundary so a caller that constructs a config or test
    // seam directly still cannot overflow `Instant + Duration` below.
    let configured_max_stale_seconds = configured_max_stale_seconds.clamp(
        crate::config::types::MIN_SD_MAX_STALE_SECONDS,
        crate::config::types::MAX_SD_MAX_STALE_SECONDS,
    );
    let floor = poll_interval_seconds
        .min(crate::config::types::MAX_SD_POLL_INTERVAL)
        .saturating_mul(DISCOVERY_MIN_STALE_POLL_INTERVALS);
    DiscoveryStaleness {
        max_stale: Some(Duration::from_secs(configured_max_stale_seconds.max(floor))),
        policy,
    }
}

/// Instant at which `key`'s generation next crosses its staleness bound.
///
/// The discovery loop arms a timer on this so withdrawal happens on expiry
/// rather than at the next poll tick, which may be far later.
pub(crate) fn next_stale_deadline(key: &str, generation: u64) -> Option<Instant> {
    let entry = registry().get(key)?;
    if entry.generation != generation || entry.expiry_applied {
        return None;
    }
    if let Some(retry_at) = entry.expiry_retry_at {
        return Some(retry_at);
    }
    let max = entry.staleness.max_stale?;
    Some(entry.last_success_at.unwrap_or(entry.started_at) + max)
}

fn project(key: &str, entry: &TaskHealth, now: Instant) -> DiscoveryTaskStatus {
    DiscoveryTaskStatus {
        upstream: key.to_string(),
        provider: entry.provider,
        state: entry.state.as_str(),
        stale: entry.is_stale(now),
        withdrawn: entry.withdrawn,
        policy: entry.staleness.policy.as_str(),
        max_stale_seconds: entry.staleness.max_stale_seconds(),
        last_success_age_seconds: entry
            .last_success_at
            .map(|at| now.saturating_duration_since(at).as_secs()),
        anchor_age_seconds: entry.anchor_age(now).as_secs(),
        consecutive_failures: entry.consecutive_failures,
        consecutive_crashes: entry.consecutive_crashes,
        restarts: entry.restarts,
        last_error: entry.last_error.map(DiscoveryFailureReason::as_str),
    }
}

fn compute_aggregate(now: Instant) -> DiscoveryHealthAggregate {
    let mut aggregate = DiscoveryHealthAggregate::default();
    for entry in registry().iter() {
        let entry = entry.value();
        aggregate.tasks += 1;
        match entry.state {
            DiscoveryTaskState::Running | DiscoveryTaskState::Starting => aggregate.running += 1,
            DiscoveryTaskState::Restarting => aggregate.restarting += 1,
            DiscoveryTaskState::CrashLooping => aggregate.crash_looping += 1,
            DiscoveryTaskState::Stopped => {}
        }
        if entry.last_success_at.is_none() {
            aggregate.never_succeeded += 1;
        }
        if entry.withdrawn {
            aggregate.withdrawn += 1;
        }
        if entry.is_stale(now) {
            aggregate.stale += 1;
            if entry.staleness.policy.fails_readiness()
                || (entry.staleness.policy.withdraws() && !entry.withdrawn)
            {
                aggregate.readiness_failing += 1;
            }
        }
        aggregate.max_anchor_age_seconds = aggregate
            .max_anchor_age_seconds
            .max(entry.anchor_age(now).as_secs());
    }
    aggregate
}

/// Recompute the coarse projection after a background lifecycle transition.
/// This may walk configured tasks on the control-plane/background path; the
/// unauthenticated health path remains an O(1) ArcSwap load.
fn refresh_coarse_aggregate() {
    // Serialize recomputes so an older transition cannot publish its snapshot
    // after a newer one. The lock is never touched by aggregate readers.
    let _guard = COARSE_AGGREGATE_REFRESH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    coarse_aggregate_cache().store(std::sync::Arc::new(compute_aggregate(Instant::now())));
}

/// Precomputed fixed-cardinality aggregate for unauthenticated coarse health.
///
/// Background lifecycle transitions precompute this snapshot, keeping the
/// unauthenticated `/health` and `/status` paths lock-free and O(1). Age-only
/// fields are not consumed on that tier; authenticated projections and metrics
/// use [`aggregate`] to compute their current values.
pub fn coarse_aggregate() -> DiscoveryHealthAggregate {
    **coarse_aggregate_cache().load()
}

/// Current fixed-cardinality aggregate for authenticated detail and `/metrics`.
pub fn aggregate() -> DiscoveryHealthAggregate {
    compute_aggregate(Instant::now())
}

/// Authenticated projection: aggregate plus per-upstream detail, sorted by
/// upstream key so the body is stable across scrapes.
pub fn snapshot() -> DiscoveryHealthSnapshot {
    let now = Instant::now();
    let mut upstreams: Vec<DiscoveryTaskStatus> = registry()
        .iter()
        .map(|entry| project(entry.key(), entry.value(), now))
        .collect();
    upstreams.sort_by(|a, b| a.upstream.cmp(&b.upstream));
    DiscoveryHealthSnapshot {
        aggregate: compute_aggregate(now),
        upstreams,
    }
}

/// Whether any discovery task is currently configured. Used to keep the health
/// body free of an empty discovery object on gateways without discovery.
pub fn has_tasks() -> bool {
    !registry().is_empty()
}

/// Drop all registry entries. Test-only: the registry is process-global, so
/// external suites that start managers must isolate themselves.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn reset_for_test() {
    registry().clear();
    refresh_coarse_aggregate();
}

/// Register a task generation directly, as a reconcile-driven replacement
/// would. Test-only seam for proving that a superseded supervisor exits instead
/// of restarting or publishing.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn register_task_for_test(
    key: &str,
    generation: u64,
    provider: &'static str,
    staleness: DiscoveryStaleness,
) {
    register_task(key, generation, provider, staleness);
}

/// Generation currently owning `key`, if any. Test-only observation seam: a
/// kept task keeps its generation across reconcile, a replaced one does not.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn generation_for_test(key: &str) -> Option<u64> {
    registry().get(key).map(|entry| entry.generation)
}

/// Number of bounded withdrawal-publication retries for `key`.
/// Test-only observation seam for the fail-closed retry contract.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn expiry_retry_attempts_for_test(key: &str) -> Option<u64> {
    registry().get(key).map(|entry| entry.expiry_retry_attempts)
}

/// Run `body` inside the production publication fence for `key`/`generation`.
///
/// Test-only seam for proving the interleaving contract: while `body` runs, a
/// concurrent [`register_task_for_test`] for the same key cannot complete.
/// `None` means the generation was already superseded and `body` never ran.
/// `body` must not touch this registry (see [`publish_if_current`]).
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn publish_under_fence_for_test<T>(
    key: &str,
    generation: u64,
    body: impl FnOnce() -> T,
) -> Option<T> {
    publish_if_current(key, generation, body).published()
}

/// Drive the staleness-withdrawal fence exactly as the discovery loop's expiry
/// path does when no lifecycle signal is pending. `None` means the generation
/// was superseded and `publish` never ran; otherwise the publication result and
/// whether this call claimed the expiry episode.
///
/// The adapter below never aborts, so the abort outcome is unreachable here;
/// use [`publish_withdrawal_under_fence_with_abort_for_test`] to cover a
/// cancellation or shutdown observed inside the fence.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn publish_withdrawal_under_fence_for_test(
    key: &str,
    generation: u64,
    publish: impl FnOnce() -> Result<(), String>,
) -> Option<(Result<(), String>, bool)> {
    let attempt = || match publish() {
        Ok(()) => WithdrawalAttempt::Published,
        Err(error) => WithdrawalAttempt::Failed(error),
    };
    match publish_withdrawal_if_current(key, generation, attempt).published()? {
        FencedWithdrawal::Published { claimed } => Some((Ok(()), claimed)),
        FencedWithdrawal::Failed(error) => Some((Err(error), false)),
        // Unreachable for the adapter above; reported as "did not publish"
        // rather than panicking in a shipped code path.
        FencedWithdrawal::Aborted => None,
    }
}

/// Test-facing projection of a fenced staleness-withdrawal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub enum FencedWithdrawalForTest {
    /// Static-only targets were installed; `claimed` marks the one call per
    /// episode that claimed it.
    Published { claimed: bool },
    /// Installation was attempted and failed.
    Failed,
    /// A lifecycle signal was observed inside the fence; nothing was written.
    Aborted,
    /// The generation no longer owned the key; the closure never ran.
    Superseded,
}

/// Drive the staleness-withdrawal fence with a closure that may decide, inside
/// the fence, that cancellation or shutdown won (`None`).
///
/// Test-only seam for the interleaving contract of the abort path: while the
/// closure runs, a concurrent [`register_task_for_test`] for the same key
/// cannot complete, and an abort must claim nothing.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn publish_withdrawal_under_fence_with_abort_for_test(
    key: &str,
    generation: u64,
    publish: impl FnOnce() -> Option<Result<(), String>>,
) -> FencedWithdrawalForTest {
    let attempt = || match publish() {
        Some(Ok(())) => WithdrawalAttempt::Published,
        Some(Err(error)) => WithdrawalAttempt::Failed(error),
        None => WithdrawalAttempt::Aborted,
    };
    match publish_withdrawal_if_current(key, generation, attempt) {
        FencedPublish::Superseded => FencedWithdrawalForTest::Superseded,
        FencedPublish::Published(FencedWithdrawal::Published { claimed }) => {
            FencedWithdrawalForTest::Published { claimed }
        }
        FencedPublish::Published(FencedWithdrawal::Failed(_)) => FencedWithdrawalForTest::Failed,
        FencedPublish::Published(FencedWithdrawal::Aborted) => FencedWithdrawalForTest::Aborted,
    }
}

/// Whether `key`'s current entry has its expiry episode applied. Test-only
/// observation seam for the fenced withdrawal claim.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn expiry_applied_for_test(key: &str) -> Option<bool> {
    registry().get(key).map(|entry| entry.expiry_applied)
}

/// Force `key`'s staleness anchor to `age` seconds ago without waiting.
///
/// Test-only. Returns `false` when the key is absent, so a test cannot silently
/// assert against an entry that was never registered.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn age_anchor_for_test(key: &str, age_seconds: u64) -> bool {
    let Some(mut entry) = registry().get_mut(key) else {
        return false;
    };
    let Some(shifted) = Instant::now().checked_sub(Duration::from_secs(age_seconds)) else {
        return false;
    };
    entry.started_at = shifted;
    if entry.last_success_at.is_some() {
        entry.last_success_at = Some(shifted);
    }
    drop(entry);
    refresh_coarse_aggregate();
    true
}
