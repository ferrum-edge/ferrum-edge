//! `proxy_alerts` — observes proxy traffic and dispatches notifications when
//! configured rules breach their thresholds.
//!
//! Hooks into the `log()`, `on_stream_disconnect()`, and selected
//! `on_ws_disconnect()` lifecycle phases (after the request/connection has
//! completed). Per-rule sliding windows track matched/total counts (or
//! latency observations); on threshold breach the plugin builds a generic
//! [`Notification`] and dispatches it to the rule's configured channels via
//! the shared `crate::notifications` layer.
//!
//! Architecture notes:
//! - **Channels are reusable**: live in `src/notifications/channels/`. Other
//!   subsystems (overload manager, mesh policy, future plugins) can use the
//!   same channel implementations without depending on `proxy_alerts`.
//! - **Per-`(rule, proxy, channel)` incident lifecycle**: every channel owns
//!   its own [`RecoveryGate`], so Trigger/Resolve delivery state is tracked
//!   per channel. A channel that missed an event (dispatch backpressure,
//!   failed delivery) keeps owing it and retries on the next eligible
//!   evaluation even when a sibling channel delivered successfully.
//! - **Per-`(rule, proxy, channel)` cooldown** prevents repeated dispatches
//!   without suppressing unrelated proxies that share a global/group rule.
//!   Cooldown is armed at dispatch admission and released if delivery fails
//!   or is abandoned, so a failed send does not silently consume the window.
//! - **Pending delivery seats**: Trigger/Resolve commit
//!   `PendingTrigger` / `PendingResolve` when a send is admitted; state moves
//!   to `Active` / `Healthy` only after a successful settle (or rolls back on
//!   failure so the next evaluation can retry). A reminder Trigger for an
//!   already-Active incident reserves `PendingReminder`, which holds recovery
//!   until the reminder settles so a slow reminder can never land after the
//!   Resolve and reopen a resolved incident at the receiver.
//! - **Compensating Trigger after an uncertain Resolve**: a Resolve that is
//!   already externally in flight cannot be unsent, and retiring its local
//!   future is not a rollback. If the rule breaches again in that window the
//!   incident parks in `ResolveInFlightRebreached` (no notification — a Trigger
//!   emitted now could overtake the Resolve on the wire), and the Resolve's
//!   settle — success, failure, or abandonment alike — converges to
//!   `CompensatingTrigger`. The next breaching sample then re-alerts through
//!   the ordinary cooldown gate, so a possibly-delivered Resolve can never
//!   leave a genuinely breached incident silently suppressed. If the rule is no
//!   longer breaching by then, the Resolve was accurate and the state returns
//!   to `Healthy` with no phantom alert.
//! - **Time-driven lifecycle**: a background task re-evaluates
//!   Active/Recovering/CompensatingTrigger incidents against their windows
//!   every `LIFECYCLE_TICK` (5s) without recording a sample, so an incident on a
//!   proxy that stopped producing traffic still ages out of breach, enters
//!   recovery, and resolves on schedule. A window that re-breaches as samples
//!   age out (a rate or percentile can rise when older healthy samples expire)
//!   resets a Recovering incident to Active, so the next clear starts a fresh
//!   recovery interval; re-evaluation never sends a Trigger or reminder. The task holds only a `Weak` handle
//!   and is aborted on `Drop`.
//! - **Best-effort endpoint delivery**: bounded backpressure/failure paths can
//!   produce zero copies, while transport timeouts, post-write connection
//!   errors, and cancellation after bytes left the process are all reported as
//!   failure/abandonment even though the endpoint may have acted on the send.
//!   Retries and compensating Triggers can therefore duplicate an alert at the
//!   receiver. See the delivery contract in `src/notifications/dispatch.rs`
//!   and `docs/notifications.md`.
//! - **Bounded-concurrency dispatch**: `tokio::Semaphore`. When exhausted,
//!   alerts are dropped with a `warn!` rather than queued — alert storms
//!   during a partial channel outage should be visible, not buffered.
//! - **Classified retries**: transient transport/HTTP failures retry inside
//!   the same task with jittered bounded backoff while holding the permit.
//! - **Generation drain**: each instance owns a [`DispatchGeneration`];
//!   reload/`Drop` cancels admission, and tasks participate in the process
//!   observability delivery shutdown budget.
//! - **Quiet hours**: optional UTC time-of-day windows where `Trigger`
//!   alerts are suppressed (without consuming the cooldown gate). `Resolve`
//!   events still fire so operators don't miss recovery during off hours.
//! - **Lifecycle retention**: preserved global/proxy-group instances publish
//!   per-proxy ownership generations and retire cooldown/recovery/window rows
//!   when proxies leave the instance's active set or when an ID's generation
//!   advances (incremental cache commit, off the request path). Lifecycle
//!   rows themselves are keyed by admission ownership generation so a stale
//!   write that races past retain cannot populate or poison the replacement
//!   incarnation. Samples carry the admission-time generation captured from
//!   the published RequestEpoch/plugin-cache snapshot. Full retention passes
//!   (commit-path retain and the background ownership sweep) share a
//!   poison-recovering cold-path mutex so a stale sweep cannot delete rows
//!   for the latest published map. Expired cooldown timestamps and terminal
//!   Healthy recovery rows are also swept by the background eviction task.
//! - **Clock separation**: sliding windows, cooldown/recovery durations, and
//!   lifecycle eviction use one process-monotonic clock. UTC is consulted only
//!   for quiet-hour policy and human-readable notification timestamps.

use crate::plugins::utils::log_sampling::warn_sampled;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::notifications::dispatch::{DeliveryCallback, DeliveryRetryPolicy};
use crate::notifications::generation::{DispatchGeneration, DispatchSettle};
use crate::notifications::{EventAction, Notification, NotificationChannel};
use crate::plugins::utils::http_client::PluginHttpClient;

use super::{
    ALL_PROTOCOLS, Plugin, ProxyProtocol, StreamTransactionSummary, TransactionSummary,
    WsDisconnectContext,
};

pub mod config;
pub mod cooldown;
mod generation_map;
pub mod render;
pub mod rules;
pub mod windows;

use config::{ProxyAlertsConfig, QuietHourWindow};
use cooldown::{CooldownGate, LifecycleOutcome, RecoveryGate, RuleState};
use render::AlertSubject;
use rules::{Rule, RuleObservation, SampleInput};
use windows::{WindowStore, monotonic_now_ms};

/// Floor for background lifecycle retention, matching the historical window
/// sweep cadence documented for inactive proxies.
const LIFECYCLE_KEEP_FLOOR_MS: u64 = 3_600_000;

/// Cadence of the background lifecycle re-evaluation. Matches the minimum
/// `window_seconds` / `resolved_window_seconds`, so an idle incident resolves
/// at most one tick after its recovery window elapses.
const LIFECYCLE_TICK: Duration = Duration::from_secs(5);

/// Ownership retention + stale-row eviction run every this many lifecycle
/// ticks (60s), the historical eviction cadence.
const EVICTION_EVERY_TICKS: u32 = 12;

/// Ownership generation used by offline / unarmed unit tests that intentionally
/// omit an admission token. Armed production instances reject missing tokens
/// before any lifecycle write.
pub const UNARMED_PROXY_LIFECYCLE_GENERATION: u64 = 0;

/// Policy identity used for `${incident_key}` by instances constructed without
/// a plugin-config resource id (config validation, direct/test construction).
pub const STANDALONE_POLICY_ID: &str = "standalone";

static NEXT_DISPATCH_GENERATION: AtomicU64 = AtomicU64::new(1);

pub struct ProxyAlerts {
    core: Arc<AlertCore>,
    /// Background lifecycle task (re-evaluation + eviction). Started by
    /// `commit_background_tasks` once the owning generation is installed,
    /// never by the constructor: config validation constructs and drops
    /// instances, and the task can send resolve notifications (issue #6616).
    /// Empty outside a Tokio runtime. Holds only a `Weak` core and is aborted
    /// on `Drop`.
    lifecycle_task: OnceLock<tokio::task::JoinHandle<()>>,
}

/// Shared plugin state. Owned by [`ProxyAlerts`]; the background lifecycle
/// task reaches it through a `Weak` so it never extends the instance's life.
struct AlertCore {
    rules: Arc<Vec<Rule>>,
    channel_by_id: Arc<HashMap<u32, Arc<NotificationChannel>>>,
    windows: Arc<WindowStore>,
    cooldowns: Arc<CooldownGate>,
    /// One incident-lifecycle gate per channel, indexed by channel id (ids are
    /// dense `0..channels.len()`, assigned at config parse).
    recovery_by_channel: Vec<Arc<RecoveryGate>>,
    /// Rendering identity remembered when a sample admitted an alert, so the
    /// background re-evaluation can label a Resolve for a proxy that stopped
    /// producing traffic. Keyed by namespace-qualified owner key; bounded by
    /// owned proxies with live incidents (ownership retain + sweep prune it).
    subjects: DashMap<String, IncidentSubject>,
    /// Published ownership generations for proxies this instance may observe.
    /// `None` until the first cold-path retain (unit tests that never retain
    /// keep the historical ungated write path). After retain, writes require a
    /// matching admitted generation.
    active_proxy_generations: ArcSwap<Option<HashMap<String, u64>>>,
    /// Serializes full ownership retention passes (commit-path retain and the
    /// background ownership sweep). Request observation only loads the
    /// ArcSwap snapshot and never takes this lock.
    retention_lock: Mutex<()>,
    dispatch_sem: Arc<Semaphore>,
    /// Per-instance dispatch generation: closed and cancelled on Drop so
    /// reload retires in-flight sends without leaking them into the next
    /// plugin incarnation.
    dispatch_generation: Arc<DispatchGeneration>,
    delivery_retry: DeliveryRetryPolicy,
    http_client: PluginHttpClient,
    enabled: AtomicBool,
    quiet_hours: Vec<QuietHourWindow>,
    lifecycle_keep_ms: u64,
    /// Stable plugin-config resource id of this instance (or
    /// [`STANDALONE_POLICY_ID`]). Scopes `${incident_key}` so two instances
    /// reusing a rule name on one proxy never share a receiver incident.
    policy_id: Arc<str>,
}

#[derive(Debug, Clone)]
struct IncidentSubject {
    generation: u64,
    namespace: Arc<str>,
    proxy_id: Arc<str>,
    proxy_name: Option<Arc<str>>,
}

impl IncidentSubject {
    fn as_alert_subject(&self) -> AlertSubject<'_> {
        AlertSubject {
            namespace: self.namespace.as_ref(),
            proxy_id: Some(self.proxy_id.as_ref()),
            proxy_name: self.proxy_name.as_deref(),
        }
    }
}

/// A notification rendered for one event action, shared by every channel
/// admitted for that action from the same observation.
type RenderedAlert = (EventAction, Arc<Notification>, Arc<HashMap<String, String>>);

/// One channel delivery admitted by [`AlertCore::advance_channel`]: its
/// lifecycle seat is reserved and the dispatch permit is held.
struct AdmittedDispatch {
    channel: Arc<NotificationChannel>,
    channel_id: u32,
    permit: OwnedSemaphorePermit,
    gate: Arc<RecoveryGate>,
    event_action: EventAction,
    left_threshold_at_ms: u64,
}

impl std::fmt::Debug for ProxyAlerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAlerts")
            .field("rules", &self.core.rules.len())
            .field("channels", &self.core.channel_by_id.len())
            .field("enabled", &self.core.enabled.load(Ordering::Acquire))
            .field("quiet_hours", &self.core.quiet_hours.len())
            .finish()
    }
}

thread_local! {
    /// Reusable scratch buffer for the namespace-qualified lifecycle identity
    /// (`namespace|proxy_id`). Borrowed strictly synchronously within one
    /// `handle` call (no `.await`, no re-entry), so per-sample identity
    /// composition stays allocation-free in steady state.
    static OWNER_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(64));
}

impl ProxyAlerts {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, None)
    }

    /// Construct with the stable plugin-config resource id the plugin cache
    /// passes (`None` for validation/direct construction, which uses
    /// [`STANDALONE_POLICY_ID`]). The id scopes `${incident_key}`. A supplied
    /// blank id fails closed.
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        let policy_id = match plugin_config_id {
            Some(id) if id.trim().is_empty() => {
                return Err("proxy_alerts: plugin config id must not be blank".to_string());
            }
            Some(id) => id,
            None => STANDALONE_POLICY_ID,
        };
        let parsed = ProxyAlertsConfig::parse(http_client.backend_allow_ips(), config)?;

        let rule_specs = parsed
            .rules
            .iter()
            .map(|r| (r.id(), r.window_spec()))
            .collect();
        // Honour `FERRUM_POOL_SHARD_AMOUNT` like every other hot-path plugin map.
        let shard_amount = http_client.pool_shard_amount();
        let windows = Arc::new(WindowStore::with_shard_amount(rule_specs, shard_amount));
        let cooldowns = Arc::new(CooldownGate::with_shard_amount(shard_amount));
        let recovery_by_channel = (0..parsed.channel_by_id.len())
            .map(|_| Arc::new(RecoveryGate::with_shard_amount(shard_amount)))
            .collect();
        let lifecycle_keep_ms = lifecycle_keep_ms(parsed.rules.as_ref());
        let dispatch_sem = Arc::new(Semaphore::new(parsed.max_concurrent_dispatches));
        let dispatch_generation =
            DispatchGeneration::new(NEXT_DISPATCH_GENERATION.fetch_add(1, Ordering::Relaxed));

        let core = Arc::new(AlertCore {
            rules: parsed.rules,
            channel_by_id: parsed.channel_by_id,
            windows,
            cooldowns,
            recovery_by_channel,
            subjects: DashMap::with_shard_amount(shard_amount),
            active_proxy_generations: ArcSwap::from_pointee(None),
            retention_lock: Mutex::new(()),
            dispatch_sem,
            dispatch_generation,
            delivery_retry: parsed.delivery_retry,
            http_client,
            enabled: AtomicBool::new(parsed.enabled),
            quiet_hours: parsed.quiet_hours,
            lifecycle_keep_ms,
            policy_id: Arc::from(policy_id),
        });
        Ok(Self {
            core,
            lifecycle_task: OnceLock::new(),
        })
    }

    /// Publish ownership generations and retire per-proxy window/cooldown/
    /// recovery rows for proxies absent from that map or whose stored
    /// generation does not match the published incarnation.
    ///
    /// Invoked from the plugin-cache commit path for preserved global and
    /// proxy-group instances. Must not run on the request hot path.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        self.core.retain_proxies(active_proxy_generations);
    }

    /// Compatibility helper for tests that only have an active-ID set.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn retain_proxy_ids_for_test(&self, active_proxy_ids: &HashSet<&str>) {
        let generations: HashMap<&str, u64> = active_proxy_ids
            .iter()
            .copied()
            .map(|id| {
                let generation = self
                    .core
                    .active_proxy_generations
                    .load()
                    .as_ref()
                    .as_ref()
                    .and_then(|map| map.get(id).copied())
                    .unwrap_or(1);
                (id, generation)
            })
            .collect();
        self.retain_proxies(&generations);
    }

    /// Seed cooldown + Active recovery state (on every channel) for
    /// deterministic external tests.
    #[doc(hidden)]
    pub fn seed_lifecycle_state_for_test(&self, proxy_id: &str, generation: u64) {
        // Ensure the seeded proxy is owned under `generation` so subsequent
        // gated writes from the same incarnation succeed in tests.
        let mut map = self
            .core
            .active_proxy_generations
            .load()
            .as_ref()
            .clone()
            .unwrap_or_default();
        map.insert(proxy_id.to_string(), generation);
        self.core
            .active_proxy_generations
            .store(Arc::new(Some(map)));
        let _ = self
            .core
            .cooldowns
            .try_acquire(0, proxy_id, 0, 60_000, 1, generation);
        for gate in &self.core.recovery_by_channel {
            let _ = gate.observe(0, proxy_id, true, 5_000, 1, generation);
            // observe lands on PendingTrigger; commit Active for seeders that
            // need a fully-delivered incident (plugin-cache retention tests).
            gate.settle_trigger_success(0, proxy_id, generation, 1, 1);
        }
    }

    /// Whether this instance currently holds lifecycle state for `proxy_id`
    /// under any ownership generation.
    #[doc(hidden)]
    pub fn has_lifecycle_state_for_test(&self, proxy_id: &str) -> bool {
        self.core.cooldowns.contains_proxy(proxy_id)
            || self
                .core
                .recovery_by_channel
                .iter()
                .any(|gate| gate.contains_proxy(proxy_id))
            || self.core.windows.contains_proxy(proxy_id)
    }

    /// Whether this instance holds lifecycle state for `(proxy_id, generation)`.
    #[doc(hidden)]
    pub fn has_lifecycle_state_for_generation_for_test(
        &self,
        proxy_id: &str,
        generation: u64,
    ) -> bool {
        self.core
            .cooldowns
            .contains_proxy_generation(proxy_id, generation)
            || self
                .core
                .recovery_by_channel
                .iter()
                .any(|gate| gate.contains_proxy_generation(proxy_id, generation))
            || self
                .core
                .windows
                .contains_proxy_generation(proxy_id, generation)
    }

    /// Direct store write that bypasses the admission precheck — used by
    /// deterministic race-contract tests to prove generation-keyed isolation
    /// even when a stale writer races past retain publication.
    #[doc(hidden)]
    pub fn write_lifecycle_state_for_test(&self, proxy_id: &str, generation: u64) {
        if let Some(rule) = self.core.rules.first() {
            self.core
                .windows
                .record_count(rule.id(), proxy_id, generation, true, 1);
        }
        let _ = self
            .core
            .cooldowns
            .try_acquire(0, proxy_id, 0, 60_000, 1, generation);
        for gate in &self.core.recovery_by_channel {
            let _ = gate.observe(0, proxy_id, true, 5_000, 1, generation);
            gate.settle_trigger_success(0, proxy_id, generation, 1, 1);
        }
    }

    /// Run the ownership portion of the background lifecycle sweep without
    /// waiting for its one-minute cadence.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn sweep_lifecycle_ownership_for_test(&self) {
        self.core.retain_published_proxy_generations();
    }

    /// Run the background lifecycle re-evaluation once at an injected
    /// monotonic `now_ms`, without waiting for its cadence.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn reevaluate_incidents_at_for_test(&self, now_ms: u64) {
        self.core.reevaluate_idle_incidents(now_ms, Utc::now());
    }

    /// Stop the background lifecycle task so a deterministic test that injects
    /// monotonic timestamps owns every re-evaluation itself.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn stop_lifecycle_task_for_test(&self) {
        if let Some(task) = self.lifecycle_task.get() {
            task.abort();
        }
    }

    /// Whether the background lifecycle task is still running (`None` until
    /// `commit_background_tasks` started it on a Tokio runtime).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn lifecycle_task_finished_for_test(&self) -> Option<bool> {
        self.lifecycle_task
            .get()
            .map(tokio::task::JoinHandle::is_finished)
    }

    /// Probe reporting whether this instance's shared core is still alive, so
    /// a test can prove the background task does not keep a dropped instance
    /// (and its channels/credentials) alive.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn core_alive_probe_for_test(&self) -> Box<dyn Fn() -> bool + Send + Sync> {
        let core = Arc::downgrade(&self.core);
        Box::new(move || core.strong_count() > 0)
    }

    /// Feed one sample through the full observation + dispatch path at an
    /// injected monotonic `now_ms` (quiet hours ignored). Ownership checks
    /// match the production `log()` / disconnect hooks.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn handle_sample_at_for_test(&self, sample: SampleInput<'_>, now_ms: u64) {
        let Some(proxy_id) = sample.proxy_id() else {
            return;
        };
        let mut owner_key = String::new();
        crate::config::db_backend::write_namespaced_runtime_key(
            &mut owner_key,
            sample.namespace(),
            proxy_id,
        );
        if !proxy_id.is_empty()
            && !self
                .core
                .owns_proxy_generation(&owner_key, sample.proxy_lifecycle_generation())
        {
            return;
        }
        self.core
            .handle_at(sample, &owner_key, now_ms, Utc::now(), false);
    }

    /// Hold the cold-path retention lock for deterministic serialization tests.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn with_retention_lock_for_test<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.core.retention_guard();
        f()
    }

    /// Whether the retention lock is free (`true`) or held (`false`).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn try_retention_lock_for_test(&self) -> bool {
        self.core.retention_lock.try_lock().is_ok()
    }

    /// Publish ownership generations without retaining (test-only). Callers
    /// must already hold [`Self::with_retention_lock_for_test`] when proving
    /// the commit/sweep serialization contract.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn publish_proxy_generations_for_test(
        &self,
        active_proxy_generations: &HashMap<&str, u64>,
    ) {
        let owned: HashMap<String, u64> = active_proxy_generations
            .iter()
            .map(|(id, generation)| ((*id).to_string(), *generation))
            .collect();
        self.core
            .active_proxy_generations
            .store(Arc::new(Some(owned)));
    }

    /// Cancel admission for this instance's dispatch generation (test hook).
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn cancel_dispatch_generation_for_test(&self) {
        self.core.dispatch_generation.cancel();
    }

    /// Borrow this instance's dispatch generation so a deterministic external
    /// test can observe retirement and drain *after* the plugin itself has been
    /// dropped (the reload boundary this contract is about).
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn dispatch_generation_for_test(&self) -> Arc<DispatchGeneration> {
        Arc::clone(&self.core.dispatch_generation)
    }

    /// Borrow the recovery gate of the first rule's first channel so a
    /// deterministic external test can assert producer state settled after the
    /// plugin was dropped.
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn recovery_gate_for_test(&self) -> Arc<RecoveryGate> {
        self.core
            .rules
            .first()
            .and_then(|rule| self.core.primary_gate_for_rule(rule.id()))
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(RecoveryGate::new()))
    }

    /// In-flight dispatch count for this instance generation.
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn dispatch_in_flight_for_test(&self) -> usize {
        self.core.dispatch_generation.in_flight()
    }

    /// Current recovery state of the rule's first channel for deterministic
    /// external delivery tests.
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn recovery_state_for_test(
        &self,
        rule_id: u32,
        proxy_id: &str,
        ownership_generation: u64,
    ) -> Option<RuleState> {
        self.core.primary_gate_for_rule(rule_id)?.current_state(
            rule_id,
            proxy_id,
            ownership_generation,
        )
    }

    /// Current recovery state of `rule_id` on the channel configured as
    /// `channel_name` (per-channel lifecycle).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn recovery_state_for_channel_for_test(
        &self,
        rule_id: u32,
        channel_name: &str,
        proxy_id: &str,
        ownership_generation: u64,
    ) -> Option<RuleState> {
        let channel_id = self
            .core
            .channel_by_id
            .iter()
            .find(|(_, channel)| channel.name() == channel_name)
            .map(|(id, _)| *id)?;
        self.core
            .recovery_gate(channel_id)?
            .current_state(rule_id, proxy_id, ownership_generation)
    }

    /// Try to reserve one cooldown seat for deterministic external tests.
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn try_acquire_cooldown_for_test(
        &self,
        rule_id: u32,
        proxy_id: &str,
        channel_id: u32,
        cooldown_ms: u64,
        now_ms: u64,
        ownership_generation: u64,
    ) -> bool {
        self.core.cooldowns.try_acquire(
            rule_id,
            proxy_id,
            channel_id,
            cooldown_ms,
            now_ms,
            ownership_generation,
        )
    }
}

impl AlertCore {
    fn retention_guard(&self) -> MutexGuard<'_, ()> {
        self.retention_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn recovery_gate(&self, channel_id: u32) -> Option<&Arc<RecoveryGate>> {
        self.recovery_by_channel.get(channel_id as usize)
    }

    /// Gate of the first channel configured on `rule_id` (test accessors).
    fn primary_gate_for_rule(&self, rule_id: u32) -> Option<&Arc<RecoveryGate>> {
        let channel_id = self
            .rules
            .iter()
            .find(|rule| rule.id() == rule_id)
            .and_then(|rule| rule.common().channel_ids.first().copied())
            .unwrap_or(0);
        self.recovery_gate(channel_id)
    }

    fn in_quiet_hours(&self, now: DateTime<Utc>) -> bool {
        self.quiet_hours.iter().any(|w| w.matches(now))
    }

    fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
        let owned: HashMap<String, u64> = active_proxy_generations
            .iter()
            .map(|(id, generation)| ((*id).to_string(), *generation))
            .collect();
        // Serialize against the background ownership sweep. Publish under the
        // same guard before the retain walks so admission sees the new map
        // immediately while a concurrent sweep cannot still be retaining an
        // older snapshot (which would delete current-generation rows).
        let _guard = self.retention_guard();
        self.active_proxy_generations
            .store(Arc::new(Some(owned.clone())));
        let borrowed: HashMap<&str, u64> = owned
            .iter()
            .map(|(proxy_id, generation)| (proxy_id.as_str(), *generation))
            .collect();
        self.retain_lifecycle_rows(&borrowed);
    }

    /// Re-apply the latest published ownership map. Serialized with the
    /// commit-path retain by the retention lock.
    fn retain_published_proxy_generations(&self) {
        let _guard = self.retention_guard();
        // Load only after acquiring the serialization guard so a concurrent
        // commit cannot publish a newer map and finish retaining before this
        // pass still deletes against a stale snapshot.
        let active = self.active_proxy_generations.load();
        let Some(active) = active.as_ref() else {
            return;
        };
        let borrowed: HashMap<&str, u64> = active
            .iter()
            .map(|(proxy_id, generation)| (proxy_id.as_str(), *generation))
            .collect();
        self.retain_lifecycle_rows(&borrowed);
    }

    /// Caller must hold the retention lock.
    fn retain_lifecycle_rows(&self, active: &HashMap<&str, u64>) {
        self.windows.retain_proxies(active);
        self.cooldowns.retain_proxies(active);
        for gate in &self.recovery_by_channel {
            gate.retain_proxies(active);
        }
        self.subjects.retain(|owner_key, subject| {
            active.get(owner_key.as_str()).copied() == Some(subject.generation)
        });
    }

    /// Periodic eviction: ownership retention, stale windows/cooldowns,
    /// terminal Healthy recovery rows, and remembered subjects that no longer
    /// back any lifecycle row.
    fn sweep_lifecycle(&self, now_ms: u64) {
        // A sample can pass the admission-generation check immediately
        // before a cache commit and finish its write immediately after the
        // commit-time retain. Generation-keying isolates that row from the
        // replacement; periodically reapplying the published ownership map
        // also bounds the orphan rather than leaving an old-generation
        // Active/Recovering recovery row resident indefinitely. The
        // retention lock ensures this sweep loads the latest published map
        // and cannot interleave with a commit-path retain pass.
        self.retain_published_proxy_generations();
        self.windows.evict_stale(now_ms, self.lifecycle_keep_ms);
        self.cooldowns.evict_stale(now_ms, self.lifecycle_keep_ms);
        for gate in &self.recovery_by_channel {
            gate.evict_resolved();
        }
        self.subjects.retain(|owner_key, subject| {
            self.recovery_by_channel
                .iter()
                .any(|gate| gate.contains_proxy_generation(owner_key, subject.generation))
        });
    }

    /// Whether an admitted sample may mutate lifecycle state for `proxy_id`.
    fn owns_proxy_generation(&self, proxy_id: &str, admitted_generation: Option<u64>) -> bool {
        let guard = self.active_proxy_generations.load();
        match guard.as_ref() {
            // Retention not armed yet (offline unit tests / pre-retain).
            None => true,
            Some(active) => match (active.get(proxy_id), admitted_generation) {
                (Some(&current), Some(admitted)) => current == admitted,
                // Armed retention: missing proxy or missing admission token
                // must not create ownership visible to a replacement generation.
                _ => false,
            },
        }
    }

    fn handle(&self, sample: SampleInput<'_>) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        // Nothing to observe without a proxy identity (HTTP summaries may omit
        // it); mirrors the historical `sample.proxy_id()?` short-circuit.
        let Some(proxy_id) = sample.proxy_id() else {
            return;
        };
        OWNER_KEY_BUF.with(|buf| {
            let mut owner = buf.borrow_mut();
            // Lifecycle identity is namespace-qualified (`namespace|id`) so the
            // same proxy id in two tenants owns independent window/cooldown/
            // recovery/ownership rows and cannot mutate or retain each other's.
            crate::config::db_backend::write_namespaced_runtime_key(
                &mut owner,
                sample.namespace(),
                proxy_id,
            );
            let owner_key = owner.as_str();
            if !proxy_id.is_empty()
                && !self.owns_proxy_generation(owner_key, sample.proxy_lifecycle_generation())
            {
                return;
            }
            let now = Utc::now();
            let now_ms = monotonic_now_ms();
            let in_quiet = self.in_quiet_hours(now);
            self.handle_at(sample, owner_key, now_ms, now, in_quiet);
        });
    }

    /// Observe `sample` against every rule and advance each rule's per-channel
    /// lifecycle. `owner_key` is the namespace-qualified identity already
    /// admitted by the ownership check.
    fn handle_at(
        &self,
        sample: SampleInput<'_>,
        owner_key: &str,
        now_ms: u64,
        now: DateTime<Utc>,
        in_quiet: bool,
    ) {
        let ownership_generation = sample
            .proxy_lifecycle_generation()
            .unwrap_or(UNARMED_PROXY_LIFECYCLE_GENERATION);
        let subject = AlertSubject::from_sample(sample);
        // `observe` re-derives the same namespace-qualified identity from the
        // sample (its own thread-local scratch); `process_observation` reuses
        // this `owner_key`. Both agree because the composition is identical.
        for rule in self.rules.iter() {
            let Some(observation) = rule.observe(sample, &self.windows, now_ms) else {
                continue;
            };
            self.process_observation(
                rule,
                &observation,
                subject,
                owner_key,
                ownership_generation,
                now_ms,
                now,
                in_quiet,
                None,
            );
        }
    }

    /// Background lifecycle re-evaluation (no sample recorded).
    ///
    /// For every Active / Recovering / CompensatingTrigger incident still owned
    /// by its generation, snapshot the rule's window at `now_ms` and feed it
    /// through the normal per-channel lifecycle, so an idle proxy enters
    /// recovery and dispatches its single Resolve on schedule. A breaching
    /// snapshot is applied too — a window can re-breach without new samples
    /// when older healthy samples age out — so a Recovering incident returns
    /// to Active and the next clear restarts the recovery interval. Event
    /// admission is limited to Resolve here: a breach never sends a Trigger or
    /// reminder from the timer (`advance_channel` with `time_driven`).
    fn reevaluate_idle_incidents(&self, now_ms: u64, now: DateTime<Utc>) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let in_quiet = self.in_quiet_hours(now);
        for rule in self.rules.iter() {
            for &channel_id in &rule.common().channel_ids {
                let Some(gate) = self.recovery_gate(channel_id) else {
                    continue;
                };
                // Owned rows: no gate guard is held while dispatching below.
                for (owner_key, generation, _) in gate.time_driven_rows(rule.id()) {
                    if !self.owns_proxy_generation(&owner_key, Some(generation)) {
                        continue;
                    }
                    let observation =
                        rule.window_observation(&self.windows, &owner_key, generation, now_ms);
                    let subject = self.subject_for(&owner_key, generation);
                    self.process_observation(
                        rule,
                        &observation,
                        subject.as_alert_subject(),
                        &owner_key,
                        generation,
                        now_ms,
                        now,
                        in_quiet,
                        Some(channel_id),
                    );
                }
            }
        }
    }

    /// Rendering identity for a time-driven event: the one remembered when the
    /// incident was alerted, or (if pruned) one derived from the owner key.
    fn subject_for(&self, owner_key: &str, generation: u64) -> IncidentSubject {
        if let Some(stored) = self
            .subjects
            .get(owner_key)
            .filter(|stored| stored.generation == generation)
            .map(|stored| stored.value().clone())
        {
            return stored;
        }
        let (namespace, proxy_id) = owner_key.split_once('|').unwrap_or(("", owner_key));
        IncidentSubject {
            generation,
            namespace: Arc::from(namespace),
            proxy_id: Arc::from(proxy_id),
            proxy_name: None,
        }
    }

    /// Remember the rendering identity of an alerted incident (cold path:
    /// runs only when a dispatch was admitted).
    fn remember_subject(&self, owner_key: &str, generation: u64, subject: AlertSubject<'_>) {
        let unchanged = self.subjects.get(owner_key).is_some_and(|existing| {
            existing.generation == generation
                && existing.proxy_name.as_deref() == subject.proxy_name
        });
        if unchanged {
            return;
        }
        self.subjects.insert(
            owner_key.to_string(),
            IncidentSubject {
                generation,
                namespace: Arc::from(subject.namespace),
                proxy_id: Arc::from(subject.proxy_id.unwrap_or("")),
                proxy_name: subject.proxy_name.map(Arc::from),
            },
        );
    }

    /// Advance the rule's lifecycle on every configured channel (or only
    /// `only_channel`) and dispatch whatever each channel is owed.
    #[allow(clippy::too_many_arguments)]
    fn process_observation(
        &self,
        rule: &Rule,
        observation: &RuleObservation,
        subject: AlertSubject<'_>,
        owner_key: &str,
        ownership_generation: u64,
        now_ms: u64,
        now: DateTime<Utc>,
        in_quiet: bool,
        only_channel: Option<u32>,
    ) {
        let mut admitted: Option<Vec<AdmittedDispatch>> = None;
        for &channel_id in &rule.common().channel_ids {
            if only_channel.is_some_and(|only| only != channel_id) {
                continue;
            }
            if let Some(dispatch) = self.advance_channel(
                rule,
                observation.breach,
                owner_key,
                ownership_generation,
                channel_id,
                now_ms,
                in_quiet,
                only_channel.is_some(),
            ) {
                admitted.get_or_insert_with(Vec::new).push(dispatch);
            }
        }
        let Some(admitted) = admitted else {
            return;
        };
        if only_channel.is_none() {
            // Traffic-path admission: remember who this incident is about so a
            // later time-driven Resolve renders the same proxy identity.
            self.remember_subject(owner_key, ownership_generation, subject);
        }
        // Channels admitted from one observation normally share one event
        // action (a breach can only Trigger, a clear can only Resolve); render
        // once and share it, re-rendering only if an action ever differs.
        let mut rendered: Option<RenderedAlert> = None;
        for dispatch in admitted {
            let reuse = rendered
                .as_ref()
                .filter(|(action, _, _)| *action == dispatch.event_action)
                .map(|(_, notification, extras)| (Arc::clone(notification), Arc::clone(extras)));
            let (notification, extras) = match reuse {
                Some(pair) => pair,
                None => {
                    let notification = Arc::new(render::build_notification(
                        rule,
                        observation,
                        subject,
                        dispatch.event_action,
                        now,
                    ));
                    let extras = Arc::new(render::build_webhook_vars(
                        rule,
                        observation,
                        subject,
                        &self.policy_id,
                        dispatch.event_action,
                        now,
                    ));
                    rendered = Some((
                        dispatch.event_action,
                        Arc::clone(&notification),
                        Arc::clone(&extras),
                    ));
                    (notification, extras)
                }
            };
            let pending = Arc::new(PendingDelivery {
                event_action: dispatch.event_action,
                rule_id: rule.id(),
                channel_id: dispatch.channel_id,
                proxy_id: owner_key.to_string(),
                ownership_generation,
                reserved_at_ms: now_ms,
                left_threshold_at_ms: dispatch.left_threshold_at_ms,
                cooldowns: Arc::clone(&self.cooldowns),
                recovery: dispatch.gate,
            });
            self.spawn_dispatch(
                dispatch.channel,
                notification,
                extras,
                dispatch.permit,
                pending,
            );
        }
    }

    /// Evaluate and (when an event is owed and admitted) commit one channel's
    /// lifecycle for this observation. Returns the admitted dispatch, or
    /// `None` when nothing is sent on this channel.
    ///
    /// `time_driven` marks the background re-evaluation: non-event transitions
    /// (enter recovery, re-breach back to Active, compensating fall-back) are
    /// committed as usual, but only a Resolve may be admitted — a Trigger or
    /// reminder is left to the traffic path and nothing is reserved for it.
    #[allow(clippy::too_many_arguments)]
    fn advance_channel(
        &self,
        rule: &Rule,
        breach: bool,
        owner_key: &str,
        ownership_generation: u64,
        channel_id: u32,
        now_ms: u64,
        in_quiet: bool,
        time_driven: bool,
    ) -> Option<AdmittedDispatch> {
        let gate = self.recovery_gate(channel_id)?;
        let channel = self.channel_by_id.get(&channel_id)?;
        let rule_id = rule.id();
        // One state read per channel per sample; evaluation reuses it.
        let previous_state = gate.current_state(rule_id, owner_key, ownership_generation);
        if breach && in_quiet && matches!(previous_state, None | Some(RuleState::Healthy)) {
            return None;
        }
        let recovery_ms = rule
            .common()
            .recovery
            .as_ref()
            .map(|r| r.resolved_window_ms)
            .unwrap_or(0);
        let outcome = RecoveryGate::evaluate_state(previous_state, breach, recovery_ms, now_ms);
        let Some(event_action) = lifecycle_event_action(outcome) else {
            if non_event_outcome_needs_commit(outcome, previous_state, recovery_ms) {
                // Commit the non-event transition, but if evaluate→observe
                // raced into an event-reserving seat (no dispatch was admitted
                // on this path), roll that exact reservation back immediately.
                let committed = gate.observe(
                    rule_id,
                    owner_key,
                    breach,
                    recovery_ms,
                    now_ms,
                    ownership_generation,
                );
                gate.rollback_unadmitted_reservation(
                    rule_id,
                    owner_key,
                    ownership_generation,
                    committed,
                    now_ms,
                );
            }
            return None;
        };
        if event_action != EventAction::Resolve && (in_quiet || time_driven) {
            return None;
        }
        // Backpressure: nothing is committed, so this channel keeps owing the
        // event and the next eligible evaluation retries it.
        let permit = self.try_acquire_dispatch_permit(channel.name(), channel.kind())?;
        if event_action != EventAction::Resolve
            && !self.cooldowns.try_acquire(
                rule_id,
                owner_key,
                channel_id,
                rule.common().cooldown_ms,
                now_ms,
                ownership_generation,
            )
        {
            return None;
        }
        let (committed, committed_state) = gate.observe_committed(
            rule_id,
            owner_key,
            breach,
            recovery_ms,
            now_ms,
            ownership_generation,
        );
        if lifecycle_event_action(committed) != Some(event_action) {
            // State raced; release the cooldown we just armed and drop the
            // permit. `observe` may have committed a different event
            // reservation than the one evaluated above; no delivery is admitted
            // for it, so roll its exact token back as well.
            if event_action != EventAction::Resolve {
                self.cooldowns.release(
                    rule_id,
                    owner_key,
                    channel_id,
                    ownership_generation,
                    now_ms,
                );
            }
            gate.rollback_unadmitted_reservation(
                rule_id,
                owner_key,
                ownership_generation,
                committed,
                now_ms,
            );
            return None;
        }
        let left_threshold_at_ms = match committed_state {
            RuleState::PendingResolve {
                left_threshold_at_ms,
                ..
            } => left_threshold_at_ms,
            _ => now_ms,
        };
        Some(AdmittedDispatch {
            channel: Arc::clone(channel),
            channel_id,
            permit,
            gate: Arc::clone(gate),
            event_action,
            left_threshold_at_ms,
        })
    }

    fn try_acquire_dispatch_permit(
        &self,
        channel_name: &str,
        channel_type: &'static str,
    ) -> Option<OwnedSemaphorePermit> {
        match Arc::clone(&self.dispatch_sem).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                crate::notifications::metrics::global().record_backpressure_dropped(channel_type);
                warn_sampled!(
                    plugin = "proxy_alerts",
                    channel = %channel_name,
                    channel_type,
                    "notification dispatch backpressure: dropping alert"
                );
                None
            }
        }
    }

    fn spawn_dispatch(
        &self,
        channel: Arc<NotificationChannel>,
        notification: Arc<Notification>,
        extras: Arc<HashMap<String, String>>,
        permit: OwnedSemaphorePermit,
        pending: Arc<PendingDelivery>,
    ) {
        let generation = Arc::clone(&self.dispatch_generation);
        let retry = self.delivery_retry;
        let http = self.http_client.clone();
        // We already hold `permit`; dispatch_one would try_acquire again. Run
        // the retry loop directly, transferring the permit into the task.
        let on_settle: DeliveryCallback = Arc::new(move |settle| {
            pending.on_settle(settle);
        });
        let channel_type = channel.kind();
        let spawned = generation.spawn(channel_type, Some(on_settle), {
            let channel = Arc::clone(&channel);
            let generation = Arc::clone(&generation);
            async move {
                crate::notifications::dispatch::run_with_retries(
                    channel,
                    notification,
                    extras,
                    http,
                    permit,
                    retry,
                    &generation,
                    "proxy_alerts",
                )
                .await
            }
        });
        if !spawned {
            warn_sampled!(
                plugin = "proxy_alerts",
                channel = %channel.name(),
                channel_type,
                "notification dispatch rejected by delivery generation or shutdown registry"
            );
        }
    }
}

/// Settles one channel's admitted lifecycle event: commits Trigger/Resolve
/// state only after a defined delivery outcome, or rolls the reservation back.
struct PendingDelivery {
    event_action: EventAction,
    rule_id: u32,
    channel_id: u32,
    proxy_id: String,
    ownership_generation: u64,
    /// Reservation token of the lifecycle seat and the cooldown arm (both the
    /// admission `now_ms`).
    reserved_at_ms: u64,
    left_threshold_at_ms: u64,
    cooldowns: Arc<CooldownGate>,
    recovery: Arc<RecoveryGate>,
}

impl PendingDelivery {
    fn on_settle(&self, settle: DispatchSettle) {
        let success = matches!(settle, DispatchSettle::Succeeded);
        match self.event_action {
            EventAction::Resolve => {
                if success {
                    self.recovery.settle_resolve_success(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.reserved_at_ms,
                    );
                } else {
                    self.recovery.settle_resolve_failure(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.left_threshold_at_ms,
                        self.reserved_at_ms,
                    );
                }
            }
            EventAction::Trigger | EventAction::Info => {
                // Initial Triggers settle PendingTrigger; reminders settle
                // PendingReminder back to Active either way.
                if success {
                    self.recovery.settle_trigger_success(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.reserved_at_ms,
                        self.reserved_at_ms,
                    );
                } else {
                    // A failed Trigger/reminder must not keep the cooldown seat.
                    self.cooldowns.release(
                        self.rule_id,
                        &self.proxy_id,
                        self.channel_id,
                        self.ownership_generation,
                        self.reserved_at_ms,
                    );
                    self.recovery.settle_trigger_failure(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.reserved_at_ms,
                    );
                }
            }
        }
    }
}

impl Drop for ProxyAlerts {
    fn drop(&mut self) {
        // Stop admitting and cooperatively cancel in-flight deliveries so a
        // reload cannot keep sending through retired credentials/endpoints.
        // Tasks observe the cancel flag between attempts and settle as
        // abandoned; the global observability registry still owns hard-abort
        // on process-shutdown deadline expiry.
        self.core.dispatch_generation.cancel();
        if let Some(task) = self.lifecycle_task.get() {
            task.abort();
        }
    }
}

fn lifecycle_keep_ms(rules: &[Rule]) -> u64 {
    let mut keep = LIFECYCLE_KEEP_FLOOR_MS;
    for rule in rules {
        let common = rule.common();
        keep = keep.max(common.cooldown_ms);
        keep = keep.max(u64::from(common.window_seconds) * 1000);
        if let Some(recovery) = common.recovery.as_ref() {
            keep = keep.max(recovery.resolved_window_ms);
        }
    }
    keep
}

fn start_lifecycle_task(core: Weak<AlertCore>) -> Option<tokio::task::JoinHandle<()>> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return None;
    };
    Some(handle.spawn(async move {
        let mut ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + LIFECYCLE_TICK, LIFECYCLE_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tick: u32 = 0;
        loop {
            ticker.tick().await;
            // Never extend the instance's life: a dropped plugin ends the task
            // even before its `Drop` abort is observed.
            let Some(core) = core.upgrade() else {
                return;
            };
            let now_ms = monotonic_now_ms();
            core.reevaluate_idle_incidents(now_ms, Utc::now());
            tick = tick.wrapping_add(1);
            if tick.is_multiple_of(EVICTION_EVERY_TICKS) {
                core.sweep_lifecycle(now_ms);
            }
        }
    }))
}

fn lifecycle_event_action(outcome: LifecycleOutcome) -> Option<EventAction> {
    match outcome {
        LifecycleOutcome::Trigger | LifecycleOutcome::StillActive => Some(EventAction::Trigger),
        LifecycleOutcome::Resolve => Some(EventAction::Resolve),
        LifecycleOutcome::EnteringRecovery
        | LifecycleOutcome::Reactivate
        | LifecycleOutcome::Quiet => None,
    }
}

fn non_event_outcome_needs_commit(
    outcome: LifecycleOutcome,
    previous_state: Option<RuleState>,
    recovery_ms: u64,
) -> bool {
    match (outcome, previous_state) {
        (LifecycleOutcome::EnteringRecovery | LifecycleOutcome::Reactivate, _) => true,
        (LifecycleOutcome::Quiet, Some(RuleState::Active { .. })) => true,
        (LifecycleOutcome::Quiet, Some(RuleState::Recovering { .. })) if recovery_ms == 0 => true,
        // A rule that owes a compensating Trigger but is no longer breaching
        // must commit its return to Healthy, otherwise the possibly-delivered
        // Resolve would keep an unnecessary compensating seat resident and the
        // row would never become evictable.
        (LifecycleOutcome::Quiet, Some(RuleState::CompensatingTrigger { .. })) => true,
        _ => false,
    }
}

#[async_trait]
impl Plugin for ProxyAlerts {
    fn name(&self) -> &str {
        "proxy_alerts"
    }

    /// Start the idle re-evaluation / eviction ticker for the installed
    /// generation. Idempotent: a concurrent second call aborts its own task.
    fn commit_background_tasks(&self) {
        if self.lifecycle_task.get().is_some() {
            return;
        }
        if let Some(task) = start_lifecycle_task(Arc::downgrade(&self.core))
            && let Err(duplicate) = self.lifecycle_task.set(task)
        {
            duplicate.abort();
        }
    }

    fn priority(&self) -> u16 {
        super::priority::PROXY_ALERTS
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::LOG
    }

    fn retain_active_proxy_state(&self, active_proxy_generations: &HashMap<&str, u64>) {
        self.retain_proxies(active_proxy_generations);
    }

    #[doc(hidden)]
    fn seed_proxy_lifecycle_state_for_test(&self, proxy_id: &str, generation: u64) {
        self.seed_lifecycle_state_for_test(proxy_id, generation);
    }

    #[doc(hidden)]
    fn has_proxy_lifecycle_state_for_test(&self, proxy_id: &str) -> bool {
        self.has_lifecycle_state_for_test(proxy_id)
    }

    #[doc(hidden)]
    fn has_proxy_lifecycle_state_for_generation_for_test(
        &self,
        proxy_id: &str,
        generation: u64,
    ) -> bool {
        self.has_lifecycle_state_for_generation_for_test(proxy_id, generation)
    }

    #[doc(hidden)]
    fn write_proxy_lifecycle_state_for_test(&self, proxy_id: &str, generation: u64) {
        self.write_lifecycle_state_for_test(proxy_id, generation);
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn is_authorize_plugin(&self) -> bool {
        false
    }

    /// Reusable (issue #5583). This plugin acts only in the post-transaction
    /// observability hooks (`log`, `on_stream_disconnect`, `on_ws_disconnect`):
    /// it takes no admission decision, holds no per-request budget, and never
    /// rejects. Reuse changes only how many tunnel summaries its alert windows
    /// sample — the same fidelity trade every observability surface makes when
    /// one tunnel carries many operations — not what any operation is allowed
    /// to do. The trait default refuses, so this override is a deliberate
    /// opt-in and not an inherited answer.
    fn allows_hbone_inner_reuse(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .core
            .channel_by_id
            .values()
            .flat_map(|channel| channel.warmup_hostnames())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    async fn log(&self, summary: &TransactionSummary) {
        if summary.mirror {
            return;
        }
        self.core.handle(SampleInput::Http(summary));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.core.handle(SampleInput::Stream(summary));
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        self.core.rules.iter().any(Rule::observes_ws_disconnect)
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.core.handle(SampleInput::WebSocket(ctx));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::plugins::utils::http_client::PluginHttpClient;
    use crate::plugins::{Plugin, TransactionSummary};

    use super::*;

    #[tokio::test]
    async fn log_skips_mirror_summaries_before_alert_windows() {
        let cfg = json!({
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 100,
                  "cooldown_seconds": 1, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            mirror: true,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;
        assert_eq!(
            plugin.core.windows.snapshot_count(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION,
                monotonic_now_ms(),
            ),
            (0, 0)
        );

        let mut primary_summary = summary;
        primary_summary.mirror = false;
        plugin.log(&primary_summary).await;
        assert_eq!(
            plugin.core.windows.snapshot_count(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION,
                monotonic_now_ms(),
            ),
            (1, 1)
        );
    }

    #[tokio::test]
    async fn healthy_non_breach_does_not_create_recovery_state() {
        let cfg = json!({
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 1, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 200,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;

        assert_eq!(
            plugin.core.recovery_by_channel[0].current_state(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION
            ),
            None
        );
    }

    #[tokio::test]
    async fn dispatch_backpressure_does_not_consume_trigger_cooldown() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 60, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let _held_permit = plugin
            .core
            .dispatch_sem
            .clone()
            .try_acquire_owned()
            .expect("test should reserve the only dispatch permit");
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;

        assert!(
            plugin.core.cooldowns.try_acquire(
                0,
                "ferrum|p1",
                0,
                60_000,
                monotonic_now_ms(),
                UNARMED_PROXY_LIFECYCLE_GENERATION,
            ),
            "a dropped dispatch must not arm the trigger cooldown"
        );
    }

    #[tokio::test]
    async fn failed_channel_dispatch_releases_permit() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "max_delivery_retries": 0,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1:1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 1, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(permit) = plugin.core.dispatch_sem.clone().try_acquire_owned() {
                    drop(permit);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed webhook dispatch should return its semaphore permit promptly");
    }

    #[tokio::test]
    async fn dispatch_backpressure_does_not_activate_unsent_trigger() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "max_delivery_retries": 0,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 60, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let held_permit = plugin
            .core
            .dispatch_sem
            .clone()
            .try_acquire_owned()
            .expect("test should reserve the only dispatch permit");
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;
        assert_eq!(
            plugin.core.recovery_by_channel[0].current_state(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION
            ),
            None
        );

        drop(held_permit);
        plugin.log(&summary).await;
        // Admission commits PendingTrigger; a failed channel send rolls back
        // to Healthy rather than silently marking Active.
        assert!(matches!(
            plugin.core.recovery_by_channel[0].current_state(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION
            ),
            Some(RuleState::PendingTrigger { .. }) | Some(RuleState::Healthy) | None
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match plugin.core.recovery_by_channel[0].current_state(
                    0,
                    "ferrum|p1",
                    UNARMED_PROXY_LIFECYCLE_GENERATION,
                ) {
                    Some(RuleState::PendingTrigger { .. }) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    other => {
                        assert!(
                            matches!(other, None | Some(RuleState::Healthy)),
                            "failed delivery must not leave a permanently Active incident: {other:?}"
                        );
                        break;
                    }
                }
            }
        })
        .await
        .expect("pending trigger should settle");
    }

    #[tokio::test]
    async fn cooldown_suppressed_initial_trigger_does_not_activate_incident() {
        let cfg = json!({
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 60,
                  "recovery": { "resolved_window_seconds": 5 },
                  "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let now_ms = monotonic_now_ms();
        assert!(plugin.core.cooldowns.try_acquire(
            0,
            "ferrum|p1",
            0,
            60_000,
            now_ms,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
        ));
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;

        assert_eq!(
            plugin.core.recovery_by_channel[0].current_state(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION
            ),
            None,
            "a first trigger suppressed by cooldown must not create a resolvable incident"
        );
    }

    #[tokio::test]
    async fn dispatch_backpressure_does_not_resolve_unsent_recovery() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "max_delivery_retries": 0,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "errors", "type": "error_rate",
                  "status_codes": [500], "threshold_percent": 60.0,
                  "min_request_count": 1,
                  "recovery": { "resolved_window_seconds": 5 },
                  "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        plugin.core.recovery_by_channel[0].observe(
            0,
            "ferrum|p1",
            true,
            5_000,
            1,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
        );
        plugin.core.recovery_by_channel[0].settle_trigger_success(
            0,
            "ferrum|p1",
            UNARMED_PROXY_LIFECYCLE_GENERATION,
            1,
            1,
        );
        plugin.core.recovery_by_channel[0].observe(
            0,
            "ferrum|p1",
            false,
            5_000,
            2,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
        );
        assert!(matches!(
            plugin.core.recovery_by_channel[0].current_state(
                0,
                "ferrum|p1",
                UNARMED_PROXY_LIFECYCLE_GENERATION
            ),
            Some(RuleState::Recovering { .. })
        ));

        let held_permit = plugin
            .core
            .dispatch_sem
            .clone()
            .try_acquire_owned()
            .expect("test should reserve the only dispatch permit");
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 200,
            ..TransactionSummary::default()
        };

        let sample = SampleInput::Http(&summary);
        // Namespace-qualified lifecycle identity the plugin composes internally.
        let owner_key = "ferrum|p1";
        let rule = &plugin.core.rules[0];
        let first_resolve_ms = 5_002;
        let observation = rule
            .observe(sample, &plugin.core.windows, first_resolve_ms)
            .expect("error-rate rule observes HTTP summaries");
        plugin.core.process_observation(
            rule,
            &observation,
            AlertSubject::from_sample(sample),
            owner_key,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
            first_resolve_ms,
            chrono::Utc::now(),
            false,
            None,
        );
        assert!(matches!(
            plugin.core.recovery_by_channel[0].current_state(
                0,
                owner_key,
                UNARMED_PROXY_LIFECYCLE_GENERATION
            ),
            Some(RuleState::Recovering { .. })
        ));

        drop(held_permit);
        let second_resolve_ms = first_resolve_ms + 1;
        let observation = rule
            .observe(sample, &plugin.core.windows, second_resolve_ms)
            .expect("error-rate rule observes HTTP summaries");
        plugin.core.process_observation(
            rule,
            &observation,
            AlertSubject::from_sample(sample),
            owner_key,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
            second_resolve_ms,
            chrono::Utc::now(),
            false,
            None,
        );
        // Admit PendingResolve; the unreachable webhook fails and rolls back to
        // Recovering so a later healthy sample can retry Resolve.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match plugin.core.recovery_by_channel[0].current_state(
                    0,
                    owner_key,
                    UNARMED_PROXY_LIFECYCLE_GENERATION,
                ) {
                    Some(RuleState::PendingResolve { .. }) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Some(RuleState::Recovering { .. }) => break,
                    other => panic!("unexpected resolve settle state: {other:?}"),
                }
            }
        })
        .await
        .expect("failed resolve must roll back to Recovering");
    }
}
