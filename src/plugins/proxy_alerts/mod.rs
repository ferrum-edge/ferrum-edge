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
//! - **Per-`(rule, proxy, channel)` cooldown** prevents repeated dispatches
//!   without suppressing unrelated proxies that share a global/group rule.
//!   Cooldown is armed at dispatch admission and released if delivery fails
//!   or is abandoned, so a failed send does not silently consume the window.
//! - **Pending delivery seats**: Trigger/Resolve commit
//!   `PendingTrigger` / `PendingResolve` when a send is admitted; state moves
//!   to `Active` / `Healthy` only after a successful settle (or rolls back on
//!   failure so the next sample can retry).
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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use crate::notifications::dispatch::{DeliveryCallback, DeliveryRetryPolicy};
use crate::notifications::generation::{DispatchGeneration, DispatchSettle};
use crate::notifications::{EventAction, NotificationChannel};
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
use rules::{Rule, RuleObservation, SampleInput};
use windows::{WindowStore, monotonic_now_ms};

/// Floor for background lifecycle retention, matching the historical window
/// sweep cadence documented for inactive proxies.
const LIFECYCLE_KEEP_FLOOR_MS: u64 = 3_600_000;

/// Ownership generation used by offline / unarmed unit tests that intentionally
/// omit an admission token. Armed production instances reject missing tokens
/// before any lifecycle write.
pub const UNARMED_PROXY_LIFECYCLE_GENERATION: u64 = 0;

static NEXT_DISPATCH_GENERATION: AtomicU64 = AtomicU64::new(1);

pub struct ProxyAlerts {
    rules: Arc<Vec<Rule>>,
    channel_by_id: Arc<HashMap<u32, Arc<NotificationChannel>>>,
    windows: Arc<WindowStore>,
    cooldowns: Arc<CooldownGate>,
    recovery: Arc<RecoveryGate>,
    /// Published ownership generations for proxies this instance may observe.
    /// `None` until the first cold-path retain (unit tests that never retain
    /// keep the historical ungated write path). After retain, writes require a
    /// matching admitted generation.
    active_proxy_generations: Arc<ArcSwap<Option<HashMap<String, u64>>>>,
    /// Serializes full ownership retention passes (commit-path retain and the
    /// background ownership sweep). Request observation only loads the
    /// ArcSwap snapshot and never takes this lock.
    retention_lock: Arc<Mutex<()>>,
    dispatch_sem: Arc<Semaphore>,
    /// Per-instance dispatch generation: closed and cancelled on Drop so
    /// reload retires in-flight sends without leaking them into the next
    /// plugin incarnation.
    dispatch_generation: Arc<DispatchGeneration>,
    delivery_retry: DeliveryRetryPolicy,
    http_client: PluginHttpClient,
    enabled: AtomicBool,
    quiet_hours: Arc<Vec<QuietHourWindow>>,
    /// Eviction sweep handle for runtime plugin instances. `None` when the
    /// plugin was instantiated by an offline validation path without a Tokio
    /// runtime.
    eviction_handle: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for ProxyAlerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAlerts")
            .field("rules", &self.rules.len())
            .field("channels", &self.channel_by_id.len())
            .field("enabled", &self.enabled.load(Ordering::Acquire))
            .field("quiet_hours", &self.quiet_hours.len())
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
        let parsed = ProxyAlertsConfig::parse(config)?;

        let rule_specs = parsed
            .rules
            .iter()
            .map(|r| (r.id(), r.window_spec()))
            .collect();
        let windows = Arc::new(WindowStore::new(rule_specs));
        let cooldowns = Arc::new(CooldownGate::new());
        let recovery = Arc::new(RecoveryGate::new());
        let lifecycle_keep_ms = lifecycle_keep_ms(parsed.rules.as_ref());
        let active_proxy_generations = Arc::new(ArcSwap::from_pointee(None));
        let retention_lock = Arc::new(Mutex::new(()));
        let eviction_handle = start_lifecycle_eviction_task(
            Arc::clone(&windows),
            Arc::clone(&cooldowns),
            Arc::clone(&recovery),
            Arc::clone(&active_proxy_generations),
            Arc::clone(&retention_lock),
            lifecycle_keep_ms,
        );

        let dispatch_sem = Arc::new(Semaphore::new(parsed.max_concurrent_dispatches));
        let dispatch_generation =
            DispatchGeneration::new(NEXT_DISPATCH_GENERATION.fetch_add(1, Ordering::Relaxed));

        Ok(Self {
            rules: parsed.rules,
            channel_by_id: parsed.channel_by_id,
            windows,
            cooldowns,
            recovery,
            active_proxy_generations,
            retention_lock,
            dispatch_sem,
            dispatch_generation,
            delivery_retry: parsed.delivery_retry,
            http_client,
            enabled: AtomicBool::new(parsed.enabled),
            quiet_hours: Arc::new(parsed.quiet_hours),
            eviction_handle,
        })
    }

    fn retention_guard(&self) -> MutexGuard<'_, ()> {
        self.retention_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Publish ownership generations and retire per-proxy window/cooldown/
    /// recovery rows for proxies absent from that map or whose stored
    /// generation does not match the published incarnation.
    ///
    /// Invoked from the plugin-cache commit path for preserved global and
    /// proxy-group instances. Must not run on the request hot path.
    pub fn retain_proxies(&self, active_proxy_generations: &HashMap<&str, u64>) {
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
        self.windows.retain_proxies(&borrowed);
        self.cooldowns.retain_proxies(&borrowed);
        self.recovery.retain_proxies(&borrowed);
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

    /// Seed cooldown + Active recovery state for deterministic external tests.
    #[doc(hidden)]
    pub fn seed_lifecycle_state_for_test(&self, proxy_id: &str, generation: u64) {
        // Ensure the seeded proxy is owned under `generation` so subsequent
        // gated writes from the same incarnation succeed in tests.
        let mut map = self
            .active_proxy_generations
            .load()
            .as_ref()
            .clone()
            .unwrap_or_default();
        map.insert(proxy_id.to_string(), generation);
        self.active_proxy_generations.store(Arc::new(Some(map)));
        let _ = self
            .cooldowns
            .try_acquire(0, proxy_id, 0, 60_000, 1, generation);
        let _ = self
            .recovery
            .observe(0, proxy_id, true, 5_000, 1, generation);
        // observe now lands on PendingTrigger; commit Active for seeders that
        // need a fully-delivered incident (plugin-cache retention tests).
        self.recovery
            .settle_trigger_success(0, proxy_id, generation, 1, 1);
    }

    /// Whether this instance currently holds lifecycle state for `proxy_id`
    /// under any ownership generation.
    #[doc(hidden)]
    pub fn has_lifecycle_state_for_test(&self, proxy_id: &str) -> bool {
        self.cooldowns.contains_proxy(proxy_id)
            || self.recovery.contains_proxy(proxy_id)
            || self.windows.contains_proxy(proxy_id)
    }

    /// Whether this instance holds lifecycle state for `(proxy_id, generation)`.
    #[doc(hidden)]
    pub fn has_lifecycle_state_for_generation_for_test(
        &self,
        proxy_id: &str,
        generation: u64,
    ) -> bool {
        self.cooldowns
            .contains_proxy_generation(proxy_id, generation)
            || self
                .recovery
                .contains_proxy_generation(proxy_id, generation)
            || self.windows.contains_proxy_generation(proxy_id, generation)
    }

    /// Direct store write that bypasses the admission precheck — used by
    /// deterministic race-contract tests to prove generation-keyed isolation
    /// even when a stale writer races past retain publication.
    #[doc(hidden)]
    pub fn write_lifecycle_state_for_test(&self, proxy_id: &str, generation: u64) {
        if let Some(rule) = self.rules.first() {
            self.windows
                .record_count(rule.id(), proxy_id, generation, true, 1);
        }
        let _ = self
            .cooldowns
            .try_acquire(0, proxy_id, 0, 60_000, 1, generation);
        let _ = self
            .recovery
            .observe(0, proxy_id, true, 5_000, 1, generation);
        self.recovery
            .settle_trigger_success(0, proxy_id, generation, 1, 1);
    }

    /// Run the ownership portion of the background lifecycle sweep without
    /// waiting for its one-minute cadence.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn sweep_lifecycle_ownership_for_test(&self) {
        retain_published_proxy_generations(
            &self.windows,
            &self.cooldowns,
            &self.recovery,
            &self.active_proxy_generations,
            &self.retention_lock,
        );
    }

    /// Hold the cold-path retention lock for deterministic serialization tests.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn with_retention_lock_for_test<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.retention_guard();
        f()
    }

    /// Whether the retention lock is free (`true`) or held (`false`).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn try_retention_lock_for_test(&self) -> bool {
        self.retention_lock.try_lock().is_ok()
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
        self.active_proxy_generations.store(Arc::new(Some(owned)));
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
            let in_quiet = self.quiet_hours.iter().any(|w| w.matches(now));
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
                    sample,
                    owner_key,
                    now_ms,
                    now,
                    in_quiet,
                );
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn process_observation(
        &self,
        rule: &Rule,
        observation: &RuleObservation,
        sample: SampleInput<'_>,
        owner_key: &str,
        now_ms: u64,
        now: chrono::DateTime<chrono::Utc>,
        in_quiet: bool,
    ) {
        // Namespace-qualified lifecycle identity; `sample` still carries the
        // bare proxy name/namespace used for notification rendering.
        let proxy_id = owner_key;
        let ownership_generation = sample
            .proxy_lifecycle_generation()
            .unwrap_or(UNARMED_PROXY_LIFECYCLE_GENERATION);
        let previous_state = self
            .recovery
            .current_state(rule.id(), proxy_id, ownership_generation);
        if observation.breach
            && in_quiet
            && matches!(previous_state, None | Some(RuleState::Healthy))
        {
            return;
        }
        let recovery_ms = rule
            .common()
            .recovery
            .as_ref()
            .map(|r| r.resolved_window_ms)
            .unwrap_or(0);
        let outcome = self.recovery.evaluate(
            rule.id(),
            proxy_id,
            observation.breach,
            recovery_ms,
            now_ms,
            ownership_generation,
        );
        let Some(event_action) = lifecycle_event_action(outcome) else {
            if non_event_outcome_needs_commit(outcome, previous_state, recovery_ms) {
                // Commit the non-event transition, but if evaluate→observe
                // raced into an event-reserving seat (no dispatch was admitted
                // on this path), roll that exact reservation back immediately.
                let committed = self.recovery.observe(
                    rule.id(),
                    proxy_id,
                    observation.breach,
                    recovery_ms,
                    now_ms,
                    ownership_generation,
                );
                self.recovery.rollback_unadmitted_reservation(
                    rule.id(),
                    proxy_id,
                    ownership_generation,
                    committed,
                    now_ms,
                );
            }
            return;
        };
        if event_action == EventAction::Trigger && in_quiet {
            return;
        }
        let mut dispatches: Option<Vec<(Arc<NotificationChannel>, u32, OwnedSemaphorePermit)>> =
            None;
        let mut cooldown_suppressed = false;
        for &channel_id in &rule.common().channel_ids {
            let Some(channel) = self.channel_by_id.get(&channel_id) else {
                continue;
            };
            let Some(permit) = self.try_acquire_dispatch_permit(channel.name(), channel.kind())
            else {
                continue;
            };
            let cooldown_ok = match event_action {
                EventAction::Resolve => true,
                _ => self.cooldowns.try_acquire(
                    rule.id(),
                    proxy_id,
                    channel_id,
                    rule.common().cooldown_ms,
                    now_ms,
                    ownership_generation,
                ),
            };
            if !cooldown_ok {
                cooldown_suppressed = true;
                continue;
            }
            dispatches
                .get_or_insert_with(Vec::new)
                .push((Arc::clone(channel), channel_id, permit));
        }
        let Some(dispatches) = dispatches else {
            if cooldown_suppressed && matches!(outcome, LifecycleOutcome::StillActive) {
                // Same class of race as the non-event commit path: observe may
                // reserve Trigger/Resolve without an admitted delivery.
                let committed = self.recovery.observe(
                    rule.id(),
                    proxy_id,
                    observation.breach,
                    recovery_ms,
                    now_ms,
                    ownership_generation,
                );
                self.recovery.rollback_unadmitted_reservation(
                    rule.id(),
                    proxy_id,
                    ownership_generation,
                    committed,
                    now_ms,
                );
            }
            return;
        };
        let committed_outcome = self.recovery.observe(
            rule.id(),
            proxy_id,
            observation.breach,
            recovery_ms,
            now_ms,
            ownership_generation,
        );
        if lifecycle_event_action(committed_outcome) != Some(event_action) {
            // State raced; release cooldowns we just armed and drop permits.
            if event_action != EventAction::Resolve {
                for (_, channel_id, _) in &dispatches {
                    self.cooldowns.release(
                        rule.id(),
                        proxy_id,
                        *channel_id,
                        ownership_generation,
                        now_ms,
                    );
                }
            }
            // `observe` may have committed a different event reservation than
            // the one evaluated above. No delivery is admitted for that
            // mismatched event, so roll its exact token back as well.
            self.recovery.rollback_unadmitted_reservation(
                rule.id(),
                proxy_id,
                ownership_generation,
                committed_outcome,
                now_ms,
            );
            return;
        }
        let (left_threshold_at_ms, recovery_reserved_at_ms) =
            match self
                .recovery
                .current_state(rule.id(), proxy_id, ownership_generation)
            {
                Some(RuleState::PendingResolve {
                    left_threshold_at_ms,
                    reserved_at_ms,
                }) => (left_threshold_at_ms, reserved_at_ms),
                Some(RuleState::PendingTrigger { reserved_at_ms }) => (now_ms, reserved_at_ms),
                _ => (now_ms, now_ms),
            };
        let notification = render::build_notification(rule, observation, sample, event_action, now);
        let extras = render::build_webhook_vars(rule, observation, sample, event_action, now);
        let notification = Arc::new(notification);
        let extras = Arc::new(extras);
        let pending = Arc::new(PendingDeliveryFanout {
            remaining: AtomicUsize::new(dispatches.len()),
            any_success: AtomicBool::new(false),
            event_action,
            rule_id: rule.id(),
            proxy_id: proxy_id.to_string(),
            ownership_generation,
            fired_at_ms: now_ms,
            left_threshold_at_ms,
            recovery_reserved_at_ms,
            cooldown_reserved_at_ms: now_ms,
            cooldowns: Arc::clone(&self.cooldowns),
            recovery: Arc::clone(&self.recovery),
        });
        for (channel, channel_id, permit) in dispatches {
            self.spawn_dispatch(
                channel,
                channel_id,
                Arc::clone(&notification),
                Arc::clone(&extras),
                permit,
                Arc::clone(&pending),
            );
        }
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
                warn!(
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
        channel_id: u32,
        notification: Arc<crate::notifications::Notification>,
        extras: Arc<HashMap<String, String>>,
        permit: OwnedSemaphorePermit,
        pending: Arc<PendingDeliveryFanout>,
    ) {
        let generation = Arc::clone(&self.dispatch_generation);
        let retry = self.delivery_retry;
        let http = self.http_client.clone();
        // Re-insert the already-acquired permit by transferring ownership into
        // the spawned task via the dispatch helper's permit parameter. We
        // already hold `permit`; dispatch_one would try_acquire again. Run the
        // retry loop directly instead.
        let on_settle: DeliveryCallback = Arc::new({
            let pending = Arc::clone(&pending);
            move |settle| {
                pending.on_channel_settle(channel_id, settle);
            }
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
            warn!(
                plugin = "proxy_alerts",
                channel = %channel.name(),
                channel_type,
                "notification dispatch rejected by delivery generation or shutdown registry"
            );
        }
    }

    /// Cancel admission for this instance's dispatch generation (test hook).
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn cancel_dispatch_generation_for_test(&self) {
        self.dispatch_generation.cancel();
    }

    /// Borrow this instance's dispatch generation so a deterministic external
    /// test can observe retirement and drain *after* the plugin itself has been
    /// dropped (the reload boundary this contract is about).
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn dispatch_generation_for_test(&self) -> Arc<DispatchGeneration> {
        Arc::clone(&self.dispatch_generation)
    }

    /// Borrow this instance's recovery gate so a deterministic external test can
    /// assert producer state settled after the plugin was dropped.
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn recovery_gate_for_test(&self) -> Arc<RecoveryGate> {
        Arc::clone(&self.recovery)
    }

    /// In-flight dispatch count for this instance generation.
    #[doc(hidden)]
    // External tests consume this through the library target; the binary target
    // recompiles the module tree without that caller.
    #[allow(dead_code)]
    pub fn dispatch_in_flight_for_test(&self) -> usize {
        self.dispatch_generation.in_flight()
    }

    /// Current recovery state for deterministic external delivery tests.
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
        self.recovery
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
        self.cooldowns.try_acquire(
            rule_id,
            proxy_id,
            channel_id,
            cooldown_ms,
            now_ms,
            ownership_generation,
        )
    }
}

/// Coordinates fan-out settle across every channel admitted for one lifecycle
/// event so Trigger/Resolve state commits only after a defined delivery
/// outcome.
struct PendingDeliveryFanout {
    remaining: AtomicUsize,
    any_success: AtomicBool,
    event_action: EventAction,
    rule_id: u32,
    proxy_id: String,
    ownership_generation: u64,
    fired_at_ms: u64,
    left_threshold_at_ms: u64,
    recovery_reserved_at_ms: u64,
    cooldown_reserved_at_ms: u64,
    cooldowns: Arc<CooldownGate>,
    recovery: Arc<RecoveryGate>,
}

impl PendingDeliveryFanout {
    fn on_channel_settle(&self, channel_id: u32, settle: DispatchSettle) {
        let success = matches!(settle, DispatchSettle::Succeeded);
        if success {
            self.any_success.store(true, Ordering::Release);
        } else if self.event_action != EventAction::Resolve {
            // Failed Trigger/StillActive must not keep the cooldown seat.
            self.cooldowns.release(
                self.rule_id,
                &self.proxy_id,
                channel_id,
                self.ownership_generation,
                self.cooldown_reserved_at_ms,
            );
        }
        if self.remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // Last channel settled: commit or roll back incident state.
        match self.event_action {
            EventAction::Resolve => {
                if self.any_success.load(Ordering::Acquire) {
                    self.recovery.settle_resolve_success(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.recovery_reserved_at_ms,
                    );
                } else {
                    self.recovery.settle_resolve_failure(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.left_threshold_at_ms,
                        self.recovery_reserved_at_ms,
                    );
                }
            }
            EventAction::Trigger | EventAction::Info => {
                // StillActive re-triggers leave Active in place; only the
                // initial PendingTrigger path needs settle. settle_* no-ops
                // when state is already Active.
                if self.any_success.load(Ordering::Acquire) {
                    self.recovery.settle_trigger_success(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.recovery_reserved_at_ms,
                        self.fired_at_ms,
                    );
                } else {
                    self.recovery.settle_trigger_failure(
                        self.rule_id,
                        &self.proxy_id,
                        self.ownership_generation,
                        self.recovery_reserved_at_ms,
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
        self.dispatch_generation.cancel();
        if let Some(handle) = self.eviction_handle.take() {
            handle.abort();
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

fn start_lifecycle_eviction_task(
    windows: Arc<WindowStore>,
    cooldowns: Arc<CooldownGate>,
    recovery: Arc<RecoveryGate>,
    active_proxy_generations: Arc<ArcSwap<Option<HashMap<String, u64>>>>,
    retention_lock: Arc<Mutex<()>>,
    keep_ms: u64,
) -> Option<tokio::task::JoinHandle<()>> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return None;
    };
    Some(handle.spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let now_ms = windows::monotonic_now_ms();
            // A sample can pass the admission-generation check immediately
            // before a cache commit and finish its write immediately after the
            // commit-time retain. Generation-keying isolates that row from the
            // replacement; periodically reapplying the published ownership map
            // also bounds the orphan rather than leaving an old-generation
            // Active/Recovering recovery row resident indefinitely. The
            // retention lock ensures this sweep loads the latest published map
            // and cannot interleave with a commit-path retain pass.
            retain_published_proxy_generations(
                &windows,
                &cooldowns,
                &recovery,
                &active_proxy_generations,
                &retention_lock,
            );
            windows.evict_stale(now_ms, keep_ms);
            cooldowns.evict_stale(now_ms, keep_ms);
            recovery.evict_resolved();
        }
    }))
}

fn retain_published_proxy_generations(
    windows: &WindowStore,
    cooldowns: &CooldownGate,
    recovery: &RecoveryGate,
    active_proxy_generations: &ArcSwap<Option<HashMap<String, u64>>>,
    retention_lock: &Mutex<()>,
) {
    let _guard = retention_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Load only after acquiring the serialization guard so a concurrent
    // commit cannot publish a newer map and finish retaining before this
    // pass still deletes against a stale snapshot.
    let active = active_proxy_generations.load();
    let Some(active) = active.as_ref() else {
        return;
    };
    let borrowed: HashMap<&str, u64> = active
        .iter()
        .map(|(proxy_id, generation)| (proxy_id.as_str(), *generation))
        .collect();
    windows.retain_proxies(&borrowed);
    cooldowns.retain_proxies(&borrowed);
    recovery.retain_proxies(&borrowed);
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

    fn priority(&self) -> u16 {
        super::priority::PROXY_ALERTS
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

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
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
        self.handle(SampleInput::Http(summary));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.handle(SampleInput::Stream(summary));
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        self.rules.iter().any(Rule::observes_ws_disconnect)
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.handle(SampleInput::WebSocket(ctx));
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
            plugin.windows.snapshot_count(
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
            plugin.windows.snapshot_count(
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
            plugin
                .recovery
                .current_state(0, "ferrum|p1", UNARMED_PROXY_LIFECYCLE_GENERATION),
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
            plugin.cooldowns.try_acquire(
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
                if let Ok(permit) = plugin.dispatch_sem.clone().try_acquire_owned() {
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
            plugin
                .recovery
                .current_state(0, "ferrum|p1", UNARMED_PROXY_LIFECYCLE_GENERATION),
            None
        );

        drop(held_permit);
        plugin.log(&summary).await;
        // Admission commits PendingTrigger; a failed channel send rolls back
        // to Healthy rather than silently marking Active.
        assert!(matches!(
            plugin
                .recovery
                .current_state(0, "ferrum|p1", UNARMED_PROXY_LIFECYCLE_GENERATION),
            Some(RuleState::PendingTrigger { .. }) | Some(RuleState::Healthy) | None
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match plugin.recovery.current_state(
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
        assert!(plugin.cooldowns.try_acquire(
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
            plugin
                .recovery
                .current_state(0, "ferrum|p1", UNARMED_PROXY_LIFECYCLE_GENERATION),
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
        plugin.recovery.observe(
            0,
            "ferrum|p1",
            true,
            5_000,
            1,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
        );
        plugin.recovery.settle_trigger_success(
            0,
            "ferrum|p1",
            UNARMED_PROXY_LIFECYCLE_GENERATION,
            1,
            1,
        );
        plugin.recovery.observe(
            0,
            "ferrum|p1",
            false,
            5_000,
            2,
            UNARMED_PROXY_LIFECYCLE_GENERATION,
        );
        assert!(matches!(
            plugin
                .recovery
                .current_state(0, "ferrum|p1", UNARMED_PROXY_LIFECYCLE_GENERATION),
            Some(RuleState::Recovering { .. })
        ));

        let held_permit = plugin
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
        let rule = &plugin.rules[0];
        let first_resolve_ms = 5_002;
        let observation = rule
            .observe(sample, &plugin.windows, first_resolve_ms)
            .expect("error-rate rule observes HTTP summaries");
        plugin.process_observation(
            rule,
            &observation,
            sample,
            owner_key,
            first_resolve_ms,
            chrono::Utc::now(),
            false,
        );
        assert!(matches!(
            plugin
                .recovery
                .current_state(0, owner_key, UNARMED_PROXY_LIFECYCLE_GENERATION),
            Some(RuleState::Recovering { .. })
        ));

        drop(held_permit);
        let second_resolve_ms = first_resolve_ms + 1;
        let observation = rule
            .observe(sample, &plugin.windows, second_resolve_ms)
            .expect("error-rate rule observes HTTP summaries");
        plugin.process_observation(
            rule,
            &observation,
            sample,
            owner_key,
            second_resolve_ms,
            chrono::Utc::now(),
            false,
        );
        // Admit PendingResolve; the unreachable webhook fails and rolls back to
        // Recovering so a later healthy sample can retry Resolve.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match plugin.recovery.current_state(
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
