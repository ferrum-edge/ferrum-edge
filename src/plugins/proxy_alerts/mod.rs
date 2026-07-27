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
//! - **Per-`(rule, proxy)` recovery state machine** dispatches a one-shot
//!   `Resolve` event once a rule's window stays below threshold for the
//!   configured `resolved_window_seconds`.
//! - **Bounded-concurrency dispatch**: `tokio::Semaphore`. When exhausted,
//!   alerts are dropped with a `warn!` rather than queued — alert storms
//!   during a partial channel outage should be visible, not buffered.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

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

        Ok(Self {
            rules: parsed.rules,
            channel_by_id: parsed.channel_by_id,
            windows,
            cooldowns,
            recovery,
            active_proxy_generations,
            retention_lock,
            dispatch_sem,
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
                self.recovery.observe(
                    rule.id(),
                    proxy_id,
                    observation.breach,
                    recovery_ms,
                    now_ms,
                    ownership_generation,
                );
            }
            return;
        };
        if event_action == EventAction::Trigger && in_quiet {
            return;
        }
        let mut dispatches: Option<Vec<(Arc<NotificationChannel>, OwnedSemaphorePermit)>> = None;
        let mut cooldown_suppressed = false;
        for &channel_id in &rule.common().channel_ids {
            let Some(channel) = self.channel_by_id.get(&channel_id) else {
                continue;
            };
            let Some(permit) = self.try_acquire_dispatch_permit(channel.name()) else {
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
                .push((Arc::clone(channel), permit));
        }
        let Some(dispatches) = dispatches else {
            if cooldown_suppressed && matches!(outcome, LifecycleOutcome::StillActive) {
                self.recovery.observe(
                    rule.id(),
                    proxy_id,
                    observation.breach,
                    recovery_ms,
                    now_ms,
                    ownership_generation,
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
            return;
        }
        let notification = render::build_notification(rule, observation, sample, event_action, now);
        let extras = render::build_webhook_vars(rule, observation, sample, event_action, now);
        let notification = Arc::new(notification);
        let extras = Arc::new(extras);
        for (channel, permit) in dispatches {
            self.spawn_dispatch(
                channel,
                Arc::clone(&notification),
                Arc::clone(&extras),
                permit,
            );
        }
    }

    fn try_acquire_dispatch_permit(&self, channel_name: &str) -> Option<OwnedSemaphorePermit> {
        match Arc::clone(&self.dispatch_sem).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                warn!(
                    plugin = "proxy_alerts",
                    channel = %channel_name,
                    "notification dispatch backpressure: dropping alert"
                );
                None
            }
        }
    }

    fn spawn_dispatch(
        &self,
        channel: Arc<NotificationChannel>,
        notification: Arc<crate::notifications::Notification>,
        extras: Arc<HashMap<String, String>>,
        permit: OwnedSemaphorePermit,
    ) {
        let http = self.http_client.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = channel
                .dispatch_with_vars(&notification, &extras, &http)
                .await
            {
                warn!(
                    plugin = "proxy_alerts",
                    channel = %channel.name(),
                    error = %e,
                    "notification dispatch failed"
                );
            }
        });
    }
}

impl Drop for ProxyAlerts {
    fn drop(&mut self) {
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
        assert!(matches!(
            plugin
                .recovery
                .current_state(0, "ferrum|p1", UNARMED_PROXY_LIFECYCLE_GENERATION),
            Some(RuleState::Active { .. })
        ));
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
        assert_eq!(
            plugin
                .recovery
                .current_state(0, owner_key, UNARMED_PROXY_LIFECYCLE_GENERATION),
            Some(RuleState::Healthy)
        );
    }
}
