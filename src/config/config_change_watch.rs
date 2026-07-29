//! Backend-native config-change **wake-up** plumbing (issue #3330).
//!
//! A backend that can push change notifications (today: MongoDB replica-set
//! change streams over the durable `config_changes` collection) may signal this
//! module instead of waiting for the next periodic poll tick. The signal is a
//! *coalesced wake-up only*:
//!
//! - It never carries config data, never advances the accepted durable sequence
//!   cursor, and never publishes a runtime config generation.
//! - Every wake-up runs the exact same authoritative cursor-based
//!   incremental/full reload path a periodic tick would have run, so duplicate,
//!   out-of-order, malformed, or entirely missed notifications are harmless.
//! - The periodic poll interval stays armed as the correctness backstop. If the
//!   watcher dies, disconnects, loses change-stream history, or is not supported
//!   by the topology, the gateway degrades to exactly the pre-#3330 behavior.
//!
//! Bounding: notifications collapse into a single [`tokio::sync::Notify`]
//! permit, a wake-up sleeps a short debounce window and then drains any permit
//! stored during it, so a burst of committed mutations produces one reload and
//! the wake rate can never exceed one poll per debounce window.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use crate::config::EnvConfig;

/// Fixed, bounded label set for the watcher's degraded reason. Never contains
/// resource IDs, namespaces, hostnames, or URLs, so it is safe as a metric
/// label and as an authenticated health field.
pub const CONFIG_CHANGE_WATCH_DEGRADED_REASON_LABELS: [&str; 8] = [
    "none",
    "connect_failed",
    "stream_error",
    "history_lost",
    "invalidated",
    "unauthorized",
    "unsupported_topology",
    "stopped",
];

/// Why the config-change watcher is not currently delivering wake-ups.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigChangeWatchDegradedReason {
    /// Connected and healthy.
    None = 0,
    /// Opening the backend watch failed (transient connectivity, election, …).
    ConnectFailed = 1,
    /// An established watch returned an error or ended.
    StreamError = 2,
    /// The retained resume point is no longer in the backend's history.
    HistoryLost = 3,
    /// The watched collection was dropped/renamed and the watch invalidated.
    Invalidated = 4,
    /// The database user is not authorized to open the watch.
    Unauthorized = 5,
    /// The connected topology cannot serve change streams (standalone).
    UnsupportedTopology = 6,
    /// The watcher task exited (shutdown).
    Stopped = 7,
}

impl ConfigChangeWatchDegradedReason {
    pub fn as_str(self) -> &'static str {
        CONFIG_CHANGE_WATCH_DEGRADED_REASON_LABELS[self as usize]
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::ConnectFailed,
            2 => Self::StreamError,
            3 => Self::HistoryLost,
            4 => Self::Invalidated,
            5 => Self::Unauthorized,
            6 => Self::UnsupportedTopology,
            7 => Self::Stopped,
            _ => Self::None,
        }
    }
}

/// Coalescing wake-up channel between a backend watcher task and the
/// authoritative poll loop.
///
/// Backed by a single-permit [`Notify`]: any number of `signal()` calls that
/// land before the poll loop wakes collapse into one wake-up. A signal raised
/// while the poll loop is busy applying a previous reload is retained (not
/// lost), so the loop immediately re-polls afterwards.
#[derive(Debug, Default)]
pub struct ConfigChangeWakeSignal {
    notify: Notify,
    signals_total: AtomicU64,
    wakes_total: AtomicU64,
}

impl ConfigChangeWakeSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Raise a coalesced wake-up. Cheap, lock-free, never blocks, and safe to
    /// call from a watcher task on every observed event.
    pub fn signal(&self) {
        self.signals_total.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_one();
    }

    /// Await the next wake-up. Cancel-safe: a permit consumed by a dropped
    /// `Notified` future is returned to the channel by tokio.
    pub async fn wait(&self) {
        self.notify.notified().await;
        self.wakes_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Consume a pending permit without waiting. Returns `true` when a permit
    /// was drained. Used to collapse a burst that landed during the debounce
    /// window into the wake-up that is about to run.
    pub fn take_pending(&self) -> bool {
        let notified = std::pin::pin!(self.notify.notified());
        futures_util::FutureExt::now_or_never(notified).is_some()
    }

    pub fn signals_total(&self) -> u64 {
        self.signals_total.load(Ordering::Relaxed)
    }

    pub fn wakes_total(&self) -> u64 {
        self.wakes_total.load(Ordering::Relaxed)
    }
}

/// Bounded, authenticated-detail health for a backend config-change watcher.
///
/// Every field is a counter, flag, or fixed enum label. Resource IDs,
/// namespaces, connection strings, and backend error bodies never reach it.
#[derive(Debug, Default)]
pub struct ConfigChangeWatcherHealth {
    enabled: AtomicBool,
    connected: AtomicBool,
    degraded_reason: AtomicU8,
    events_total: AtomicU64,
    reconnects_total: AtomicU64,
    invalidations_total: AtomicU64,
    history_losses_total: AtomicU64,
    resume_token_retained: AtomicBool,
    last_event_unix_ms: AtomicU64,
}

impl ConfigChangeWatcherHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark that a watcher task exists for this process. Until this is called
    /// the watcher is entirely absent from health/metrics output.
    pub fn mark_enabled(&self) {
        self.enabled.store(true, Ordering::Release);
        invalidate_render_cache();
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// A watch is open and delivering events.
    pub fn mark_connected(&self) {
        let was_connected = self.connected.swap(true, Ordering::AcqRel);
        if !was_connected {
            self.reconnects_total.fetch_add(1, Ordering::Relaxed);
        }
        let healthy = ConfigChangeWatchDegradedReason::None as u8;
        self.degraded_reason.store(healthy, Ordering::Release);
        invalidate_render_cache();
    }

    /// The watch is not delivering events. Periodic polling remains
    /// authoritative, so this is a latency signal, not a config-outage signal.
    pub fn mark_degraded(&self, reason: ConfigChangeWatchDegradedReason) {
        self.connected.store(false, Ordering::Release);
        self.degraded_reason.store(reason as u8, Ordering::Release);
        match reason {
            ConfigChangeWatchDegradedReason::Invalidated => {
                self.invalidations_total.fetch_add(1, Ordering::Relaxed);
            }
            ConfigChangeWatchDegradedReason::HistoryLost => {
                self.history_losses_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        invalidate_render_cache();
    }

    /// One observed change notification. Counter only — the render cache is
    /// intentionally not invalidated per event (the poll loop invalidates it on
    /// every completed poll), so an event burst cannot amplify into cache
    /// churn.
    pub fn record_event(&self) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        let millis = chrono::Utc::now().timestamp_millis();
        let millis = if millis < 0 { 0 } else { millis as u64 };
        self.last_event_unix_ms.store(millis, Ordering::Release);
    }

    pub fn set_resume_token_retained(&self, retained: bool) {
        self.resume_token_retained
            .store(retained, Ordering::Release);
    }

    pub fn events_total(&self) -> u64 {
        self.events_total.load(Ordering::Relaxed)
    }

    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub fn degraded_reason(&self) -> ConfigChangeWatchDegradedReason {
        ConfigChangeWatchDegradedReason::from_u8(self.degraded_reason.load(Ordering::Acquire))
    }

    /// Bounded snapshot, or `None` when no watcher was ever started for this
    /// process (SQL backends, standalone MongoDB with the feature off, …).
    pub fn snapshot(&self) -> Option<ConfigChangeWatcherStatus> {
        if !self.enabled() {
            return None;
        }
        let last_event_unix_ms = self.last_event_unix_ms.load(Ordering::Acquire);
        let last_event_at = if last_event_unix_ms == 0 {
            None
        } else {
            chrono::DateTime::from_timestamp_millis(last_event_unix_ms as i64)
                .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        };
        Some(ConfigChangeWatcherStatus {
            enabled: true,
            connected: self.connected(),
            degraded_reason: self.degraded_reason().as_str(),
            events_total: self.events_total(),
            reconnects_total: self.reconnects_total.load(Ordering::Relaxed),
            invalidations_total: self.invalidations_total.load(Ordering::Relaxed),
            history_losses_total: self.history_losses_total.load(Ordering::Relaxed),
            resume_token_retained: self.resume_token_retained.load(Ordering::Acquire),
            last_event_at,
            last_event_unix_ms,
        })
    }
}

/// Marks a watcher `stopped` when its task ends for **any** reason, including
/// a panic or an abort during shutdown.
///
/// Without this, a task that died unexpectedly would keep reporting
/// `connected: true` forever while wake-ups silently stopped. Periodic polling
/// still applies every committed change either way; this only keeps the
/// operator-visible signal honest.
pub struct ConfigChangeWatcherStopGuard {
    health: Arc<ConfigChangeWatcherHealth>,
}

impl ConfigChangeWatcherStopGuard {
    pub fn new(health: Arc<ConfigChangeWatcherHealth>) -> Self {
        Self { health }
    }
}

impl Drop for ConfigChangeWatcherStopGuard {
    fn drop(&mut self) {
        self.health
            .mark_degraded(ConfigChangeWatchDegradedReason::Stopped);
    }
}

fn invalidate_render_cache() {
    crate::plugins::prometheus_metrics::global_registry()
        .invalidate_database_delta_poll_metrics_cache();
}

/// Serialized watcher state for authenticated `/health` + `/admin/metrics`.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct ConfigChangeWatcherStatus {
    /// A watcher task was started for this process.
    pub enabled: bool,
    /// A watch is currently open and delivering wake-ups.
    pub connected: bool,
    /// Fixed label from [`CONFIG_CHANGE_WATCH_DEGRADED_REASON_LABELS`].
    pub degraded_reason: &'static str,
    pub events_total: u64,
    pub reconnects_total: u64,
    pub invalidations_total: u64,
    pub history_losses_total: u64,
    /// Whether a resume point is currently retained in memory. Resume tokens
    /// are never persisted and never logged.
    pub resume_token_retained: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<String>,
    /// Unix millis companion for gauges; omitted from JSON.
    #[serde(skip)]
    pub last_event_unix_ms: u64,
}

/// Operator-tunable watcher settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigChangeWatchSettings {
    /// Opt-in master switch (`FERRUM_MONGO_CHANGE_STREAM_ENABLED`).
    pub enabled: bool,
    /// Burst-coalescing window applied before a stream-triggered reload.
    pub debounce: Duration,
    /// First reconnect delay after a watch failure.
    pub initial_backoff: Duration,
    /// Reconnect delay ceiling.
    pub max_backoff: Duration,
}

impl Default for ConfigChangeWatchSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            debounce: Duration::from_millis(250),
            initial_backoff: Duration::from_secs(crate::util::backoff::BACKOFF_INITIAL_SECS),
            max_backoff: Duration::from_secs(crate::util::backoff::BACKOFF_MAX_SECS),
        }
    }
}

impl ConfigChangeWatchSettings {
    /// Build from parsed env config. Bounds are already clamped by
    /// `EnvConfig`; this only re-derives the invariant `initial <= max`.
    pub fn from_env(env_config: &EnvConfig) -> Self {
        let max_backoff = Duration::from_secs(env_config.mongo_change_stream_max_backoff_seconds);
        let initial_backoff =
            Duration::from_secs(crate::util::backoff::BACKOFF_INITIAL_SECS).min(max_backoff);
        Self {
            enabled: env_config.mongo_change_stream_enabled,
            debounce: Duration::from_millis(env_config.mongo_change_stream_debounce_ms),
            initial_backoff,
            max_backoff,
        }
    }
}

/// Next reconnect delay in seconds: double, capped at `max_secs`, floored at
/// `initial_secs`. `current_secs == 0` means "first failure".
pub fn next_config_change_watch_backoff_secs(
    current_secs: u64,
    initial_secs: u64,
    max_secs: u64,
) -> u64 {
    let max_secs = max_secs.max(1);
    let initial_secs = initial_secs.clamp(1, max_secs);
    if current_secs == 0 {
        return initial_secs;
    }
    current_secs.saturating_mul(2).clamp(initial_secs, max_secs)
}

/// Next reconnect delay after one watch-session outcome.
///
/// `delivered_usable_event` is true only when the session observed at least one
/// non-lifecycle change-stream event (healthy progress). A successful `watch()`
/// open alone must pass `false`: servers that accept the watch and then
/// immediately end/error would otherwise forever restart at the initial delay
/// instead of escalating toward `max_secs`.
pub fn config_change_watch_backoff_after_session(
    previous_backoff_secs: u64,
    initial_secs: u64,
    max_secs: u64,
    delivered_usable_event: bool,
) -> u64 {
    let base = if delivered_usable_event {
        0
    } else {
        previous_backoff_secs
    };
    next_config_change_watch_backoff_secs(base, initial_secs, max_secs)
}

/// MongoDB `Unauthorized`. The database user may not open the watch.
pub const MONGO_ERR_UNAUTHORIZED: i32 = 13;
/// MongoDB `ChangeStreamFatalError` — the stream cannot resume from its token.
pub const MONGO_ERR_CHANGE_STREAM_FATAL: i32 = 280;
/// MongoDB `ChangeStreamHistoryLost` — the oplog no longer covers the resume
/// point, so the retained token must be dropped and the watch re-opened from
/// now. The authoritative sequence cursor is what repairs the gap.
pub const MONGO_ERR_CHANGE_STREAM_HISTORY_LOST: i32 = 286;

/// Character cap applied to any backend error text the watcher logs, after URL
/// redaction. Bounds log volume from a repeating backend failure.
pub const WATCH_ERROR_LOG_CHARS: usize = 300;

/// Classify a MongoDB change-stream failure into a bounded degraded reason.
///
/// Deliberately consumes only the server command code plus the
/// authentication-failure shape: the driver's error text is never inspected for
/// classification and never becomes a label.
pub fn classify_mongo_change_stream_failure(
    command_code: Option<i32>,
    authentication_failure: bool,
) -> ConfigChangeWatchDegradedReason {
    if let Some(code) = command_code {
        return match code {
            MONGO_ERR_CHANGE_STREAM_HISTORY_LOST | MONGO_ERR_CHANGE_STREAM_FATAL => {
                ConfigChangeWatchDegradedReason::HistoryLost
            }
            MONGO_ERR_UNAUTHORIZED => ConfigChangeWatchDegradedReason::Unauthorized,
            _ => ConfigChangeWatchDegradedReason::StreamError,
        };
    }
    if authentication_failure {
        ConfigChangeWatchDegradedReason::Unauthorized
    } else {
        ConfigChangeWatchDegradedReason::StreamError
    }
}

/// Bound already-redacted backend error text before it reaches a log line.
pub fn truncate_watch_error(text: &str) -> String {
    if text.chars().count() <= WATCH_ERROR_LOG_CHARS {
        return text.to_string();
    }
    let truncated: String = text.chars().take(WATCH_ERROR_LOG_CHARS).collect();
    format!("{truncated}… (truncated)")
}

/// What woke the authoritative poll loop for this iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPollWake {
    /// The periodic backstop interval elapsed.
    Interval,
    /// A backend watcher signalled a committed config change.
    ChangeStream,
}

/// Await the next authoritative poll iteration.
///
/// Without a watcher this is exactly `interval.tick()`. With one, a wake-up
/// short-circuits the interval, sleeps `debounce` so a burst of committed
/// mutations coalesces, drains any permit raised during that window, and resets
/// the periodic interval so the backstop measures from the reload that is about
/// to run. The returned wake source never changes what the caller does next:
/// both paths run the same authoritative cursor work.
///
/// `earliest_wake` is the caller's active retry deadline (today: the
/// rejected-delta backoff). A wake-up never runs before it, so a stream of
/// committed-but-rejected changes cannot defeat the poll loop's backoff. A
/// deadline in the past is a no-op.
///
/// Cancel-safe — the caller may race this against a shutdown signal.
pub async fn wait_for_config_poll_wake(
    interval: &mut tokio::time::Interval,
    wake: Option<&Arc<ConfigChangeWakeSignal>>,
    debounce: Duration,
    earliest_wake: Option<tokio::time::Instant>,
) -> ConfigPollWake {
    let Some(wake) = wake else {
        interval.tick().await;
        return ConfigPollWake::Interval;
    };
    tokio::select! {
        _ = interval.tick() => ConfigPollWake::Interval,
        _ = wake.wait() => {
            if let Some(deadline) = earliest_wake {
                tokio::time::sleep_until(deadline).await;
            }
            if !debounce.is_zero() {
                tokio::time::sleep(debounce).await;
            }
            // One authoritative poll covers every change committed during the
            // window, so drop the permits they raised.
            wake.take_pending();
            interval.reset();
            ConfigPollWake::ChangeStream
        }
    }
}

/// Everything a backend needs to run a config-change wake-up watcher.
pub struct ConfigChangeWakeWatcherParams {
    /// The gateway's namespace. The watcher must filter to it so a co-tenant
    /// namespace's mutations cannot wake (or leak into) this gateway.
    pub namespace: String,
    pub signal: Arc<ConfigChangeWakeSignal>,
    pub health: Arc<ConfigChangeWatcherHealth>,
    pub settings: ConfigChangeWatchSettings,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
    /// Connection URLs scrubbed out of any backend error text before logging.
    pub redact_urls: Vec<String>,
}
