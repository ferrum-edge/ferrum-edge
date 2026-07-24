//! Database mode — single-instance gateway backed by PostgreSQL, MySQL, or SQLite.
//!
//! Lifecycle:
//! 1. Connect to the primary DB (with failover URL retry)
//! 2. Optionally connect a read replica for admin read offload
//! 3. Load full config from DB (falls back to on-disk JSON backup if DB is unreachable)
//! 4. Build all caches (router, plugin, consumer, load balancer, circuit breaker)
//! 5. Start proxy + admin listeners
//! 6. Enter the polling loop: read durable config changes after the accepted
//!    sequence cursor, with automatic fallback to full reload + DB failover on error
//!
//! The admin API is read/write in this mode. A `db_available` AtomicBool gates
//! write endpoints — when the DB is unreachable, the admin API becomes temporarily
//! read-only and returns 503 on mutations.

use anyhow::Context;
use arc_swap::ArcSwap;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use tokio::task::JoinHandle;

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::config_backup::load_config_backup;
use crate::config::db_backend::{self, DatabaseBackend};
use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
use crate::config::types::GatewayConfig;
use crate::dns::{DnsCache, DnsConfig};
use crate::modes::file::{
    ListenerJoinHandle, await_fallible_listener_handles, join_background_handles,
};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

async fn shutdown_database_runtime_tasks(
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    proxy_state: &ProxyState,
    listener_handles: Vec<(String, ListenerJoinHandle)>,
    mut background_handles: Vec<JoinHandle<()>>,
) -> Result<(), anyhow::Error> {
    let _ = shutdown_tx.send(true);
    let listener_result = if listener_handles.is_empty() {
        Ok(())
    } else {
        await_fallible_listener_handles(listener_handles, || {}).await
    };
    proxy_state.stream_listener_manager.shutdown_all().await;
    background_handles.extend(proxy_state.health_checker.take_active_check_handles());
    join_background_handles(background_handles, Duration::from_secs(5)).await;
    listener_result
}

pub const DATABASE_DELTA_RESOURCE_CATEGORY_LABELS: [&str; 6] = [
    "none",
    "proxy",
    "consumer",
    "plugin_config",
    "upstream",
    "mixed",
];
pub const DATABASE_DELTA_BACKOFF_BUCKET_LABELS: [&str; 6] =
    ["none", "lt_5s", "lt_30s", "lt_5m", "gte_5m", "max"];
const PLUGIN_MIGRATIONS_RECONCILED: u8 = 0;
const PLUGIN_MIGRATIONS_NEED_RECONCILE: u8 = 1;
const PLUGIN_MIGRATIONS_RECONCILING: u8 = 2;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct DatabaseDeltaPollDegraded {
    pub reason: &'static str,
    pub resource_category: &'static str,
    pub validation_category: &'static str,
    pub consecutive_identical_rejections: u64,
    pub current_backoff_bucket: &'static str,
    pub current_backoff_seconds: u64,
    pub escalated: bool,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct DatabaseDeltaPollMetricsSnapshot {
    pub rejected_deltas_total: u64,
    pub rejected_deltas_by_resource_category: BTreeMap<&'static str, u64>,
    pub consecutive_identical_rejections: u64,
    pub current_backoff_bucket: &'static str,
    pub current_backoff_seconds: u64,
    pub forced_full_reloads_total: u64,
    pub recoveries_total: u64,
    pub last_resource_category: &'static str,
    pub degraded: Option<DatabaseDeltaPollDegraded>,
}

/// Bounded observability for database incremental-delta rejections.
///
/// The metric dimensions are fixed enums. Resource IDs and validation strings
/// are hashed or classified before reaching this type so `/metrics` cannot
/// grow unbounded time series from hostile or malformed database rows.
#[derive(Debug)]
pub struct DatabaseDeltaPollMetrics {
    rejected_deltas_total: AtomicU64,
    rejected_none: AtomicU64,
    rejected_proxy: AtomicU64,
    rejected_consumer: AtomicU64,
    rejected_plugin_config: AtomicU64,
    rejected_upstream: AtomicU64,
    rejected_mixed: AtomicU64,
    consecutive_identical_rejections: AtomicU64,
    current_backoff_bucket: AtomicU8,
    current_backoff_seconds: AtomicU64,
    forced_full_reloads_total: AtomicU64,
    recoveries_total: AtomicU64,
    last_resource_category: AtomicU8,
    degraded: ArcSwap<Option<DatabaseDeltaPollDegraded>>,
}

impl Default for DatabaseDeltaPollMetrics {
    fn default() -> Self {
        Self {
            rejected_deltas_total: AtomicU64::new(0),
            rejected_none: AtomicU64::new(0),
            rejected_proxy: AtomicU64::new(0),
            rejected_consumer: AtomicU64::new(0),
            rejected_plugin_config: AtomicU64::new(0),
            rejected_upstream: AtomicU64::new(0),
            rejected_mixed: AtomicU64::new(0),
            consecutive_identical_rejections: AtomicU64::new(0),
            current_backoff_bucket: AtomicU8::new(DatabaseDeltaBackoffBucket::None as u8),
            current_backoff_seconds: AtomicU64::new(0),
            forced_full_reloads_total: AtomicU64::new(0),
            recoveries_total: AtomicU64::new(0),
            last_resource_category: AtomicU8::new(DatabaseDeltaResourceCategory::None as u8),
            degraded: ArcSwap::from_pointee(None),
        }
    }
}

impl DatabaseDeltaPollMetrics {
    fn record_rejection(
        &self,
        category: DatabaseDeltaResourceCategory,
        validation_category: DatabaseDeltaValidationCategory,
        consecutive: u64,
        backoff: Duration,
        max_backoff: Duration,
        escalated: bool,
    ) {
        self.rejected_deltas_total.fetch_add(1, Ordering::Relaxed);
        self.counter_for_category(category)
            .fetch_add(1, Ordering::Relaxed);
        self.consecutive_identical_rejections
            .store(consecutive, Ordering::Relaxed);
        self.current_backoff_bucket.store(
            DatabaseDeltaBackoffBucket::for_duration(backoff, max_backoff) as u8,
            Ordering::Relaxed,
        );
        self.current_backoff_seconds
            .store(backoff.as_secs(), Ordering::Relaxed);
        self.last_resource_category
            .store(category as u8, Ordering::Relaxed);
        self.degraded
            .store(Arc::new(Some(DatabaseDeltaPollDegraded {
                reason: if escalated {
                    "rejected_incremental_delta_escalated"
                } else {
                    "rejected_incremental_delta"
                },
                resource_category: category.as_str(),
                validation_category: validation_category.as_str(),
                consecutive_identical_rejections: consecutive,
                current_backoff_bucket: DatabaseDeltaBackoffBucket::for_duration(
                    backoff,
                    max_backoff,
                )
                .as_str(),
                current_backoff_seconds: backoff.as_secs(),
                escalated,
            })));
        invalidate_database_delta_poll_metrics_cache();
    }

    fn record_forced_full_reload(&self) {
        self.forced_full_reloads_total
            .fetch_add(1, Ordering::Relaxed);
        invalidate_database_delta_poll_metrics_cache();
    }

    fn record_recovery_if_degraded(&self) {
        let degraded = self.degraded.load();
        if (**degraded).is_some() {
            self.recoveries_total.fetch_add(1, Ordering::Relaxed);
        }
        self.clear_active_rejection();
    }

    fn clear_active_rejection(&self) {
        let had_active_rejection = self
            .consecutive_identical_rejections
            .load(Ordering::Relaxed)
            != 0
            || self.current_backoff_seconds.load(Ordering::Relaxed) != 0
            || (**self.degraded.load()).is_some();
        self.consecutive_identical_rejections
            .store(0, Ordering::Relaxed);
        self.current_backoff_bucket
            .store(DatabaseDeltaBackoffBucket::None as u8, Ordering::Relaxed);
        self.current_backoff_seconds.store(0, Ordering::Relaxed);
        self.degraded.store(Arc::new(None));
        if had_active_rejection {
            invalidate_database_delta_poll_metrics_cache();
        }
    }

    pub fn degraded(&self) -> Option<DatabaseDeltaPollDegraded> {
        self.degraded.load_full().as_ref().clone()
    }

    pub fn snapshot(&self) -> DatabaseDeltaPollMetricsSnapshot {
        let mut rejected_deltas_by_resource_category = BTreeMap::new();
        for category in DatabaseDeltaResourceCategory::ALL {
            rejected_deltas_by_resource_category.insert(
                category.as_str(),
                self.counter_for_category(category).load(Ordering::Relaxed),
            );
        }

        DatabaseDeltaPollMetricsSnapshot {
            rejected_deltas_total: self.rejected_deltas_total.load(Ordering::Relaxed),
            rejected_deltas_by_resource_category,
            consecutive_identical_rejections: self
                .consecutive_identical_rejections
                .load(Ordering::Relaxed),
            current_backoff_bucket: DatabaseDeltaBackoffBucket::from_u8(
                self.current_backoff_bucket.load(Ordering::Relaxed),
            )
            .as_str(),
            current_backoff_seconds: self.current_backoff_seconds.load(Ordering::Relaxed),
            forced_full_reloads_total: self.forced_full_reloads_total.load(Ordering::Relaxed),
            recoveries_total: self.recoveries_total.load(Ordering::Relaxed),
            last_resource_category: DatabaseDeltaResourceCategory::from_u8(
                self.last_resource_category.load(Ordering::Relaxed),
            )
            .as_str(),
            degraded: self.degraded(),
        }
    }

    fn counter_for_category(&self, category: DatabaseDeltaResourceCategory) -> &AtomicU64 {
        match category {
            DatabaseDeltaResourceCategory::None => &self.rejected_none,
            DatabaseDeltaResourceCategory::Proxy => &self.rejected_proxy,
            DatabaseDeltaResourceCategory::Consumer => &self.rejected_consumer,
            DatabaseDeltaResourceCategory::PluginConfig => &self.rejected_plugin_config,
            DatabaseDeltaResourceCategory::Upstream => &self.rejected_upstream,
            DatabaseDeltaResourceCategory::Mixed => &self.rejected_mixed,
        }
    }
}

fn invalidate_database_delta_poll_metrics_cache() {
    crate::plugins::prometheus_metrics::global_registry()
        .invalidate_database_delta_poll_metrics_cache();
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DatabaseDeltaResourceCategory {
    None = 0,
    Proxy = 1,
    Consumer = 2,
    PluginConfig = 3,
    Upstream = 4,
    Mixed = 5,
}

impl DatabaseDeltaResourceCategory {
    const ALL: [Self; 6] = [
        Self::None,
        Self::Proxy,
        Self::Consumer,
        Self::PluginConfig,
        Self::Upstream,
        Self::Mixed,
    ];

    fn as_str(self) -> &'static str {
        DATABASE_DELTA_RESOURCE_CATEGORY_LABELS[self as usize]
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Proxy,
            2 => Self::Consumer,
            3 => Self::PluginConfig,
            4 => Self::Upstream,
            5 => Self::Mixed,
            _ => Self::None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseDeltaBackoffBucket {
    None = 0,
    UnderFiveSeconds = 1,
    UnderThirtySeconds = 2,
    UnderFiveMinutes = 3,
    AtLeastFiveMinutes = 4,
    Max = 5,
}

impl DatabaseDeltaBackoffBucket {
    fn as_str(self) -> &'static str {
        DATABASE_DELTA_BACKOFF_BUCKET_LABELS[self as usize]
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::UnderFiveSeconds,
            2 => Self::UnderThirtySeconds,
            3 => Self::UnderFiveMinutes,
            4 => Self::AtLeastFiveMinutes,
            5 => Self::Max,
            _ => Self::None,
        }
    }

    fn for_duration(backoff: Duration, max_backoff: Duration) -> Self {
        if backoff.is_zero() {
            Self::None
        } else if backoff >= max_backoff {
            Self::Max
        } else if backoff < Duration::from_secs(5) {
            Self::UnderFiveSeconds
        } else if backoff < Duration::from_secs(30) {
            Self::UnderThirtySeconds
        } else if backoff < Duration::from_secs(300) {
            Self::UnderFiveMinutes
        } else {
            Self::AtLeastFiveMinutes
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DatabaseDeltaValidationCategory {
    SecurityPlugin,
    DuplicateRoute,
    Listener,
    UpstreamReference,
    PluginReference,
    Tls,
    Other,
}

impl DatabaseDeltaValidationCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::SecurityPlugin => "security_plugin",
            Self::DuplicateRoute => "duplicate_route",
            Self::Listener => "listener",
            Self::UpstreamReference => "upstream_reference",
            Self::PluginReference => "plugin_reference",
            Self::Tls => "tls",
            Self::Other => "other",
        }
    }

    fn classify(errors: &[String]) -> Self {
        const MAX_CLASSIFIED_ERRORS: usize = 32;
        const MAX_CLASSIFIED_ERROR_CHARS: usize = 256;

        let mut security_plugin = false;
        let mut duplicate_route = false;
        let mut listener = false;
        let mut upstream_reference = false;
        let mut plugin_reference = false;
        let mut tls = false;

        for error in errors.iter().take(MAX_CLASSIFIED_ERRORS) {
            let normalized = error
                .chars()
                .take(MAX_CLASSIFIED_ERROR_CHARS)
                .collect::<String>()
                .to_ascii_lowercase();
            security_plugin |= normalized.contains("security plugin");
            duplicate_route |=
                normalized.contains("duplicate") || normalized.contains("listen path");
            listener |= normalized.contains("listen")
                || normalized.contains("port")
                || normalized.contains("bind");
            upstream_reference |= normalized.contains("upstream");
            plugin_reference |= normalized.contains("plugin");
            tls |= normalized.contains("tls") || normalized.contains("certificate");
        }

        if security_plugin {
            Self::SecurityPlugin
        } else if duplicate_route {
            Self::DuplicateRoute
        } else if listener {
            Self::Listener
        } else if upstream_reference {
            Self::UpstreamReference
        } else if plugin_reference {
            Self::PluginReference
        } else if tls {
            Self::Tls
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RejectedDeltaIdentity {
    after_sequence: u64,
    resource_category: DatabaseDeltaResourceCategory,
    change_set_hash: u64,
}

impl RejectedDeltaIdentity {
    fn from_incremental(after_sequence: u64, result: &db_backend::IncrementalResult) -> Self {
        Self {
            after_sequence,
            resource_category: rejected_delta_resource_category(result),
            change_set_hash: rejected_delta_change_set_hash(result),
        }
    }

    fn with_validation(self, errors: &[String]) -> RejectedDeltaFingerprint {
        RejectedDeltaFingerprint {
            after_sequence: self.after_sequence,
            resource_category: self.resource_category,
            validation_category: DatabaseDeltaValidationCategory::classify(errors),
            change_set_hash: self.change_set_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RejectedDeltaFingerprint {
    after_sequence: u64,
    resource_category: DatabaseDeltaResourceCategory,
    validation_category: DatabaseDeltaValidationCategory,
    change_set_hash: u64,
}

#[derive(Debug, Clone)]
struct RejectedDeltaState {
    fingerprint: RejectedDeltaFingerprint,
    consecutive: u64,
    next_backoff: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectedDeltaLogAction {
    First,
    BackoffTransition,
    Escalation,
    ValidationCategoryChanged,
    Suppressed,
}

#[derive(Debug, Clone)]
struct RejectedDeltaDecision {
    fingerprint: RejectedDeltaFingerprint,
    consecutive: u64,
    backoff: Duration,
    log_action: RejectedDeltaLogAction,
    should_escalate: bool,
}

struct RejectedDeltaTracker {
    current: Option<RejectedDeltaState>,
    initial_backoff: Duration,
    max_backoff: Duration,
    full_reload_threshold: u64,
    metrics: Arc<DatabaseDeltaPollMetrics>,
}

impl RejectedDeltaTracker {
    fn new(
        initial_backoff: Duration,
        max_backoff: Duration,
        full_reload_threshold: u64,
        metrics: Arc<DatabaseDeltaPollMetrics>,
    ) -> Self {
        let max_backoff = max_backoff.max(initial_backoff);
        Self {
            current: None,
            initial_backoff,
            max_backoff,
            full_reload_threshold: full_reload_threshold.max(1),
            metrics,
        }
    }

    fn record_rejection(&mut self, fingerprint: RejectedDeltaFingerprint) -> RejectedDeltaDecision {
        let mut log_action = RejectedDeltaLogAction::First;
        let mut consecutive = 1;
        let mut backoff = self.initial_backoff;

        match &mut self.current {
            Some(state) if state.fingerprint == fingerprint => {
                state.consecutive = state.consecutive.saturating_add(1);
                consecutive = state.consecutive;
                backoff = state.next_backoff;
                log_action = if consecutive >= self.full_reload_threshold
                    && (consecutive - self.full_reload_threshold)
                        .is_multiple_of(self.full_reload_threshold)
                {
                    RejectedDeltaLogAction::Escalation
                } else if backoff < self.max_backoff {
                    RejectedDeltaLogAction::BackoffTransition
                } else {
                    RejectedDeltaLogAction::Suppressed
                };
                state.next_backoff = next_rejected_delta_backoff(backoff, self.max_backoff);
            }
            Some(state) => {
                log_action =
                    if state.fingerprint.validation_category != fingerprint.validation_category {
                        RejectedDeltaLogAction::ValidationCategoryChanged
                    } else {
                        RejectedDeltaLogAction::First
                    };
                *state = RejectedDeltaState {
                    fingerprint: fingerprint.clone(),
                    consecutive,
                    next_backoff: next_rejected_delta_backoff(backoff, self.max_backoff),
                };
            }
            None => {
                self.current = Some(RejectedDeltaState {
                    fingerprint: fingerprint.clone(),
                    consecutive,
                    next_backoff: next_rejected_delta_backoff(backoff, self.max_backoff),
                });
            }
        }

        let should_escalate = consecutive >= self.full_reload_threshold
            && (consecutive - self.full_reload_threshold)
                .is_multiple_of(self.full_reload_threshold);
        if should_escalate {
            log_action = RejectedDeltaLogAction::Escalation;
        }
        self.metrics.record_rejection(
            fingerprint.resource_category,
            fingerprint.validation_category,
            consecutive,
            backoff,
            self.max_backoff,
            should_escalate,
        );

        RejectedDeltaDecision {
            fingerprint,
            consecutive,
            backoff,
            log_action,
            should_escalate,
        }
    }

    fn record_accepted(&mut self) {
        if self.current.take().is_some() {
            self.metrics.record_recovery_if_degraded();
        } else {
            self.metrics.clear_active_rejection();
        }
    }
}

fn next_rejected_delta_backoff(current: Duration, max_backoff: Duration) -> Duration {
    let next_secs = current
        .as_secs()
        .max(1)
        .saturating_mul(2)
        .min(max_backoff.as_secs().max(1));
    Duration::from_secs(next_secs)
}

fn rejected_delta_resource_category(
    result: &db_backend::IncrementalResult,
) -> DatabaseDeltaResourceCategory {
    let proxy_changed =
        !result.added_or_modified_proxies.is_empty() || !result.removed_proxy_ids.is_empty();
    let consumer_changed =
        !result.added_or_modified_consumers.is_empty() || !result.removed_consumer_ids.is_empty();
    let plugin_config_changed = !result.added_or_modified_plugin_configs.is_empty()
        || !result.removed_plugin_config_ids.is_empty();
    let upstream_changed =
        !result.added_or_modified_upstreams.is_empty() || !result.removed_upstream_ids.is_empty();
    let changed_count = [
        proxy_changed,
        consumer_changed,
        plugin_config_changed,
        upstream_changed,
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();

    match changed_count {
        0 => DatabaseDeltaResourceCategory::None,
        1 if proxy_changed => DatabaseDeltaResourceCategory::Proxy,
        1 if consumer_changed => DatabaseDeltaResourceCategory::Consumer,
        1 if plugin_config_changed => DatabaseDeltaResourceCategory::PluginConfig,
        1 if upstream_changed => DatabaseDeltaResourceCategory::Upstream,
        _ => DatabaseDeltaResourceCategory::Mixed,
    }
}

fn rejected_delta_change_set_hash(result: &db_backend::IncrementalResult) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_sorted_resource_fingerprints(
        &mut hasher,
        "added_or_modified_proxies",
        result
            .added_or_modified_proxies
            .iter()
            .map(|proxy| (proxy.id.as_str(), proxy)),
    );
    hash_sorted_ids(
        &mut hasher,
        "removed_proxy_ids",
        result.removed_proxy_ids.iter().map(String::as_str),
    );
    hash_sorted_resource_fingerprints(
        &mut hasher,
        "added_or_modified_consumers",
        result
            .added_or_modified_consumers
            .iter()
            .map(|consumer| (consumer.id.as_str(), consumer)),
    );
    hash_sorted_namespaced_ids(
        &mut hasher,
        "removed_consumer_ids",
        result.removed_consumer_ids.iter(),
    );
    hash_sorted_resource_fingerprints(
        &mut hasher,
        "added_or_modified_plugin_configs",
        result
            .added_or_modified_plugin_configs
            .iter()
            .map(|plugin_config| (plugin_config.id.as_str(), plugin_config)),
    );
    hash_sorted_ids(
        &mut hasher,
        "removed_plugin_config_ids",
        result.removed_plugin_config_ids.iter().map(String::as_str),
    );
    hash_sorted_resource_fingerprints(
        &mut hasher,
        "added_or_modified_upstreams",
        result
            .added_or_modified_upstreams
            .iter()
            .map(|upstream| (upstream.id.as_str(), upstream)),
    );
    hash_sorted_ids(
        &mut hasher,
        "removed_upstream_ids",
        result.removed_upstream_ids.iter().map(String::as_str),
    );
    hasher.finish()
}

fn hash_sorted_resource_fingerprints<'a, T>(
    hasher: &mut std::collections::hash_map::DefaultHasher,
    label: &'static str,
    resources: impl Iterator<Item = (&'a str, &'a T)>,
) where
    T: serde::Serialize + 'a,
{
    label.hash(hasher);
    let mut resources: Vec<(&str, u64)> = resources
        .map(|(id, resource)| (id, stable_json_hash(resource)))
        .collect();
    resources.sort_unstable_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(&right.1)));
    resources.len().hash(hasher);
    for (id, content_hash) in resources {
        id.hash(hasher);
        content_hash.hash(hasher);
    }
}

fn stable_json_hash<T: serde::Serialize>(value: &T) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match serde_json::to_value(value) {
        Ok(value) => hash_json_value(&mut hasher, &value),
        Err(_) => "serialization_error".hash(&mut hasher),
    }
    hasher.finish()
}

fn hash_json_value(
    hasher: &mut std::collections::hash_map::DefaultHasher,
    value: &serde_json::Value,
) {
    match value {
        serde_json::Value::Null => {
            "null".hash(hasher);
        }
        serde_json::Value::Bool(value) => {
            "bool".hash(hasher);
            value.hash(hasher);
        }
        serde_json::Value::Number(value) => {
            "number".hash(hasher);
            value.to_string().hash(hasher);
        }
        serde_json::Value::String(value) => {
            "string".hash(hasher);
            value.hash(hasher);
        }
        serde_json::Value::Array(values) => {
            "array".hash(hasher);
            values.len().hash(hasher);
            for value in values {
                hash_json_value(hasher, value);
            }
        }
        serde_json::Value::Object(values) => {
            "object".hash(hasher);
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort_unstable();
            keys.len().hash(hasher);
            for key in keys {
                key.hash(hasher);
                if let Some(value) = values.get(key) {
                    hash_json_value(hasher, value);
                }
            }
        }
    }
}

fn hash_sorted_ids<'a>(
    hasher: &mut std::collections::hash_map::DefaultHasher,
    label: &'static str,
    ids: impl Iterator<Item = &'a str>,
) {
    label.hash(hasher);
    let mut ids: Vec<&str> = ids.collect();
    ids.sort_unstable();
    ids.len().hash(hasher);
    for id in ids {
        id.hash(hasher);
    }
}

fn hash_sorted_namespaced_ids<'a>(
    hasher: &mut std::collections::hash_map::DefaultHasher,
    label: &'static str,
    ids: impl Iterator<Item = &'a crate::config::db_backend::NamespacedResourceId>,
) {
    label.hash(hasher);
    let mut ids: Vec<(&str, &str)> = ids
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    ids.sort_unstable();
    ids.len().hash(hasher);
    for (namespace, id) in ids {
        namespace.hash(hasher);
        id.hash(hasher);
    }
}

fn log_rejected_delta_decision(decision: &RejectedDeltaDecision, errors: &[String]) {
    let category = decision.fingerprint.resource_category.as_str();
    let validation_category = decision.fingerprint.validation_category.as_str();
    let change_set_hash = format!("{:016x}", decision.fingerprint.change_set_hash);
    let backoff_seconds = decision.backoff.as_secs();
    let error_count = errors.len();
    let errors_for_log = bounded_rejection_errors_for_log(errors);

    match decision.log_action {
        RejectedDeltaLogAction::First => warn!(
            resource_category = category,
            validation_category = validation_category,
            consecutive_identical_rejections = decision.consecutive,
            backoff_seconds = backoff_seconds,
            change_set_hash = %change_set_hash,
            error_count = error_count,
            validation_errors = ?errors_for_log,
            "Incremental config update rejected by validation; keeping poll cursor unchanged and backing off before retry"
        ),
        RejectedDeltaLogAction::BackoffTransition => warn!(
            resource_category = category,
            validation_category = validation_category,
            consecutive_identical_rejections = decision.consecutive,
            backoff_seconds = backoff_seconds,
            change_set_hash = %change_set_hash,
            "Repeated database delta rejection; increasing bounded retry backoff"
        ),
        RejectedDeltaLogAction::Escalation => error!(
            resource_category = category,
            validation_category = validation_category,
            consecutive_identical_rejections = decision.consecutive,
            backoff_seconds = backoff_seconds,
            change_set_hash = %change_set_hash,
            error_count = error_count,
            validation_errors = ?errors_for_log,
            "Repeated database delta rejection reached threshold; attempting authoritative full reload"
        ),
        RejectedDeltaLogAction::ValidationCategoryChanged => warn!(
            resource_category = category,
            validation_category = validation_category,
            consecutive_identical_rejections = decision.consecutive,
            backoff_seconds = backoff_seconds,
            change_set_hash = %change_set_hash,
            error_count = error_count,
            validation_errors = ?errors_for_log,
            "Database delta rejection category changed; resetting rejected-delta backoff state"
        ),
        RejectedDeltaLogAction::Suppressed => debug!(
            resource_category = category,
            validation_category = validation_category,
            consecutive_identical_rejections = decision.consecutive,
            backoff_seconds = backoff_seconds,
            change_set_hash = %change_set_hash,
            "Repeated database delta rejection unchanged; retry log suppressed"
        ),
    }
}

fn bounded_rejection_errors_for_log(errors: &[String]) -> Vec<String> {
    errors
        .iter()
        .take(3)
        .map(|error| truncate_for_log(error, 256))
        .collect()
}

fn truncate_for_log(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let failover_urls = env_config
        .effective_db_failover_urls()
        .map_err(anyhow::Error::msg)?;
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    let effective_replica_url = env_config
        .effective_db_read_replica_url()
        .map_err(anyhow::Error::msg)?;

    // Tracks whether the initial connect succeeded. When `true`, the gateway
    // started via `FERRUM_DB_CONFIG_BACKUP_PATH` because every configured DB
    // URL was unreachable — polling will retry and flip this back to normal
    // operation once the database recovers.
    let mut bootstrap_from_backup = false;

    // Build the database backend — SQL (sqlx) or MongoDB depending on FERRUM_DB_TYPE
    let db: Box<dyn DatabaseBackend> = match db_type {
        "mongodb" => {
            let mut store = crate::config::mongo_store::MongoStore::connect_with_failover(
                &effective_url,
                &env_config.mongo_database,
                env_config.mongo_app_name.as_deref(),
                env_config.mongo_replica_set.as_deref(),
                env_config.mongo_auth_mechanism.as_deref(),
                env_config.mongo_server_selection_timeout_seconds,
                env_config.mongo_connect_timeout_seconds,
                env_config.db_tls_enabled(),
                env_config.db_tls_ca_cert_path.as_deref(),
                env_config.db_tls_client_cert_path.as_deref(),
                env_config.db_tls_client_key_path.as_deref(),
                env_config.mongodb_tls_allows_invalid_certs(),
                &failover_urls,
            )
            .await?;
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
            store.set_full_load_page_size(env_config.db_full_load_page_size);
            store.set_cert_expiry_warning_days(env_config.tls_cert_expiry_warning_days);
            store.set_backend_allow_ips(env_config.backend_allow_ips.clone());
            store.run_migrations().await?;
            Box::new(store)
        }
        _ => {
            // SQL backends (postgres, mysql, sqlite)
            let pool_config = DbPoolConfig {
                max_connections: env_config.db_pool_max_connections,
                min_connections: env_config.db_pool_min_connections,
                acquire_timeout_seconds: env_config.db_pool_acquire_timeout_seconds,
                idle_timeout_seconds: env_config.db_pool_idle_timeout_seconds,
                max_lifetime_seconds: env_config.db_pool_max_lifetime_seconds,
                connect_timeout_seconds: env_config.db_pool_connect_timeout_seconds,
                statement_timeout_seconds: env_config.db_pool_statement_timeout_seconds,
            };
            let mut store = match DatabaseStore::connect_with_failover(
                db_type,
                &effective_url,
                &failover_urls,
                pool_config.clone(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    // Every URL failed. If the operator provided
                    // `FERRUM_DB_CONFIG_BACKUP_PATH`, build a lazy-pool store
                    // so the gateway can still come up serving from the
                    // on-disk backup. The polling loop will retry the primary
                    // URL and flip `db_available` to true when it recovers.
                    //
                    // Backup bootstrap is reserved for TRANSIENT connectivity/
                    // resource/connect-timeout failures. A non-transient
                    // schema/auth/config/query error must fail startup instead
                    // of masking a broken primary by serving a stale backup.
                    if env_config.db_config_backup_path.is_some()
                        && !DatabaseStore::is_non_transient_init_error(&e)
                    {
                        warn!(
                            "All database URLs failed ({}). \
                             FERRUM_DB_CONFIG_BACKUP_PATH is set — bootstrapping \
                             from backup with a lazy pool. Polling will retry \
                             primary and {} failover URL(s) in the background.",
                            e,
                            failover_urls.len()
                        );
                        bootstrap_from_backup = true;
                        // Pass `failover_urls` into the offline store so the
                        // polling loop's `try_failover_reconnect()` probes them
                        // — a primary that stays down must not prevent
                        // recovery when a configured failover DB is healthy.
                        DatabaseStore::connect_offline_with_pool_config(
                            db_type,
                            &effective_url,
                            &failover_urls,
                            pool_config,
                        )?
                    } else {
                        return Err(e);
                    }
                }
            };
            store.set_slow_query_threshold(env_config.db_slow_query_threshold_ms);
            store.set_full_load_page_size(env_config.db_full_load_page_size);
            store.set_cert_expiry_warning_days(env_config.tls_cert_expiry_warning_days);
            store.set_backend_allow_ips(env_config.backend_allow_ips.clone());

            // Connect read replica for admin-only read offload. Runtime
            // config polling remains primary-consistent.
            if let Some(ref replica_url) = effective_replica_url {
                match store.connect_read_replica(replica_url).await {
                    Ok(()) if store.read_replica_suppressed() => {
                        info!("Read replica configured but suppressed until primary failback")
                    }
                    Ok(()) => info!("Read replica connected for admin reads"),
                    Err(e) => {
                        let safe_error = db_backend::redact_error_text(&e, &[replica_url]);
                        warn!(
                            "Read replica connection failed for {}; admin reads will use primary until reconnect succeeds: {}",
                            db_backend::redact_url(replica_url),
                            safe_error
                        );
                    }
                }
            }
            Box::new(store)
        }
    };
    // Convert to Arc for sharing across tasks
    let db: Arc<dyn DatabaseBackend> = Arc::from(db);
    let db_tls_reload_handle = crate::modes::db_tls_reload::start_db_tls_reload_task(
        env_config.clone(),
        db.clone(),
        Some(shutdown_tx.subscribe()),
    );

    // If we used the offline-bootstrap path above, try to apply the deferred
    // migrations immediately. The DB may have been unreachable only during
    // the eager connect and become reachable by the time we query here; in
    // that case we must run the migrations now so `load_full_config` below
    // sees the expected schema AND the admin API can enable writes right
    // away. Leaving `bootstrap_from_backup=true` until the first polling
    // cycle would force `db_available=false` for up to one poll interval
    // even though the database has already recovered — causing false 503s.
    //
    // For non-offline stores this is a no-op (CAS fails, returns Ok(false)).
    if bootstrap_from_backup {
        match db.maybe_apply_deferred_migrations().await {
            Ok(true) => {
                info!(
                    "Backup-bootstrapped store: deferred migrations applied at startup — \
                     database became reachable during boot, admin writes enabled immediately"
                );
                bootstrap_from_backup = false;
            }
            Ok(false) => {
                // Flag already cleared — treat as if DB is available.
                // Shouldn't happen right after offline bootstrap, but
                // handling it avoids a stale `bootstrap_from_backup=true`
                // blocking admin writes unnecessarily.
                bootstrap_from_backup = false;
            }
            Err(e) => {
                warn!(
                    "Backup bootstrap: database still unreachable at startup migration \
                     attempt ({}); polling will retry in the background",
                    e
                );
            }
        }
    }

    // Custom-plugin migrations: warn on pending, opt-in auto-apply.
    // Skipped when bootstrap_from_backup is still true — the database is
    // unreachable so we can't probe migration state. The reconcile state
    // starts pending in that case so `mark_db_available_after_successful_poll_load`
    // runs the same policy after deferred core migrations succeed on recovery.
    let plugin_migration_reconcile_state = Arc::new(AtomicU8::new(if bootstrap_from_backup {
        PLUGIN_MIGRATIONS_NEED_RECONCILE
    } else {
        PLUGIN_MIGRATIONS_RECONCILED
    }));
    if !bootstrap_from_backup {
        crate::modes::handle_startup_plugin_migrations(
            &db,
            env_config.auto_apply_plugin_migrations,
            "database",
        )
        .await?;
    }

    // Load initial config from database, falling back to backup file if configured.
    // Successful DB loads seed the durable change cursor so the first poll can
    // use config_changes immediately; backup loads intentionally start without
    // a cursor and force an authoritative DB reload after recovery.
    let backup_path = env_config.db_config_backup_path.clone();
    let mut startup_config_rejected = false;
    let initial_load = load_full_config_with_sequence(&db, &env_config.namespace).await;
    let (config, initial_change_sequence) = match initial_load {
        Ok((cfg, sequence)) => {
            // The lazy offline store can recover after the deferred-migration
            // probe above fails but before this first authoritative load. A
            // successful load proves that the database is reachable now; run
            // the ordinary startup plugin-migration policy immediately instead
            // of leaving admin writes blocked until the first poll tick.
            if bootstrap_from_backup {
                crate::modes::handle_startup_plugin_migrations(
                    &db,
                    env_config.auto_apply_plugin_migrations,
                    "database-recovered-during-startup",
                )
                .await?;
                plugin_migration_reconcile_state
                    .store(PLUGIN_MIGRATIONS_RECONCILED, Ordering::Release);
                bootstrap_from_backup = false;
                info!(
                    "Backup-bootstrapped store recovered during the initial database load; \
                     custom-plugin migration policy reconciled and admin writes enabled"
                );
            }
            info!(
                "Database mode: loaded {} proxies, {} consumers",
                cfg.proxies.len(),
                cfg.consumers.len()
            );
            (cfg, Some(sequence))
        }
        Err(e) => {
            // Classify the initial full-load failure for backup eligibility.
            //
            // A config-VALIDATION rejection (issue #2158) means the backend is
            // reachable but returned a semantically-invalid snapshot: it is
            // recoverable via in-band admin repair, so it stays backup-eligible
            // (serve backup, publish config_rejected, and enable writes after
            // the recovery migration gate)
            // and is left unclassified so no "refusing to bootstrap" wrapper
            // clouds the rejection log. Every OTHER non-transient failure
            // (schema drift, bad rows, decode, query, auth) is classified and
            // must fail startup rather than mask a broken database with stale
            // on-disk config — the same policy the connect path applies via
            // `is_non_transient_init_error`. Only transient connectivity/
            // resource errors are silently backup-eligible.
            let e = if crate::modes::is_poll_validation_rejection(&e) {
                e
            } else {
                DatabaseStore::classify_initial_config_load_error(e)
            };
            if let Some(ref path) = backup_path {
                if DatabaseStore::is_non_transient_init_error(&e) {
                    return Err(e);
                }
                // Database unreachable, or reachable-but-invalid snapshot — try
                // the configured backup for pod restart resilience.
                warn!(
                    "Database load failed ({}), attempting backup file: {}",
                    e, path
                );
                match load_config_backup(path) {
                    Some(cfg) => {
                        startup_config_rejected = crate::modes::is_poll_validation_rejection(&e);
                        if startup_config_rejected {
                            error!(
                                "Initial database snapshot was rejected by runtime validation; \
                                 starting with backup config, enabling admin writes for in-band \
                                 repair after the recovery migration gate, and publishing \
                                 config_rejected immediately: {}",
                                e
                            );
                        }
                        warn!(
                            "Starting with backup config ({} proxies, {} consumers). \
                             Database polling will retry and update when DB recovers.",
                            cfg.proxies.len(),
                            cfg.consumers.len()
                        );
                        (cfg, None)
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "Database load failed and no usable backup at {}: {}",
                            path,
                            e
                        ));
                    }
                }
            } else {
                return Err(e);
            }
        }
    };

    // Validate stream proxy ports don't conflict with gateway reserved ports
    let reserved_ports = env_config.reserved_gateway_ports();
    if let Err(errors) = config.validate_stream_proxy_port_conflicts(&reserved_ports) {
        for msg in &errors {
            error!("{}", msg);
        }
        return Err(anyhow::anyhow!(
            "Stream proxy port conflicts with gateway reserved ports"
        ));
    }

    // DNS cache
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        ttl_override_seconds: env_config.dns_ttl_override,
        min_ttl_seconds: env_config.dns_min_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
        warmup_concurrency: env_config.dns_warmup_concurrency,
        slow_threshold_ms: env_config.dns_slow_threshold_ms,
        refresh_threshold_percent: env_config.dns_refresh_threshold_percent,
        failed_retry_interval_seconds: env_config.dns_failed_retry_interval,
        try_tcp_on_error: env_config.dns_try_tcp_on_error,
        num_concurrent_reqs: env_config.dns_num_concurrent_reqs,
        max_active_requests: env_config.dns_max_active_requests,
        max_concurrent_refreshes: env_config.dns_max_concurrent_refreshes,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
        shard_amount: env_config.pool_shard_amount,
    });

    // DNS warmup — resolve all hostnames (proxy backends, upstream targets,
    // and plugin endpoints) before accepting requests. Hostnames are
    // deduplicated inside DnsCache::warmup() so shared hostnames across
    // proxies/plugins only trigger one DNS lookup.
    let mut hostnames: Vec<_> = config
        .proxies
        .iter()
        .map(|p| {
            (
                p.backend_host.clone(),
                p.dns_override.clone(),
                p.dns_cache_ttl_seconds,
            )
        })
        .collect();

    // Add upstream target hostnames for load-balanced proxies
    for upstream in &config.upstreams {
        for target in &upstream.targets {
            hostnames.push((target.host.clone(), None, None));
        }
    }

    // Build TLS hardening policy from environment (needed for both frontend
    // and backend TLS — cipher suites, protocol versions, key exchange groups).
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );
    let metrics_auth = Arc::new(
        crate::admin::MetricsAuthPolicy::from_env(&env_config).map_err(|e| anyhow::anyhow!(e))?,
    );

    // Build ProxyState first so the plugin cache exists with the shared DNS
    // cache, then collect plugin hostnames to include in warmup.
    let (proxy_state, health_check_handles) = ProxyState::new(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
        Some(shutdown_tx.subscribe()),
    )?;
    crate::runtime_metrics::global().configure(
        env_config.status_counts_max_entries,
        env_config.runtime_metrics_pool_tracking_enabled,
        env_config.runtime_metrics_status_tracking_enabled,
        env_config.runtime_metrics_cache_ttl_ms,
    );

    // Wire stream listeners (TCP/UDP/DTLS) to the global SIGTERM channel so
    // their accept loops exit promptly during graceful drain. Without this,
    // stream listeners would only react to per-listener (config-driven)
    // shutdown and keep accepting connections until the runtime is dropped.
    proxy_state
        .stream_listener_manager
        .set_global_shutdown_rx(shutdown_tx.subscribe());

    // Collect plugin endpoint hostnames (http_logging, jwks_auth, etc.)
    let plugin_hosts = proxy_state.plugin_cache.collect_warmup_hostnames();
    for host in plugin_hosts {
        hostnames.push((host, None, None));
    }

    dns_cache.warmup(hostnames).await;

    // Connection pool warmup — pre-establish backend connections for HTTP-family
    // proxies so the first request to each backend avoids TCP/TLS/QUIC handshake
    // latency. Must run after DNS warmup (needs resolved IPs).
    if env_config.pool_warmup_enabled {
        proxy_state.warmup_connection_pools().await;
    }
    // Kick off an initial capability probe when warmup is off — otherwise
    // the registry stays empty and HTTPS H2/H3 dispatch falls back to
    // reqwest until the first periodic tick (up to 24 h).
    proxy_state.start_backend_capability_refresh_task(
        !env_config.pool_warmup_enabled,
        Some(shutdown_tx.subscribe()),
    );

    // Start per-IP request counter cleanup (removes stale zero-count entries)
    let per_ip_cleanup_handle =
        proxy_state.start_per_ip_cleanup_task(Some(shutdown_tx.subscribe()));

    // Start background TTL refresh to keep cache warm (with shutdown)
    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));

    // Start background task to retry failed DNS lookups
    let dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));

    // Start service discovery background tasks
    proxy_state.start_service_discovery(Some(shutdown_tx.subscribe()));

    // Start overload monitor background task
    let overload_handle = crate::overload::start_monitor(
        proxy_state.overload.clone(),
        env_config.overload_config(),
        env_config.max_connections,
        env_config.max_requests,
        shutdown_tx.subscribe(),
    );

    // Start windowed metrics monitor background task
    let metrics_handle = crate::metrics::start_metrics_monitor(
        proxy_state.request_count.clone(),
        proxy_state.status_counts.clone(),
        proxy_state.windowed_metrics.clone(),
        env_config.status_metrics_window_seconds,
        shutdown_tx.subscribe(),
    );
    let runtime_system_handle = crate::system_metrics::start_sampler(
        Some(proxy_state.clone()),
        env_config.runtime_metrics_system_sample_interval_ms,
        shutdown_tx.subscribe(),
    );
    let runtime_window_handle = crate::runtime_metrics::start_window_rotator(
        env_config.runtime_metrics_window_1m_seconds,
        env_config.runtime_metrics_window_5m_seconds,
        shutdown_tx.subscribe(),
    );
    let acme_renewal_handle =
        crate::modes::start_acme_renewal_scheduler(&env_config, shutdown_tx.subscribe());

    let mut background_handles: Vec<JoinHandle<()>> = vec![
        dns_handle,
        overload_handle,
        metrics_handle,
        runtime_system_handle,
        runtime_window_handle,
    ];
    if let Some(h) = dns_retry_handle {
        background_handles.push(h);
    }
    if let Some(h) = per_ip_cleanup_handle {
        background_handles.push(h);
    }
    if let Some(h) = db_tls_reload_handle {
        background_handles.push(h);
    }
    if let Some(h) = acme_renewal_handle {
        background_handles.push(h);
    }
    background_handles.extend(health_check_handles);

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.frontend_tls_cert_path,
        &env_config.frontend_tls_key_path,
    ) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth_and_ocsp(
            cert_path,
            key_path,
            client_ca_bundle_path,
            env_config.frontend_tls_ocsp_response_source.as_deref(),
            false,
            &tls_policy,
            env_config.tls_cert_expiry_warning_days,
            &crls,
        ) {
            Ok(mut config) => {
                // Enable 0-RTT on the proxy frontend only (not admin).
                tls::enable_early_data(&mut config, &tls_policy);
                // Enable kTLS session-secret extraction on the proxy frontend
                // only (not admin) when kTLS could be used. Rustls gates
                // `dangerous_extract_secrets()` behind this flag.
                if env_config.ktls_enabled.could_be_enabled() {
                    tls::enable_secret_extraction_for_ktls(&mut config);
                }
                if client_ca_bundle_path.is_some() {
                    info!(
                        "TLS configuration loaded with client certificate verification (HTTPS with mTLS available)"
                    );
                } else {
                    info!(
                        "TLS configuration loaded without client certificate verification (HTTPS available)"
                    );
                }
                Some(config)
            }
            Err(e) => {
                let startup_err = anyhow::anyhow!("Invalid TLS configuration: {}", e);
                error!("TLS configuration validation failed: {}", e);
                if let Err(listener_err) = shutdown_database_runtime_tasks(
                    &shutdown_tx,
                    &proxy_state,
                    Vec::new(),
                    background_handles,
                )
                .await
                {
                    return Err(
                        listener_err.context(format!("Gateway startup failed: {startup_err}"))
                    );
                }
                return Err(startup_err);
            }
        }
    } else {
        info!("No TLS configuration provided (HTTP only)");
        None
    };

    // Wire opt-in frontend TLS live reload. When
    // `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=false` (the default) this
    // returns `slot=None` / `revision_rx=None` / `watcher_handle=None` and the
    // listeners use the startup-loaded config exactly as before. When opt-in
    // is set, a background watcher polls cert/key files and atomically swaps
    // the slot on validated changes; the HTTPS / H2 / H3 listeners read from
    // the slot on every new handshake.
    let mut proxy_frontend_reload_handles = tls_config.as_ref().map(|cfg| {
        crate::modes::tls_reload::prepare_proxy_frontend_tls(
            cfg.clone(),
            &env_config,
            &tls_policy,
            &crls,
            Some(shutdown_tx.subscribe()),
        )
    });
    if let Some(handles) = proxy_frontend_reload_handles.as_ref()
        && handles.watcher_handle.is_some()
    {
        info!(
            interval_secs = env_config.frontend_tls_watch_interval_seconds,
            "Frontend TLS live reload enabled for proxy HTTPS (H1/H2) and HTTP/3"
        );
    }
    if let Some(handles) = proxy_frontend_reload_handles.as_mut()
        && let Some(handle) = handles.watcher_handle.take()
    {
        background_handles.push(handle);
    }

    // Set TLS config on stream listener manager for TCP proxies with frontend_tls.
    // TCP+TLS / UDP+DTLS stream listeners do NOT participate in live reload —
    // they keep their startup config across rotations, matching the existing
    // mesh-mode behavior.
    if let Some(ref tls_cfg) = tls_config {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_cfg.clone()))
            .await;
    }

    // Set DTLS cert/key for UDP proxies with frontend_tls (DTLS termination).
    if let (Some(cert_path), Some(key_path)) =
        (&env_config.dtls_cert_path, &env_config.dtls_key_path)
    {
        if let Err(e) = tls::check_cert_expiry(
            cert_path,
            "DTLS frontend cert",
            env_config.tls_cert_expiry_warning_days,
        ) {
            let startup_err = e.context("Invalid DTLS frontend cert");
            if let Err(listener_err) = shutdown_database_runtime_tasks(
                &shutdown_tx,
                &proxy_state,
                Vec::new(),
                background_handles,
            )
            .await
            {
                return Err(listener_err.context(format!("Gateway startup failed: {startup_err}")));
            }
            return Err(startup_err);
        }
        if let Some(ref ca_path) = env_config.dtls_client_ca_cert_path
            && let Err(e) = tls::check_cert_expiry(
                ca_path,
                "DTLS client CA cert",
                env_config.tls_cert_expiry_warning_days,
            )
        {
            let startup_err = e.context("Invalid DTLS client CA cert");
            if let Err(listener_err) = shutdown_database_runtime_tasks(
                &shutdown_tx,
                &proxy_state,
                Vec::new(),
                background_handles,
            )
            .await
            {
                return Err(listener_err.context(format!("Gateway startup failed: {startup_err}")));
            }
            return Err(startup_err);
        }
        proxy_state
            .stream_listener_manager
            .set_frontend_dtls_cert_key(
                cert_path.clone(),
                key_path.clone(),
                env_config.dtls_client_ca_cert_path.clone(),
            )
            .await;
    }

    // Start separate listeners for HTTP and HTTPS
    let mut handles: Vec<(String, ListenerJoinHandle)> = Vec::new();
    let mut startup_signals = Vec::new();

    // HTTP listener (disabled when port is 0)
    if env_config.proxy_http_port != 0 {
        let http_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_http_port);
        let http_state = proxy_state.clone();
        let http_shutdown = shutdown_tx.subscribe();
        let (http_started_tx, http_started_rx) = tokio::sync::oneshot::channel();
        let http_handle = tokio::spawn(async move {
            info!(
                "Starting HTTP proxy listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_PROXY_BIND_ADDRESS",
                    "FERRUM_PROXY_HTTP_PORT",
                    &http_addr.to_string()
                )
            );
            proxy::start_proxy_listener_with_tls_and_signal(
                http_addr,
                http_state,
                http_shutdown,
                None,
                Some(http_started_tx),
            )
            .await
            .context("HTTP proxy listener failed")
        });
        handles.push(("HTTP proxy listener".to_string(), http_handle));
        startup_signals.push(("HTTP proxy listener".to_string(), http_started_rx));
    } else {
        info!(
            "{} — plaintext HTTP proxy listener disabled",
            crate::secrets::report_env_assignment("FERRUM_PROXY_HTTP_PORT", "0")
        );
    }

    // HTTPS listener (only if TLS is configured)
    if let Some(tls_config) = tls_config.clone() {
        if env_config.proxy_https_port == 0 {
            info!(
                "{} — HTTPS proxy listener disabled",
                crate::secrets::report_env_assignment("FERRUM_PROXY_HTTPS_PORT", "0")
            );
        } else {
            let https_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
            let https_state = proxy_state.clone();
            let https_shutdown = shutdown_tx.subscribe();
            let (https_started_tx, https_started_rx) = tokio::sync::oneshot::channel();
            let reload_slot = proxy_frontend_reload_handles
                .as_ref()
                .and_then(|h| h.slot.clone());
            let https_handle = tokio::spawn(async move {
                info!(
                    "Starting HTTPS proxy listener on {}",
                    crate::secrets::report_listener_addr(
                        "FERRUM_PROXY_BIND_ADDRESS",
                        "FERRUM_PROXY_HTTPS_PORT",
                        &https_addr.to_string()
                    )
                );
                let result = if let Some(slot) = reload_slot {
                    proxy::start_proxy_listener_with_dynamic_tls_and_signal(
                        https_addr,
                        https_state,
                        https_shutdown,
                        slot,
                        Some(https_started_tx),
                    )
                    .await
                } else {
                    proxy::start_proxy_listener_with_tls_and_signal(
                        https_addr,
                        https_state,
                        https_shutdown,
                        Some(tls_config),
                        Some(https_started_tx),
                    )
                    .await
                };
                result.context("HTTPS proxy listener failed")
            });
            handles.push(("HTTPS proxy listener".to_string(), https_handle));
            startup_signals.push(("HTTPS proxy listener".to_string(), https_started_rx));
        }
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // HTTP/3 (QUIC) listener (only if enabled and TLS is configured)
    let mut h3_listener_started = false;
    if env_config.enable_http3 {
        if let Some(tls_config) = tls_config.clone() {
            if env_config.proxy_https_port == 0 {
                info!(
                    "{} — HTTP/3 proxy listener disabled",
                    crate::secrets::report_env_assignment("FERRUM_PROXY_HTTPS_PORT", "0")
                );
            } else {
                let h3_addr: SocketAddr = env_config.proxy_socket_addr(env_config.proxy_https_port);
                let h3_state = proxy_state.clone();
                let h3_shutdown = shutdown_tx.subscribe();
                let h3_config =
                    crate::http3::config::Http3ServerConfig::from_env_config(&env_config);
                let h3_tls_policy = tls_policy.clone();
                let h3_client_ca = env_config.frontend_tls_client_ca_bundle_path.clone();
                let h3_client_crls = crls.clone();
                let (h3_started_tx, h3_started_rx) = tokio::sync::oneshot::channel();
                let h3_reload = crate::modes::tls_reload::build_h3_frontend_tls_reload(
                    proxy_frontend_reload_handles.as_ref(),
                );
                let h3_handle = tokio::spawn(async move {
                    info!(
                        "Starting HTTP/3 (QUIC) proxy listener on {}",
                        crate::secrets::report_listener_addr(
                            "FERRUM_PROXY_BIND_ADDRESS",
                            "FERRUM_PROXY_HTTPS_PORT",
                            &h3_addr.to_string()
                        )
                    );
                    crate::http3::server::start_http3_listener_with_signal(
                        h3_addr,
                        h3_state,
                        h3_shutdown,
                        tls_config,
                        h3_config,
                        &h3_tls_policy,
                        crate::http3::server::Http3ListenerOptions {
                            client_ca_bundle_path: h3_client_ca,
                            client_crls: h3_client_crls,
                            started_tx: Some(h3_started_tx),
                            frontend_tls_reload: h3_reload,
                        },
                    )
                    .await
                    .context("HTTP/3 proxy listener failed")
                });
                handles.push(("HTTP/3 proxy listener".to_string(), h3_handle));
                startup_signals.push(("HTTP/3 proxy listener".to_string(), h3_started_rx));
                h3_listener_started = true;
            }
        } else {
            error!("HTTP/3 requires TLS configuration - HTTP/3 listener disabled");
        }
    }
    if env_config.proxy_http_port == 0 && (tls_config.is_none() || env_config.proxy_https_port == 0)
    {
        warn!(
            "No HTTP or HTTPS proxy listeners are active — {} and HTTPS is not configured or disabled. Only stream proxies (TCP/UDP) will serve traffic.",
            crate::secrets::report_env_assignment("FERRUM_PROXY_HTTP_PORT", "0")
        );
    }

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = env_config.admin_socket_addr(env_config.admin_http_port);
    let jwt_manager = match create_jwt_manager_from_env() {
        Ok(jwt_manager) => jwt_manager,
        Err(e) => {
            let startup_err = anyhow::anyhow!("Failed to create JWT manager: {}", e);
            if let Err(listener_err) = shutdown_database_runtime_tasks(
                &shutdown_tx,
                &proxy_state,
                handles,
                background_handles,
            )
            .await
            {
                return Err(listener_err.context(format!("Gateway startup failed: {startup_err}")));
            }
            return Err(startup_err);
        }
    };

    // Shared flag: DB polling loop sets this to false when the database is
    // unreachable, causing the admin API to reject writes early and preserve
    // the cached config until the DB recovers. When we bootstrapped from a
    // backup file because every DB URL was down at startup, initialize to
    // `false` so `/health` and the admin API report the true state
    // immediately — before the first polling tick runs. A typed validation
    // rejection proves reachability, but an offline-bootstrap path must still
    // reconcile the custom-plugin migration policy before writes are enabled.
    let startup_ready = Arc::new(AtomicBool::new(false));
    let db_available = Arc::new(AtomicBool::new(initial_db_available(
        bootstrap_from_backup,
        startup_config_rejected,
        plugin_migration_reconcile_state.load(Ordering::Acquire),
    )));
    if bootstrap_from_backup && startup_config_rejected {
        // The database recovered after the eager startup probe but returned an
        // invalid full snapshot. Preserve in-band repair from issue #2158 only
        // after the custom-plugin migration probe/auto-apply policy skipped by
        // offline bootstrap has completed (issue #2630).
        let _ = mark_db_available_after_successful_poll_load(
            &db,
            &db_available,
            "initial validation-rejected snapshot",
            env_config.auto_apply_plugin_migrations,
            &plugin_migration_reconcile_state,
        )
        .await;
    }
    // Raised by the poll loop when a full load is rejected by the runtime-config
    // validation contract (reachable backend, invalid snapshot). Distinct from
    // `db_available`: admin stays writable so the offending resource can be
    // repaired in-band (issue #2158). Cleared only by an accepted authoritative
    // full reload.
    let config_rejected = Arc::new(AtomicBool::new(startup_config_rejected));
    let database_delta_poll_metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    crate::plugins::prometheus_metrics::global_registry()
        .set_database_delta_poll_metrics(database_delta_poll_metrics.clone());

    // Shared admin connection limiter (plaintext + HTTPS listeners share one
    // management-plane cap, independent of the data-plane FERRUM_MAX_CONNECTIONS).
    let admin_conn_limiter = Arc::new(admin::AdminConnLimiter::new(
        env_config.admin_max_connections,
        env_config.admin_max_connections_per_ip,
    ));

    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(proxy_state.config.clone()),
        proxy_state: Some(proxy_state.clone()),
        mode: "database".into(),
        read_only: env_config.admin_read_only,
        admin_audit_enabled: env_config.admin_audit_enabled,
        admin_require_namespace_claim: env_config.admin_require_namespace_claim,
        startup_ready: Some(startup_ready.clone()),
        // Database mode has no post-start listener supervision that flips
        // readiness; readiness is governed by `startup_ready` alone.
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_available.clone()),
        config_rejected: Some(config_rejected.clone()),
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: reserved_ports.clone(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs: admin_allowed_cidrs.clone(),
        metrics_auth: metrics_auth.clone(),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
    };
    // Clone admin_state before the HTTP listener moves it, so we can reuse
    // the same JwtManager instance for the HTTPS listener (instead of calling
    // create_jwt_manager_from_env() a second time).
    let admin_state_for_https = admin_state.clone();
    let admin_shutdown = shutdown_tx.subscribe();

    // Admin HTTP listener (disabled when port is 0)
    if env_config.admin_http_port != 0 {
        let (admin_started_tx, admin_started_rx) = tokio::sync::oneshot::channel();
        let admin_http_limiter = admin_conn_limiter.clone();
        let admin_http_handle = tokio::spawn(async move {
            info!(
                "Starting Admin HTTP listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    "FERRUM_ADMIN_HTTP_PORT",
                    &admin_http_addr.to_string()
                )
            );
            admin::start_admin_listener_with_tls_and_signal(
                admin_http_addr,
                admin_state,
                admin_shutdown,
                None,
                Some(admin_started_tx),
                admin_http_limiter,
            )
            .await
            .context("Admin HTTP listener failed")
        });
        handles.push(("Admin HTTP listener".to_string(), admin_http_handle));
        startup_signals.push(("Admin HTTP listener".to_string(), admin_started_rx));
    } else {
        info!(
            "{} — plaintext admin HTTP listener disabled",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTP_PORT", "0")
        );
    }

    // Admin HTTPS listener (only if TLS is configured and the port is not
    // disabled — port 0 is the repository-wide disable sentinel).
    if env_config.admin_https_port == 0 {
        info!(
            "{} — admin HTTPS listener disabled",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTPS_PORT", "0")
        );
    } else if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr: SocketAddr =
            env_config.admin_socket_addr(env_config.admin_https_port);
        let admin_https_shutdown = shutdown_tx.subscribe();

        // Load admin TLS configuration
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = match tls::load_tls_config_with_client_auth_and_ocsp(
            admin_cert_path,
            admin_key_path,
            admin_client_ca_bundle,
            env_config.admin_tls_ocsp_response_source.as_deref(),
            env_config.admin_tls_no_verify,
            &tls_policy,
            env_config.tls_cert_expiry_warning_days,
            &crls,
        ) {
            Ok(config) => {
                if admin_client_ca_bundle.is_some() {
                    info!(
                        "Admin TLS configuration loaded with client certificate verification (HTTPS with mTLS available)"
                    );
                } else if env_config.admin_tls_no_verify {
                    warn!(
                        "Admin TLS configuration loaded with certificate verification DISABLED (testing mode)"
                    );
                } else {
                    info!(
                        "Admin TLS configuration loaded without client certificate verification (HTTPS available)"
                    );
                }
                config
            }
            Err(e) => {
                let startup_err = anyhow::anyhow!("Invalid admin TLS configuration: {}", e);
                error!("Failed to load admin TLS configuration: {}", e);
                if let Err(listener_err) = shutdown_database_runtime_tasks(
                    &shutdown_tx,
                    &proxy_state,
                    handles,
                    background_handles,
                )
                .await
                {
                    return Err(
                        listener_err.context(format!("Gateway startup failed: {startup_err}"))
                    );
                }
                return Err(startup_err);
            }
        };

        // Wire opt-in admin frontend TLS live reload (no early-data / no
        // kTLS — admin doesn't apply those opt-ins).
        let mut admin_reload_handles = crate::modes::tls_reload::prepare_admin_frontend_tls(
            admin_tls_config.clone(),
            &env_config,
            &tls_policy,
            &crls,
            Some(shutdown_tx.subscribe()),
        );
        if admin_reload_handles.watcher_handle.is_some() {
            info!("Frontend TLS live reload enabled for admin HTTPS");
        }
        if let Some(handle) = admin_reload_handles.watcher_handle.take() {
            background_handles.push(handle);
        }
        let admin_tls_slot = admin_reload_handles.slot.clone();

        let (admin_https_started_tx, admin_https_started_rx) = tokio::sync::oneshot::channel();
        let admin_https_limiter = admin_conn_limiter.clone();
        let admin_https_handle = tokio::spawn(async move {
            info!(
                "Starting Admin HTTPS listener on {}",
                crate::secrets::report_listener_addr(
                    "FERRUM_ADMIN_BIND_ADDRESS",
                    "FERRUM_ADMIN_HTTPS_PORT",
                    &admin_https_addr.to_string()
                )
            );
            let result = if let Some(slot) = admin_tls_slot {
                admin::start_admin_listener_with_dynamic_tls_and_signal(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    slot,
                    Some(admin_https_started_tx),
                    admin_https_limiter,
                )
                .await
            } else {
                admin::start_admin_listener_with_tls_and_signal(
                    admin_https_addr,
                    admin_state_for_https,
                    admin_https_shutdown,
                    Some(admin_tls_config),
                    Some(admin_https_started_tx),
                    admin_https_limiter,
                )
                .await
            };
            result.context("Admin HTTPS listener failed")
        });
        handles.push(("Admin HTTPS listener".to_string(), admin_https_handle));
        startup_signals.push(("Admin HTTPS listener".to_string(), admin_https_started_rx));
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
    }
    if env_config.admin_http_port == 0 && !env_config.admin_https_listener_enabled() {
        warn!(
            "No admin API listeners are active — {} and admin HTTPS is not configured or disabled. The admin API is unreachable.",
            crate::secrets::report_env_assignment("FERRUM_ADMIN_HTTP_PORT", "0")
        );
    }

    // Start stream proxy listeners (TCP/UDP) — bind failures are fatal in database mode.
    let startup_result: Result<(), anyhow::Error> = async {
        proxy_state.initial_reconcile_stream_listeners().await?;
        wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
        proxy_state
            .stream_listener_manager
            .wait_until_started(Duration::from_secs(10))
            .await?;
        proxy_state.set_h3_websocket_listener_started(h3_listener_started);
        Ok(())
    }
    .await;

    if let Err(e) = startup_result {
        warn!(
            "Gateway startup failed after spawning listener / background tasks: {}; \
             draining spawned tasks before returning",
            e
        );
        if let Err(listener_err) =
            shutdown_database_runtime_tasks(&shutdown_tx, &proxy_state, handles, background_handles)
                .await
        {
            return Err(listener_err.context(format!("Gateway startup failed: {e}")));
        }
        return Err(e);
    }

    // Mark the gateway as ready to serve traffic. At this point:
    //   - Initial full config was loaded from DB (or backup)
    //   - All caches (router, plugin, consumer, LB, circuit breaker) are built
    //   - DNS is warmed and connection pools are pre-established
    //   - All listeners (proxy HTTP/HTTPS/H3, admin, stream) are bound
    //
    // This is intentionally set BEFORE the DB polling loop starts. Two paths
    // reach this point:
    //
    //   1. Normal — `load_full_config()` succeeded, proving DB connectivity
    //      and loading a complete config.
    //   2. Backup — `load_full_config()` failed but `FERRUM_DB_CONFIG_BACKUP_PATH`
    //      was set, so config was restored from the on-disk backup file. The
    //      gateway is serving stale-but-valid config; `db_available` starts
    //      `false`, `/health` reports `"degraded"`, and admin writes are
    //      blocked. The polling loop will retry the DB and flip
    //      `db_available` back to `true` once it recovers.
    //
    // In both cases the polling loop handles *ongoing incremental updates*,
    // not initial readiness. `/health` independently validates DB connectivity
    // via a `SELECT 1` check (cached 15s), so DB failures surface in the
    // health response regardless of polling state. `db_available` separately
    // gates admin writes when the DB becomes unreachable during operation.
    startup_ready.store(true, Ordering::Release);
    info!("Gateway startup complete; /health now reports ready");

    // Database polling loop (with shutdown) — uses incremental polling
    // to avoid full table scans on every cycle.
    //
    // Normal startup seeds the durable config-change sequence cursor before
    // this task starts. Backup/offline bootstrap leaves the cursor empty so the
    // first recovered poll performs an authoritative full reload.
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let proxy_state_poll = proxy_state.clone();
    let db_available_poll = db_available.clone();
    let config_rejected_poll = config_rejected.clone();
    let plugin_migration_reconcile_state_poll = plugin_migration_reconcile_state.clone();
    let auto_apply_plugin_migrations_poll = env_config.auto_apply_plugin_migrations;
    let database_delta_poll_metrics_for_poll = database_delta_poll_metrics.clone();
    let rejected_delta_initial_backoff =
        Duration::from_secs(env_config.db_rejected_delta_backoff_initial_seconds);
    let rejected_delta_max_backoff =
        Duration::from_secs(env_config.db_rejected_delta_backoff_max_seconds);
    let rejected_delta_full_reload_threshold = env_config.db_rejected_delta_full_reload_threshold;
    let mut poll_shutdown = shutdown_tx.subscribe();

    // DNS re-resolution for the database FQDN: if the URL contains a hostname
    // (not an IP literal), resolve it via DnsCache on each poll cycle and
    // reconnect the pool when the IPs change.
    let db_hostname = db_backend::extract_db_hostname(&effective_url);
    let replica_hostname = effective_replica_url
        .as_deref()
        .and_then(db_backend::extract_db_hostname);
    let dns_cache_for_poll = dns_cache.clone();
    let db_url_for_reconnect = effective_url.clone();
    let replica_url_for_reconnect = effective_replica_url.clone();
    let poll_namespace = env_config.namespace.clone();

    let db_poll_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // skip first immediate tick

        // Track the last known set of resolved IPs for the DB hostname.
        // Initialized lazily on the first successful resolution.
        let mut last_db_ips: Option<Vec<IpAddr>> = None;
        let last_replica_ips: crate::modes::AdminReadReplicaDnsWatermark =
            Arc::new(tokio::sync::Mutex::new(None));
        let mut force_full_reload = false;
        let replica_reconnect_in_flight = Arc::new(AtomicBool::new(false));
        let mut rejected_delta_tracker = RejectedDeltaTracker::new(
            rejected_delta_initial_backoff,
            rejected_delta_max_backoff,
            rejected_delta_full_reload_threshold,
            database_delta_poll_metrics_for_poll,
        );

        let mut last_change_sequence: Option<u64> = initial_change_sequence;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Replica reconnect/DNS-watermark maintenance must run even when
                    // the plugin-migration gate later blocks publication.
                    if let Some(ref replica_url) = replica_url_for_reconnect {
                        crate::modes::schedule_admin_read_replica_reconnect_if_needed(
                            db_poll.clone(),
                            Some(replica_url.as_str()),
                            replica_hostname.as_deref(),
                            &dns_cache_for_poll,
                            last_replica_ips.clone(),
                            replica_reconnect_in_flight.clone(),
                        )
                        .await;
                    }

                    // Check if the database FQDN now resolves to different IPs
                    if let Some(ref hostname) = db_hostname
                        && let Ok(ips) = dns_cache_for_poll.resolve_all(hostname, None, None).await
                    {
                        let needs_reconnect = match &last_db_ips {
                            Some(prev) => {
                                let mut prev_sorted = prev.clone();
                                prev_sorted.sort();
                                let mut cur_sorted = ips.clone();
                                cur_sorted.sort();
                                prev_sorted != cur_sorted
                            }
                            None => false, // first resolution, just seed
                        };
                        if needs_reconnect {
                            info!(
                                "Database DNS changed for '{}': {:?} -> {:?}, reconnecting pool",
                                hostname, last_db_ips.as_deref().unwrap_or(&[]), ips
                            );
                            match db_poll.reconnect(&db_url_for_reconnect).await {
                                Ok(_) => {
                                    // Pool topology changed — re-probe plugin migrations
                                    // on the next successful load (failback/failover safety).
                                    plugin_migration_reconcile_state_poll
                                        .store(PLUGIN_MIGRATIONS_NEED_RECONCILE, Ordering::Release);
                                    last_db_ips = Some(ips);
                                    force_full_reload = true;
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to reconnect database pool after DNS change for '{}': {}",
                                        hostname, e
                                    );
                                }
                            }
                        } else {
                            last_db_ips = Some(ips);
                        }
                    }

                    if force_full_reload {
                        match load_full_config_with_sequence(&db_poll, &poll_namespace).await {
                            Ok((new_config, sequence)) => {
                                match try_publish_full_reload_after_gate(
                                    &db_poll,
                                    &db_available_poll,
                                    &proxy_state_poll,
                                    new_config,
                                    "full reload after DB DNS reconnect",
                                    "after DB DNS reconnect",
                                    auto_apply_plugin_migrations_poll,
                                    &plugin_migration_reconcile_state_poll,
                                    &mut last_change_sequence,
                                    sequence,
                                    &config_rejected_poll,
                                )
                                .await
                                {
                                    None => continue,
                                    Some(true) => {
                                        force_full_reload = false;
                                        rejected_delta_tracker.record_accepted();
                                        debug!("Full config reload complete after DB DNS reconnect");
                                    }
                                    Some(false) => {}
                                }
                            }
                            Err(e) => {
                                if crate::modes::is_poll_validation_rejection(&e) {
                                    record_config_validation_rejection_after_recovery_migration_gate(
                                        &db_poll,
                                        &db_available_poll,
                                        &config_rejected_poll,
                                        auto_apply_plugin_migrations_poll,
                                        &plugin_migration_reconcile_state_poll,
                                        &e,
                                        "full reload after DB DNS reconnect",
                                    )
                                    .await;
                                } else {
                                    error!(
                                        "Authoritative primary full config reload failed after DB DNS reconnect; keeping existing config and retrying: {}",
                                        e
                                    );
                                    db_available_poll.store(false, Ordering::Relaxed);
                                }
                                continue;
                            }
                        }
                    } else if let Some(after_sequence) = last_change_sequence {
                        match db_poll
                            .load_incremental_config(&poll_namespace, after_sequence)
                            .await
                        {
                            Ok(result) => {
                                if !mark_db_available_after_successful_poll_load(
                                    &db_poll,
                                    &db_available_poll,
                                    "incremental poll",
                                    auto_apply_plugin_migrations_poll,
                                    &plugin_migration_reconcile_state_poll,
                                )
                                .await
                                {
                                    continue;
                                }
                                let next_sequence = result.sequence_cursor;
                                let rejected_delta_identity =
                                    RejectedDeltaIdentity::from_incremental(after_sequence, &result);

                                match proxy_state_poll.apply_incremental(result).await {
                                    proxy::ConfigApplyOutcome::Applied => {
                                        last_change_sequence = Some(next_sequence);
                                        debug!("Incremental config reload complete");
                                        rejected_delta_tracker.record_accepted();
                                    }
                                    proxy::ConfigApplyOutcome::Unchanged => {
                                        last_change_sequence = Some(next_sequence);
                                        debug!("Incremental config poll valid but unchanged");
                                        rejected_delta_tracker.record_accepted();
                                    }
                                    proxy::ConfigApplyOutcome::Rejected { errors } => {
                                        let decision = rejected_delta_tracker.record_rejection(
                                            rejected_delta_identity.with_validation(&errors),
                                        );
                                        log_rejected_delta_decision(&decision, &errors);

                                        let mut recovered_by_full_reload = false;
                                        if decision.should_escalate {
                                            rejected_delta_tracker
                                                .metrics
                                                .record_forced_full_reload();
                                            match load_full_config_with_sequence(
                                                &db_poll,
                                                &poll_namespace,
                                            )
                                            .await
                                            {
                                                Ok((new_config, sequence)) => {
                                                    match try_publish_full_reload_after_gate(
                                                        &db_poll,
                                                        &db_available_poll,
                                                        &proxy_state_poll,
                                                        new_config,
                                                        "rejected-delta escalation full reload",
                                                        "rejected delta escalation",
                                                        auto_apply_plugin_migrations_poll,
                                                        &plugin_migration_reconcile_state_poll,
                                                        &mut last_change_sequence,
                                                        sequence,
                                                        &config_rejected_poll,
                                                    )
                                                    .await
                                                    {
                                                        None => continue,
                                                        Some(true) => {
                                                            rejected_delta_tracker.record_accepted();
                                                            recovered_by_full_reload = true;
                                                            info!(
                                                                "Rejected database delta recovered by authoritative full reload"
                                                            );
                                                        }
                                                        Some(false) => {}
                                                    }
                                                }
                                                Err(e) => {
                                                    // Classify first: a validation
                                                    // rejection means the same invalid
                                                    // snapshot lives on every replica, so
                                                    // failover cannot help and must not be
                                                    // allowed to flip db_available on a
                                                    // reconnect error (issue #2158). Keep
                                                    // last known-good config + admin writable.
                                                    if crate::modes::is_poll_validation_rejection(&e) {
                                                        record_config_validation_rejection_after_recovery_migration_gate(
                                                            &db_poll,
                                                            &db_available_poll,
                                                            &config_rejected_poll,
                                                            auto_apply_plugin_migrations_poll,
                                                            &plugin_migration_reconcile_state_poll,
                                                            &e,
                                                            "rejected-delta escalation full reload",
                                                        )
                                                        .await;
                                                    } else {
                                                        warn!(
                                                            "Authoritative primary full reload failed after repeated rejected delta; keeping last known-good runtime config: {}",
                                                            e
                                                        );
                                                        match db_poll
                                                            .try_failover_reconnect(
                                                                &db_url_for_reconnect,
                                                            )
                                                            .await
                                                        {
                                                            Ok(_url) => {
                                                                plugin_migration_reconcile_state_poll
                                                                    .store(PLUGIN_MIGRATIONS_NEED_RECONCILE, Ordering::Release);
                                                                match load_full_config_with_sequence(
                                                                    &db_poll,
                                                                    &poll_namespace,
                                                                )
                                                                .await
                                                                {
                                                                    Ok((new_config, sequence)) => {
                                                                        match try_publish_full_reload_after_gate(
                                                                            &db_poll,
                                                                            &db_available_poll,
                                                                            &proxy_state_poll,
                                                                            new_config,
                                                                            "rejected-delta escalation failover reload",
                                                                            "rejected delta escalation failover",
                                                                            auto_apply_plugin_migrations_poll,
                                                                            &plugin_migration_reconcile_state_poll,
                                                                            &mut last_change_sequence,
                                                                            sequence,
                                                                            &config_rejected_poll,
                                                                        )
                                                                        .await
                                                                        {
                                                                            None => continue,
                                                                            Some(true) => {
                                                                                rejected_delta_tracker
                                                                                    .record_accepted();
                                                                                recovered_by_full_reload =
                                                                                    true;
                                                                                info!(
                                                                                    "Rejected database delta recovered by authoritative failover full reload"
                                                                                );
                                                                            }
                                                                            Some(false) => {}
                                                                        }
                                                                    }
                                                                    Err(e2) => {
                                                                        if crate::modes::is_poll_validation_rejection(&e2) {
                                                                            record_config_validation_rejection_after_recovery_migration_gate(
                                                                                &db_poll,
                                                                                &db_available_poll,
                                                                                &config_rejected_poll,
                                                                                auto_apply_plugin_migrations_poll,
                                                                                &plugin_migration_reconcile_state_poll,
                                                                                &e2,
                                                                                "rejected-delta escalation failover reload",
                                                                            )
                                                                            .await;
                                                                        } else {
                                                                            db_available_poll.store(
                                                                                false,
                                                                                Ordering::Relaxed,
                                                                            );
                                                                            warn!(
                                                                                "Authoritative failover full reload also failed after repeated rejected delta; keeping last known-good runtime config: {}",
                                                                                e2
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Err(e2) => {
                                                                db_available_poll
                                                                    .store(false, Ordering::Relaxed);
                                                                warn!(
                                                                    "Database failover reconnect failed after rejected-delta escalation reload error: {}",
                                                                    e2
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if !recovered_by_full_reload {
                                            interval.reset_after(decision.backoff);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if db_backend::is_incremental_full_reload_required(&e) {
                                    info!(
                                        "Consumer change detected; using authoritative full reload for credential rehydration: {}",
                                        e
                                    );
                                } else {
                                    warn!(
                                        "Authoritative primary incremental poll failed, falling back to full reload: {}",
                                        e
                                    );
                                }
                                match load_full_config_with_sequence(&db_poll, &poll_namespace).await
                                {
                                    Ok((new_config, sequence)) => {
                                        match try_publish_full_reload_after_gate(
                                            &db_poll,
                                            &db_available_poll,
                                            &proxy_state_poll,
                                            new_config,
                                            "full fallback reload",
                                            "full fallback",
                                            auto_apply_plugin_migrations_poll,
                                            &plugin_migration_reconcile_state_poll,
                                            &mut last_change_sequence,
                                            sequence,
                                            &config_rejected_poll,
                                        )
                                        .await
                                        {
                                            None => continue,
                                            Some(true) => {
                                                rejected_delta_tracker.record_accepted();
                                            }
                                            Some(false) => {}
                                        }
                                    }
                                    Err(e2) => {
                                        // Classify the primary full-reload error
                                        // before failover: a validation rejection is
                                        // identical on every replica, so keep the last
                                        // known-good config + admin writable and skip
                                        // failover (issue #2158).
                                        if crate::modes::is_poll_validation_rejection(&e2) {
                                            record_config_validation_rejection_after_recovery_migration_gate(
                                                &db_poll,
                                                &db_available_poll,
                                                &config_rejected_poll,
                                                auto_apply_plugin_migrations_poll,
                                                &plugin_migration_reconcile_state_poll,
                                                &e2,
                                                "full fallback reload",
                                            )
                                            .await;
                                        } else {
                                            match db_poll
                                                .try_failover_reconnect(&db_url_for_reconnect)
                                                .await
                                            {
                                                Ok(_url) => {
                                                    plugin_migration_reconcile_state_poll
                                                        .store(PLUGIN_MIGRATIONS_NEED_RECONCILE, Ordering::Release);
                                                    match load_full_config_with_sequence(
                                                        &db_poll,
                                                        &poll_namespace,
                                                    )
                                                    .await
                                                    {
                                                        Ok((new_config, sequence)) => {
                                                            match try_publish_full_reload_after_gate(
                                                                &db_poll,
                                                                &db_available_poll,
                                                                &proxy_state_poll,
                                                                new_config,
                                                                "failover full reload",
                                                                "failover",
                                                                auto_apply_plugin_migrations_poll,
                                                                &plugin_migration_reconcile_state_poll,
                                                                &mut last_change_sequence,
                                                                sequence,
                                                                &config_rejected_poll,
                                                            )
                                                            .await
                                                            {
                                                                None => continue,
                                                                Some(true) => {
                                                                    rejected_delta_tracker.record_accepted();
                                                                }
                                                                Some(false) => {}
                                                            }
                                                        }
                                                        Err(e3) => {
                                                            if crate::modes::is_poll_validation_rejection(&e3) {
                                                                record_config_validation_rejection_after_recovery_migration_gate(
                                                                    &db_poll,
                                                                    &db_available_poll,
                                                                    &config_rejected_poll,
                                                                    auto_apply_plugin_migrations_poll,
                                                                    &plugin_migration_reconcile_state_poll,
                                                                    &e3,
                                                                    "failover full reload",
                                                                )
                                                                .await;
                                                            } else {
                                                                db_available_poll
                                                                    .store(false, Ordering::Relaxed);
                                                                warn!(
                                                                    "Authoritative primary failover reload also failed (using cached): {}",
                                                                    e3
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    db_available_poll.store(false, Ordering::Relaxed);
                                                    warn!(
                                                        "Authoritative primary full config reload also failed (using cached): {}",
                                                        e2
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        match load_full_config_with_sequence(&db_poll, &poll_namespace).await {
                            Ok((new_config, sequence)) => {
                                match try_publish_full_reload_after_gate(
                                    &db_poll,
                                    &db_available_poll,
                                    &proxy_state_poll,
                                    new_config,
                                    "first full reload",
                                    "initial full poll",
                                    auto_apply_plugin_migrations_poll,
                                    &plugin_migration_reconcile_state_poll,
                                    &mut last_change_sequence,
                                    sequence,
                                    &config_rejected_poll,
                                )
                                .await
                                {
                                    None => continue,
                                    Some(true) => {
                                        rejected_delta_tracker.record_accepted();
                                    }
                                    Some(false) => {}
                                }
                            }
                            Err(e) => {
                                if crate::modes::is_poll_validation_rejection(&e) {
                                    record_config_validation_rejection_after_recovery_migration_gate(
                                        &db_poll,
                                        &db_available_poll,
                                        &config_rejected_poll,
                                        auto_apply_plugin_migrations_poll,
                                        &plugin_migration_reconcile_state_poll,
                                        &e,
                                        "initial full poll",
                                    )
                                    .await;
                                } else {
                                    db_available_poll.store(false, Ordering::Relaxed);
                                    warn!(
                                        "Authoritative primary full config reload failed (using cached): {}",
                                        e
                                    );
                                }
                            }
                        }
                    }

                }
                _ = poll_shutdown.changed() => {
                    info!("Database polling shutting down");
                    return;
                }
            }
        }
    });
    background_handles.push(db_poll_handle);

    // Wait for all listeners to complete (these exit when the shutdown signal fires).
    // If no listener handles were spawned (e.g., all plaintext ports disabled and no
    // TLS configured), block on the shutdown signal so stream proxies keep running.
    let listener_result = if handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
        Ok(())
    } else {
        let shutdown_tx_on_failure = shutdown_tx.clone();
        await_fallible_listener_handles(handles, move || {
            let _ = shutdown_tx_on_failure.send(true);
        })
        .await
    };

    // Stop accepting new TCP/UDP/DTLS stream connections. The accept loops
    // also observe the global shutdown receiver wired above and will already
    // be exiting; firing each per-listener channel here clears the listener
    // map (releasing ports) and is a no-op if the loops have already exited.
    proxy_state.stream_listener_manager.shutdown_all().await;

    // Graceful connection drain: signal drain state to the proxy hot path
    // (Connection: close + reject new requests) unconditionally so the close
    // hint fires even when the operator has disabled the wait loop with
    // FERRUM_SHUTDOWN_DRAIN_SECONDS=0. Only the wait loop itself is gated.
    crate::overload::begin_drain(&proxy_state.overload);
    let drain_seconds = env_config.shutdown_drain_seconds;
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    // Wait for background tasks to drain cleanly, with a timeout to prevent
    // hanging if a task is stuck (e.g., blocked on a DB query or DNS lookup).
    // Active-health-check probes and the passive recovery timer observe the
    // shutdown watch channel via `tokio::select!` (see `start_with_shutdown`)
    // so they exit cleanly within the 5s cap rather than racing the
    // `Drop for HealthChecker` abort that fires at process exit.
    background_handles.extend(proxy_state.health_checker.take_active_check_handles());
    join_background_handles(background_handles, Duration::from_secs(5)).await;
    crate::observability_delivery::shutdown(Duration::from_millis(
        env_config.log_shutdown_drain_timeout_ms,
    ))
    .await;
    crate::plugins::api_chargeback_sink::finalize_all_snapshot_generations().await;
    crate::plugins::kafka_logging::finalize_all_generations().await;

    listener_result?;

    Ok(())
}

async fn load_full_config_with_sequence(
    db: &Arc<dyn DatabaseBackend>,
    namespace: &str,
) -> Result<(GatewayConfig, u64), anyhow::Error> {
    db.maybe_apply_deferred_migrations().await?;
    let sequence = db.latest_change_sequence(namespace).await?;
    let config = db.load_full_config(namespace).await?;
    Ok((config, sequence))
}

/// Publication chokepoint for full-reload poll sites: run the recovery plugin-
/// migration gate, then apply + commit. Returns `None` when the gate blocks
/// publication (caller must `continue` the poll tick without publishing).
/// Returns `Some(accepted)` after `update_config` + [`commit_full_reload_poll_state`].
#[allow(clippy::too_many_arguments)]
async fn try_publish_full_reload_after_gate(
    db: &Arc<dyn DatabaseBackend>,
    db_available: &AtomicBool,
    proxy_state: &ProxyState,
    new_config: GatewayConfig,
    gate_context: &str,
    commit_context: &str,
    auto_apply_plugin_migrations: bool,
    plugin_migration_reconcile_state: &AtomicU8,
    last_change_sequence: &mut Option<u64>,
    sequence: u64,
    config_rejected: &AtomicBool,
) -> Option<bool> {
    if !mark_db_available_after_successful_poll_load(
        db,
        db_available,
        gate_context,
        auto_apply_plugin_migrations,
        plugin_migration_reconcile_state,
    )
    .await
    {
        return None;
    }
    let outcome = proxy_state.update_config(new_config);
    Some(commit_full_reload_poll_state(
        commit_context,
        outcome,
        last_change_sequence,
        sequence,
        config_rejected,
    ))
}

fn commit_full_reload_poll_state(
    context: &str,
    outcome: proxy::ConfigApplyOutcome,
    last_change_sequence: &mut Option<u64>,
    sequence: u64,
    config_rejected: &AtomicBool,
) -> bool {
    match outcome {
        proxy::ConfigApplyOutcome::Applied => {
            *last_change_sequence = Some(sequence);
            info!("Configuration applied from database ({})", context);
            crate::modes::clear_config_rejected_after_accepted_full_reload(
                config_rejected,
                context,
            );
            true
        }
        proxy::ConfigApplyOutcome::Unchanged => {
            *last_change_sequence = Some(sequence);
            debug!("Database configuration valid but unchanged ({})", context);
            // An Unchanged outcome still means the freshly-loaded FULL snapshot
            // passed loader validation and matches the running config, so the
            // full snapshot is proven valid again.
            crate::modes::clear_config_rejected_after_accepted_full_reload(
                config_rejected,
                context,
            );
            true
        }
        proxy::ConfigApplyOutcome::Rejected { errors } => {
            if !config_rejected.swap(true, Ordering::Relaxed) {
                error!(
                    "Database configuration candidate rejected during full apply ({}); \
                     raising config_rejected and keeping previous runtime config and poll cursor: {}",
                    context,
                    errors.join("; ")
                );
            } else {
                debug!(
                    "Database configuration candidate still rejected during full apply ({}); \
                     keeping previous runtime config and poll cursor: {}",
                    context,
                    errors.join("; ")
                );
            }
            false
        }
    }
}

fn initial_db_available(
    bootstrap_from_backup: bool,
    config_rejected: bool,
    plugin_migration_reconcile_state: u8,
) -> bool {
    !bootstrap_from_backup
        || (config_rejected && plugin_migration_reconcile_state == PLUGIN_MIGRATIONS_RECONCILED)
}

#[must_use = "gate failure must skip recovered config publication"]
async fn mark_db_available_after_successful_poll_load(
    db: &Arc<dyn DatabaseBackend>,
    db_available: &AtomicBool,
    context: &str,
    auto_apply_plugin_migrations: bool,
    plugin_migration_reconcile_state: &AtomicU8,
) -> bool {
    // Any load that reaches this point proved the backend is reachable, so
    // re-enable admin writes. Note this does NOT clear `config_rejected`: an
    // accepted incremental poll on top of a validation-rejected full snapshot
    // does not prove the full snapshot is valid again. `config_rejected` is
    // cleared only by
    // [`crate::modes::clear_config_rejected_after_accepted_full_reload`], which
    // fires exclusively from an accepted FULL reload (issue #2158).
    //
    // When offline bootstrap skipped custom-plugin migrations, reconcile the
    // same warn/auto-apply policy here after deferred core migrations succeed
    // (issue #2630). The three-state CAS admits one reconcile attempt per
    // recovery generation. Probe/apply failures restore NEED_RECONCILE so the
    // next successful poll retries; callers must not publish the loaded config
    // when this helper returns false.
    if let Err(e) = db.maybe_apply_deferred_migrations().await {
        warn!(
            "Deferred migrations failed despite successful {}: {}. \
             Admin writes remain blocked until schema is applied.",
            context, e
        );
        db_available.store(false, Ordering::Relaxed);
        return false;
    }

    match plugin_migration_reconcile_state.compare_exchange(
        PLUGIN_MIGRATIONS_NEED_RECONCILE,
        PLUGIN_MIGRATIONS_RECONCILING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            match crate::modes::handle_recovery_plugin_migrations(
                db,
                auto_apply_plugin_migrations,
                "database-recovery",
            )
            .await
            {
                Ok(()) => {
                    plugin_migration_reconcile_state
                        .store(PLUGIN_MIGRATIONS_RECONCILED, Ordering::Release);
                    db_available.store(true, Ordering::Relaxed);
                    true
                }
                Err(e) => {
                    plugin_migration_reconcile_state
                        .store(PLUGIN_MIGRATIONS_NEED_RECONCILE, Ordering::Release);
                    warn!(
                        "Custom-plugin migration reconciliation failed after {}: {}. \
                         Admin writes and recovered config publication remain blocked until \
                         plugin schema is reconciled.",
                        context, e
                    );
                    db_available.store(false, Ordering::Relaxed);
                    false
                }
            }
        }
        Err(PLUGIN_MIGRATIONS_RECONCILED) => {
            db_available.store(true, Ordering::Relaxed);
            true
        }
        Err(PLUGIN_MIGRATIONS_RECONCILING) => {
            // The database poll task is the only caller today and invokes this
            // helper sequentially, so no owner can be abandoned while another
            // caller observes RECONCILING. If concurrent callers are added,
            // the reconcile owner must gain a drop/reset guard before relying
            // on this branch.
            db_available.store(false, Ordering::Relaxed);
            false
        }
        Err(state) => {
            warn!(
                "Invalid custom-plugin migration reconcile state {} after {}; \
                 keeping admin writes and config publication blocked",
                state, context
            );
            db_available.store(false, Ordering::Relaxed);
            false
        }
    }
}

/// A validation-rejected full snapshot still proves database reachability, but
/// an offline-bootstrapped process must not use that fact to bypass the pending
/// custom-plugin migration gate. Reconcile the same core/custom migration state
/// as a successful poll before deciding whether in-band repair writes may be
/// re-enabled, while always raising the config-rejected signal.
async fn record_config_validation_rejection_after_recovery_migration_gate(
    db: &Arc<dyn DatabaseBackend>,
    db_available: &AtomicBool,
    config_rejected: &AtomicBool,
    auto_apply_plugin_migrations: bool,
    plugin_migration_reconcile_state: &AtomicU8,
    err: &anyhow::Error,
    context: &str,
) {
    let writes_enabled = mark_db_available_after_successful_poll_load(
        db,
        db_available,
        context,
        auto_apply_plugin_migrations,
        plugin_migration_reconcile_state,
    )
    .await;
    crate::modes::apply_config_validation_rejection(
        db_available,
        config_rejected,
        writes_enabled,
        err,
        context,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn normal_startup_seeds_poll_cursor_from_initial_full_load() {
        let source = include_str!("database.rs");
        assert!(
            source.contains("let (config, initial_change_sequence) ="),
            "database startup must retain the initial full-load change sequence"
        );
        assert!(
            source.contains("let mut last_change_sequence: Option<u64> = initial_change_sequence;"),
            "poll loop must start from the initial full-load cursor"
        );
    }

    #[test]
    fn offline_recovery_reconciles_custom_plugin_migrations() {
        // Issue #2630: after backup/offline bootstrap skips custom-plugin
        // migrations, the poll-loop availability helper must invoke the same
        // warn/auto-apply policy once deferred core migrations succeed.
        let source = include_str!("database.rs");
        let helper_start = source
            .find("async fn mark_db_available_after_successful_poll_load(")
            .expect("availability helper must exist");
        let helper = &source[helper_start..];
        assert!(
            helper.contains("handle_recovery_plugin_migrations"),
            "recovery path must reconcile custom-plugin migrations"
        );
        assert!(
            helper.contains("database-recovery"),
            "recovery reconcile mode label must identify the recovery path"
        );
        assert!(
            helper.contains("compare_exchange(")
                && helper.contains("PLUGIN_MIGRATIONS_RECONCILING"),
            "recovery must admit only one reconcile attempt per generation"
        );
        assert!(
            source.contains("if bootstrap_from_backup {")
                && source.contains("PLUGIN_MIGRATIONS_NEED_RECONCILE"),
            "offline bootstrap must initialize the reconcile state as pending"
        );
        assert!(
            source.contains("async fn try_publish_full_reload_after_gate(")
                && source.contains("mark_db_available_after_successful_poll_load("),
            "full-reload publication must go through the gated publish chokepoint"
        );
        // Incremental applies are not full reloads; they still call the gate
        // directly. Full-reload sites must not call update_config outside the
        // chokepoint helper.
        let poll_start = source
            .find("let db_poll_handle = tokio::spawn(async move {")
            .expect("database poll task must exist");
        let poll_end = source[poll_start..]
            .find("background_handles.push(db_poll_handle)")
            .expect("poll task must be pushed onto background handles");
        let poll_section = &source[poll_start..poll_start + poll_end];
        assert!(
            !poll_section.contains("proxy_state_poll.update_config("),
            "poll-loop full reloads must publish only via try_publish_full_reload_after_gate"
        );
        assert!(
            poll_section.contains("schedule_admin_read_replica_reconnect_if_needed")
                && poll_section.find("schedule_admin_read_replica_reconnect_if_needed")
                    < poll_section.find("try_publish_full_reload_after_gate"),
            "replica maintenance must run before publication gates on each tick"
        );
        assert!(
            poll_section.contains("PLUGIN_MIGRATIONS_NEED_RECONCILE, Ordering::Release)"),
            "topology reconnect must reset the plugin-migration reconcile gate"
        );
    }

    #[test]
    fn startup_load_recovery_clears_backup_state_before_admin_initialization() {
        // Issue #2802: the database can recover after the eager deferred-
        // migration probe but before the initial authoritative load.
        let source = include_str!("database.rs");
        let success_arm = source
            .find("Ok((cfg, sequence)) => {")
            .expect("initial load success arm must exist");
        let initial_availability = source
            .find("let db_available = Arc::new(AtomicBool::new(initial_db_available(")
            .expect("initial availability initialization must exist");
        let startup_recovery = &source[success_arm..initial_availability];
        assert!(
            startup_recovery.contains("database-recovered-during-startup")
                && startup_recovery.contains("handle_startup_plugin_migrations("),
            "a successful initial DB load after offline connect must run plugin migration policy"
        );
        assert!(
            startup_recovery.contains(".store(PLUGIN_MIGRATIONS_RECONCILED, Ordering::Release)")
                && startup_recovery.contains("bootstrap_from_backup = false;"),
            "startup recovery must clear both migration and backup availability gates"
        );
    }

    fn offline_recovery_test_store() -> (DatabaseStore, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().expect("temporary recovery database");
        let db_path = temp_dir.path().join("plugin-recovery.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let store = DatabaseStore::connect_offline_with_pool_config(
            "sqlite",
            &db_url,
            &[],
            DbPoolConfig::default(),
        )
        .expect("offline recovery store");
        (store, temp_dir)
    }

    #[tokio::test]
    async fn offline_recovery_warn_only_probe_failure_matches_startup_and_allows_publication() {
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if plugin_migrations.is_empty() {
            // Default production builds deliberately compile no pedagogical
            // plugins. Hosted CI opts the examples in and exercises this path.
            return;
        }

        let (store, _temp_dir) = offline_recovery_test_store();
        let pool = store.pool();
        sqlx::query("CREATE TABLE _ferrum_plugin_migrations (broken TEXT)")
            .execute(&pool)
            .await
            .expect("malformed tracking table");
        let db: Arc<dyn DatabaseBackend> = Arc::new(store);
        let db_available = AtomicBool::new(false);
        let reconcile_state = AtomicU8::new(PLUGIN_MIGRATIONS_NEED_RECONCILE);

        // Warn-only probe failure must not wedge harder than a process restart
        // (startup uses the non-strict probe path and continues).
        assert!(
            mark_db_available_after_successful_poll_load(
                &db,
                &db_available,
                "test failed custom-plugin probe",
                false,
                &reconcile_state,
            )
            .await,
            "warn-only recovery must publish after a loud probe-failure warn"
        );
        assert!(db_available.load(Ordering::Relaxed));
        assert_eq!(
            reconcile_state.load(Ordering::Acquire),
            PLUGIN_MIGRATIONS_RECONCILED
        );
    }

    #[tokio::test]
    async fn offline_recovery_auto_apply_probe_failure_stays_fail_closed() {
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if plugin_migrations.is_empty() {
            return;
        }

        let (store, _temp_dir) = offline_recovery_test_store();
        let pool = store.pool();
        sqlx::query("CREATE TABLE _ferrum_plugin_migrations (broken TEXT)")
            .execute(&pool)
            .await
            .expect("malformed tracking table");
        let db: Arc<dyn DatabaseBackend> = Arc::new(store);
        let db_available = AtomicBool::new(true);
        let reconcile_state = AtomicU8::new(PLUGIN_MIGRATIONS_NEED_RECONCILE);

        assert!(
            !mark_db_available_after_successful_poll_load(
                &db,
                &db_available,
                "test auto-apply probe failure",
                true,
                &reconcile_state,
            )
            .await,
            "auto-apply recovery must stay fail-closed when the pending probe fails"
        );
        assert!(!db_available.load(Ordering::Relaxed));
        assert_eq!(
            reconcile_state.load(Ordering::Acquire),
            PLUGIN_MIGRATIONS_NEED_RECONCILE
        );
    }

    #[tokio::test]
    async fn offline_recovery_warn_only_publishes_when_probe_succeeds_with_pending() {
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if plugin_migrations.is_empty() {
            return;
        }

        let (store, _temp_dir) = offline_recovery_test_store();
        let db: Arc<dyn DatabaseBackend> = Arc::new(store);
        let db_available = AtomicBool::new(false);
        let reconcile_state = AtomicU8::new(PLUGIN_MIGRATIONS_NEED_RECONCILE);

        assert!(
            mark_db_available_after_successful_poll_load(
                &db,
                &db_available,
                "test recovered custom-plugin probe",
                false,
                &reconcile_state,
            )
            .await,
            "warn-only recovery should publish after the probe succeeds"
        );
        assert!(db_available.load(Ordering::Relaxed));
        assert_eq!(
            reconcile_state.load(Ordering::Acquire),
            PLUGIN_MIGRATIONS_RECONCILED
        );
        assert!(
            !db.pending_plugin_migrations(&plugin_migrations)
                .await
                .expect("warn-only pending list")
                .is_empty(),
            "warn-only recovery must not mutate custom-plugin schema"
        );
    }

    #[tokio::test]
    async fn offline_recovery_validation_rejection_cannot_bypass_plugin_probe() {
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if plugin_migrations.is_empty() {
            return;
        }

        let (store, _temp_dir) = offline_recovery_test_store();
        let pool = store.pool();
        sqlx::query("CREATE TABLE _ferrum_plugin_migrations (broken TEXT)")
            .execute(&pool)
            .await
            .expect("malformed tracking table");
        let db: Arc<dyn DatabaseBackend> = Arc::new(store);
        let db_available = AtomicBool::new(false);
        let config_rejected = AtomicBool::new(false);
        let reconcile_state = AtomicU8::new(PLUGIN_MIGRATIONS_NEED_RECONCILE);
        let rejection = validation_rejection_error();

        record_config_validation_rejection_after_recovery_migration_gate(
            &db,
            &db_available,
            &config_rejected,
            false,
            &reconcile_state,
            &rejection,
            "test rejected recovery snapshot",
        )
        .await;
        assert!(config_rejected.load(Ordering::Relaxed));
        // Warn-only probe failure matches startup (does not block writes); the
        // independent config_rejected signal still prevents serving the bad
        // snapshot while in-band repair remains available.
        assert!(
            db_available.load(Ordering::Relaxed),
            "warn-only probe failure must not wedge admin writes harder than restart"
        );
        assert_eq!(
            reconcile_state.load(Ordering::Acquire),
            PLUGIN_MIGRATIONS_RECONCILED
        );
        assert!(
            config_rejected.load(Ordering::Relaxed),
            "migration reconciliation must not clear the independent config rejection"
        );
    }

    #[tokio::test]
    async fn offline_recovery_auto_apply_finishes_plugin_schema_before_publication() {
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if plugin_migrations.is_empty() {
            return;
        }

        let (store, _temp_dir) = offline_recovery_test_store();
        let db: Arc<dyn DatabaseBackend> = Arc::new(store);
        let db_available = AtomicBool::new(false);
        let reconcile_state = AtomicU8::new(PLUGIN_MIGRATIONS_NEED_RECONCILE);

        assert!(
            mark_db_available_after_successful_poll_load(
                &db,
                &db_available,
                "test custom-plugin auto-apply",
                true,
                &reconcile_state,
            )
            .await,
            "auto-apply recovery should publish only after migrations succeed"
        );
        assert!(db_available.load(Ordering::Relaxed));
        assert_eq!(
            reconcile_state.load(Ordering::Acquire),
            PLUGIN_MIGRATIONS_RECONCILED
        );
        assert!(
            db.pending_plugin_migrations(&plugin_migrations)
                .await
                .expect("post-apply pending list")
                .is_empty(),
            "auto-apply recovery must finish every compiled custom migration"
        );
    }

    #[test]
    fn full_reload_applies_deferred_migrations_before_sequence_cursor_read() {
        let source = include_str!("database.rs");
        let helper_start = source
            .find("async fn load_full_config_with_sequence")
            .expect("load_full_config_with_sequence helper must exist");
        let helper_end = source[helper_start..]
            .find("fn commit_full_reload_poll_state")
            .expect("commit_full_reload_poll_state helper must follow full load helper");
        let helper_source = &source[helper_start..helper_start + helper_end];

        let migration_hook = helper_source
            .find("maybe_apply_deferred_migrations")
            .expect("full reload helper must apply deferred migrations");
        let sequence_read = helper_source
            .find("latest_change_sequence")
            .expect("full reload helper must read latest change sequence");

        assert!(
            migration_hook < sequence_read,
            "deferred migrations must run before reading config_changes"
        );
    }

    #[test]
    fn full_reload_unchanged_commits_cursor_and_clears_rejection() {
        // An Unchanged outcome still means the freshly-loaded FULL snapshot
        // passed loader validation, so a standing config_rejected must clear
        // (issue #2158, P2).
        let mut last_change_sequence = Some(7);
        let sequence = 42;
        let config_rejected = AtomicBool::new(true);

        let accepted = commit_full_reload_poll_state(
            "test unchanged",
            proxy::ConfigApplyOutcome::Unchanged,
            &mut last_change_sequence,
            sequence,
            &config_rejected,
        );

        assert!(accepted);
        assert_eq!(last_change_sequence, Some(sequence));
        assert!(
            !config_rejected.load(Ordering::Relaxed),
            "an accepted full reload (even Unchanged) must clear config_rejected"
        );
    }

    #[test]
    fn full_reload_applied_clears_standing_config_rejection() {
        // The primary clearing site: an accepted FULL reload proves the offending
        // row is gone (issue #2158, P2).
        let mut last_change_sequence = None;
        let config_rejected = AtomicBool::new(true);

        let accepted = commit_full_reload_poll_state(
            "test applied",
            proxy::ConfigApplyOutcome::Applied,
            &mut last_change_sequence,
            99,
            &config_rejected,
        );

        assert!(accepted);
        assert_eq!(last_change_sequence, Some(99));
        assert!(
            !config_rejected.load(Ordering::Relaxed),
            "an accepted full reload must clear config_rejected"
        );
    }

    #[test]
    fn full_reload_rejected_preserves_cursor_and_raises_rejection_flag() {
        // A rejected full-reload candidate keeps the previous cursor AND raises
        // config_rejected even when the loader accepted the snapshot but the
        // final runtime apply rejected it.
        let previous_sequence = Some(7);
        let mut last_change_sequence = previous_sequence;
        let config_rejected = AtomicBool::new(false);

        let accepted = commit_full_reload_poll_state(
            "test rejected",
            proxy::ConfigApplyOutcome::Rejected {
                errors: vec!["invalid candidate".to_string()],
            },
            &mut last_change_sequence,
            42,
            &config_rejected,
        );

        assert!(!accepted);
        assert_eq!(last_change_sequence, previous_sequence);
        assert!(
            config_rejected.load(Ordering::Relaxed),
            "a rejected full apply must raise config_rejected"
        );
    }

    #[test]
    fn startup_validation_rejection_respects_migration_gate() {
        assert!(
            initial_db_available(false, true, PLUGIN_MIGRATIONS_RECONCILED),
            "a reachable validation rejection must keep admin writes enabled"
        );
        assert!(
            initial_db_available(true, true, PLUGIN_MIGRATIONS_RECONCILED),
            "validation proof of reachability may enable writes after migration reconciliation"
        );
        assert!(
            !initial_db_available(true, true, PLUGIN_MIGRATIONS_NEED_RECONCILE),
            "validation proof of reachability must not bypass a pending migration gate"
        );
        assert!(
            !initial_db_available(true, false, PLUGIN_MIGRATIONS_RECONCILED),
            "a connectivity-only backup bootstrap must keep admin writes blocked"
        );
    }

    #[test]
    fn startup_backup_seeds_config_rejection_before_first_poll() {
        let source = include_str!("database.rs");
        assert!(
            source.contains(
                "startup_config_rejected = crate::modes::is_poll_validation_rejection(&e);"
            ),
            "backup startup must classify the initial full-load failure"
        );
        assert!(
            source.contains("AtomicBool::new(startup_config_rejected)"),
            "backup startup must expose config_rejected before the poll loop starts"
        );
        assert!(
            source.contains("if bootstrap_from_backup && startup_config_rejected")
                && source.contains("initial validation-rejected snapshot"),
            "a validation-rejected offline bootstrap must run the recovery migration gate"
        );
    }

    fn validation_rejection_error() -> anyhow::Error {
        crate::config::validation_pipeline::ConfigValidationRejection {
            backend: "MongoDB",
            errors: vec!["dangling upstream reference".to_string()],
        }
        .into_anyhow()
    }

    // The classification/state-machine semantics (writes stay enabled subject to
    // the migration gate, config_rejected raised, connectivity ≠ rejection) are
    // tested directly against the shared helpers in `crate::modes` tests. Here we
    // only pin the DB-mode LIFECYCLE wiring that composes those helpers.

    #[test]
    fn rejected_full_then_incremental_keeps_flag_until_next_full_reload() {
        // Issue #2158, P2 lifecycle: a validation-rejected FULL snapshot raises
        // config_rejected; an accepted incremental must NOT clear it (it does not
        // re-validate the whole snapshot); only an accepted FULL reload clears it.
        let db_available = AtomicBool::new(true);
        let config_rejected = AtomicBool::new(false);

        // 1) Rejected full snapshot raises the flag (migration gate satisfied so
        //    writes stay enabled).
        crate::modes::apply_config_validation_rejection(
            &db_available,
            &config_rejected,
            true,
            &validation_rejection_error(),
            "full poll",
        );
        assert!(config_rejected.load(Ordering::Relaxed));

        // 2) An accepted incremental keeps the flag set. The incremental-success
        //    path calls only mark_db_available_after_successful_poll_load, whose
        //    signature carries no config_rejected handle, so it cannot clear the
        //    flag. Assert that structural guarantee against the source.
        let source = include_str!("database.rs");
        let sig_start = source
            .find("async fn mark_db_available_after_successful_poll_load(")
            .expect("incremental-success helper must exist");
        let sig_end = sig_start
            + source[sig_start..]
                .find('{')
                .expect("incremental-success helper signature must terminate");
        assert!(
            !source[sig_start..sig_end].contains("config_rejected"),
            "the incremental-success helper must not carry a config_rejected handle"
        );

        // 3) An accepted full reload clears the flag.
        let mut cursor = Some(1);
        let accepted = commit_full_reload_poll_state(
            "full reload",
            proxy::ConfigApplyOutcome::Applied,
            &mut cursor,
            2,
            &config_rejected,
        );
        assert!(accepted);
        assert!(
            !config_rejected.load(Ordering::Relaxed),
            "an accepted full reload must clear config_rejected"
        );
    }

    fn incremental_with_removed_proxy(
        proxy_id: &str,
        poll_timestamp: DateTime<Utc>,
    ) -> db_backend::IncrementalResult {
        db_backend::IncrementalResult {
            added_or_modified_proxies: vec![],
            removed_proxy_ids: vec![proxy_id.to_string()],
            added_or_modified_consumers: vec![],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![],
            removed_upstream_ids: vec![],
            sequence_cursor: 1,
            poll_timestamp,
        }
    }

    fn incremental_with_plugin_config(
        config: serde_json::Value,
        poll_timestamp: DateTime<Utc>,
    ) -> db_backend::IncrementalResult {
        let timestamp = poll_timestamp;
        db_backend::IncrementalResult {
            added_or_modified_proxies: vec![],
            removed_proxy_ids: vec![],
            added_or_modified_consumers: vec![],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![crate::config::types::PluginConfig {
                id: "plugin-a".to_string(),
                plugin_name: "rate_limiting".to_string(),
                namespace: crate::config::types::default_namespace(),
                config,
                scope: crate::config::types::PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: timestamp,
                updated_at: timestamp,
            }],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![],
            removed_upstream_ids: vec![],
            sequence_cursor: 1,
            poll_timestamp,
        }
    }

    #[test]
    fn rejected_delta_identity_ignores_poll_timestamp_for_same_effective_delta() {
        let after_sequence = 9;
        let first = incremental_with_removed_proxy("proxy-a", Utc::now());
        let second =
            incremental_with_removed_proxy("proxy-a", Utc::now() + chrono::Duration::seconds(5));

        assert_eq!(
            RejectedDeltaIdentity::from_incremental(after_sequence, &first),
            RejectedDeltaIdentity::from_incremental(after_sequence, &second),
            "same cursor and change set should classify as the same rejected delta even when poll timestamps differ"
        );
    }

    #[test]
    fn rejected_delta_identity_includes_content_for_same_ids() {
        let after_sequence = 9;
        let poll_timestamp = Utc::now();
        let first = incremental_with_plugin_config(
            serde_json::json!({"limit": 10, "window_seconds": 60}),
            poll_timestamp,
        );
        let second = incremental_with_plugin_config(
            serde_json::json!({"limit": 20, "window_seconds": 60}),
            poll_timestamp,
        );

        assert_ne!(
            RejectedDeltaIdentity::from_incremental(after_sequence, &first),
            RejectedDeltaIdentity::from_incremental(after_sequence, &second),
            "same resource IDs with different content must reset rejected-delta backoff state"
        );
    }

    #[test]
    fn validation_category_classification_bounds_error_input() {
        let mut too_many_errors = vec!["unrelated validation failure".repeat(200); 32];
        too_many_errors.push("security plugin missing".to_string());
        assert_eq!(
            DatabaseDeltaValidationCategory::classify(&too_many_errors),
            DatabaseDeltaValidationCategory::Other
        );

        let long_error = format!("{} tls certificate invalid", "x".repeat(300));
        assert_eq!(
            DatabaseDeltaValidationCategory::classify(&[long_error]),
            DatabaseDeltaValidationCategory::Other
        );

        assert_eq!(
            DatabaseDeltaValidationCategory::classify(&[
                "duplicate listen path".to_string(),
                "security plugin missing".to_string(),
            ]),
            DatabaseDeltaValidationCategory::SecurityPlugin
        );
    }

    #[test]
    fn backoff_bucket_reports_long_non_max_backoff_separately() {
        assert_eq!(
            DatabaseDeltaBackoffBucket::for_duration(
                Duration::from_secs(600),
                Duration::from_secs(3600),
            )
            .as_str(),
            "gte_5m"
        );
        assert_eq!(
            DatabaseDeltaBackoffBucket::for_duration(
                Duration::from_secs(300),
                Duration::from_secs(300),
            )
            .as_str(),
            "max"
        );
    }

    #[test]
    fn rejected_delta_tracker_backs_off_to_max_and_escalates() {
        let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
        let mut tracker = RejectedDeltaTracker::new(
            Duration::from_secs(1),
            Duration::from_secs(4),
            3,
            metrics.clone(),
        );
        let after_sequence = 9;
        let result = incremental_with_removed_proxy("proxy-a", Utc::now());
        let identity = RejectedDeltaIdentity::from_incremental(after_sequence, &result);
        let errors = vec!["duplicate listen path '/api'".to_string()];

        let first = tracker.record_rejection(identity.clone().with_validation(&errors));
        assert_eq!(first.consecutive, 1);
        assert_eq!(first.backoff, Duration::from_secs(1));
        assert_eq!(first.log_action, RejectedDeltaLogAction::First);
        assert!(!first.should_escalate);

        let second = tracker.record_rejection(identity.clone().with_validation(&errors));
        assert_eq!(second.consecutive, 2);
        assert_eq!(second.backoff, Duration::from_secs(2));
        assert_eq!(second.log_action, RejectedDeltaLogAction::BackoffTransition);
        assert!(!second.should_escalate);

        let third = tracker.record_rejection(identity.clone().with_validation(&errors));
        assert_eq!(third.consecutive, 3);
        assert_eq!(third.backoff, Duration::from_secs(4));
        assert_eq!(third.log_action, RejectedDeltaLogAction::Escalation);
        assert!(third.should_escalate);

        let fourth = tracker.record_rejection(identity.with_validation(&errors));
        assert_eq!(fourth.consecutive, 4);
        assert_eq!(fourth.backoff, Duration::from_secs(4));
        assert_eq!(fourth.log_action, RejectedDeltaLogAction::Suppressed);
        assert!(!fourth.should_escalate);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.consecutive_identical_rejections, 4);
        assert_eq!(snapshot.current_backoff_bucket, "max");
        assert_eq!(
            snapshot
                .rejected_deltas_by_resource_category
                .get("proxy")
                .copied(),
            Some(4)
        );
        assert!(snapshot.degraded.is_some());
    }

    #[test]
    fn rejected_delta_tracker_resets_for_different_delta_and_recovery() {
        let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
        let mut tracker = RejectedDeltaTracker::new(
            Duration::from_secs(1),
            Duration::from_secs(8),
            3,
            metrics.clone(),
        );
        let after_sequence = 9;
        let first_delta = incremental_with_removed_proxy("proxy-a", Utc::now());
        let second_delta = incremental_with_removed_proxy("proxy-b", Utc::now());
        let errors = vec!["duplicate listen path '/api'".to_string()];

        let first_identity = RejectedDeltaIdentity::from_incremental(after_sequence, &first_delta);
        tracker.record_rejection(first_identity.clone().with_validation(&errors));
        tracker.record_rejection(first_identity.with_validation(&errors));

        let second_identity =
            RejectedDeltaIdentity::from_incremental(after_sequence, &second_delta);
        let different = tracker.record_rejection(second_identity.with_validation(&errors));
        assert_eq!(different.consecutive, 1);
        assert_eq!(different.backoff, Duration::from_secs(1));
        assert_eq!(different.log_action, RejectedDeltaLogAction::First);

        tracker.record_accepted();
        let recovered = metrics.snapshot();
        assert_eq!(recovered.consecutive_identical_rejections, 0);
        assert_eq!(recovered.current_backoff_bucket, "none");
        assert_eq!(recovered.current_backoff_seconds, 0);
        assert_eq!(recovered.recoveries_total, 1);
        assert!(recovered.degraded.is_none());

        let next = tracker.record_rejection(
            RejectedDeltaIdentity::from_incremental(after_sequence, &second_delta)
                .with_validation(&errors),
        );
        assert_eq!(next.consecutive, 1);
        assert_eq!(next.backoff, Duration::from_secs(1));
    }

    #[test]
    fn rejected_delta_tracker_surfaces_category_change_and_bounded_metrics() {
        let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
        let mut tracker = RejectedDeltaTracker::new(
            Duration::from_secs(1),
            Duration::from_secs(8),
            3,
            metrics.clone(),
        );
        let after_sequence = 9;
        let delta = incremental_with_removed_proxy("secret-proxy-id", Utc::now());
        let identity = RejectedDeltaIdentity::from_incremental(after_sequence, &delta);

        tracker.record_rejection(
            identity
                .clone()
                .with_validation(&["duplicate listen path".to_string()]),
        );
        let changed = tracker.record_rejection(
            identity.with_validation(&["TLS certificate path invalid".to_string()]),
        );

        assert_eq!(
            changed.log_action,
            RejectedDeltaLogAction::ValidationCategoryChanged
        );
        assert_eq!(changed.consecutive, 1);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.last_resource_category, "proxy");
        assert!(
            snapshot
                .rejected_deltas_by_resource_category
                .keys()
                .all(|label| !label.contains("secret-proxy-id"))
        );
        let degraded = snapshot.degraded.expect("active rejection is degraded");
        assert_eq!(degraded.reason, "rejected_incremental_delta");
        assert_eq!(degraded.resource_category, "proxy");
        assert_eq!(degraded.validation_category, "tls");
    }

    #[test]
    fn prometheus_registry_renders_database_delta_poll_metrics() {
        let registry = crate::plugins::prometheus_metrics::MetricsRegistry::new();
        registry.configure(5, 3600, 0, "ops");
        assert!(registry.database_delta_poll_metrics_snapshot().is_none());

        let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
        let mut tracker = RejectedDeltaTracker::new(
            Duration::from_secs(4),
            Duration::from_secs(4),
            1,
            metrics.clone(),
        );
        let after_sequence = 9;
        let delta = incremental_with_removed_proxy("proxy-a", Utc::now());
        let identity = RejectedDeltaIdentity::from_incremental(after_sequence, &delta);
        let decision = tracker
            .record_rejection(identity.with_validation(&["missing plugin reference".to_string()]));
        assert!(decision.should_escalate);
        metrics.record_forced_full_reload();

        registry.set_database_delta_poll_metrics(metrics.clone());
        let snapshot = registry
            .database_delta_poll_metrics_snapshot()
            .expect("registered metrics should produce a snapshot");
        assert_eq!(snapshot.rejected_deltas_total, 1);
        assert_eq!(snapshot.consecutive_identical_rejections, 1);
        assert_eq!(snapshot.current_backoff_bucket, "max");
        assert_eq!(snapshot.forced_full_reloads_total, 1);

        let output = registry.render_uncached();
        assert!(output.contains("ferrum_database_delta_rejections_total"));
        assert!(output.contains(
            r#"ferrum_database_delta_rejections_total{resource_category="proxy",namespace="ops"} 1"#
        ));
        assert!(output.contains(
            r#"ferrum_database_delta_rejections_total{resource_category="consumer",namespace="ops"} 0"#
        ));
        assert!(output.contains(
            r#"ferrum_database_delta_consecutive_identical_rejections{namespace="ops"} 1"#
        ));
        assert!(
            output.contains(
                r#"ferrum_database_delta_backoff_bucket{bucket="max",namespace="ops"} 1"#
            )
        );
        assert!(
            output.contains(
                r#"ferrum_database_delta_backoff_bucket{bucket="lt_5s",namespace="ops"} 0"#
            )
        );
        assert!(output.contains(
            r#"ferrum_database_delta_backoff_bucket{bucket="gte_5m",namespace="ops"} 0"#
        ));
        assert!(
            output
                .contains(r#"ferrum_database_delta_forced_full_reloads_total{namespace="ops"} 1"#)
        );
        assert!(output.contains(r#"ferrum_database_delta_recoveries_total{namespace="ops"} 0"#));

        tracker.record_accepted();
        let recovered = registry.render_uncached();
        assert!(recovered.contains(
            r#"ferrum_database_delta_consecutive_identical_rejections{namespace="ops"} 0"#
        ));
        assert!(
            recovered.contains(
                r#"ferrum_database_delta_backoff_bucket{bucket="none",namespace="ops"} 1"#
            )
        );
        assert!(recovered.contains(r#"ferrum_database_delta_recoveries_total{namespace="ops"} 1"#));
    }

    #[test]
    fn prometheus_registry_invalidates_cached_database_delta_poll_metrics() {
        let registry = crate::plugins::prometheus_metrics::global_registry();
        registry.configure(3600, 3600, 0, "ops-cache");

        let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
        let mut tracker = RejectedDeltaTracker::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            3,
            metrics.clone(),
        );
        registry.set_database_delta_poll_metrics(metrics);

        let initial = registry.render();
        assert!(initial.contains(
            r#"ferrum_database_delta_rejections_total{resource_category="proxy",namespace="ops-cache"} 0"#
        ));

        let after_sequence = 9;
        let delta = incremental_with_removed_proxy("proxy-a", Utc::now());
        let identity = RejectedDeltaIdentity::from_incremental(after_sequence, &delta);
        tracker.record_rejection(identity.with_validation(&["missing upstream".to_string()]));

        let updated = registry.render();
        assert!(updated.contains(
            r#"ferrum_database_delta_rejections_total{resource_category="proxy",namespace="ops-cache"} 1"#
        ));
    }
}
