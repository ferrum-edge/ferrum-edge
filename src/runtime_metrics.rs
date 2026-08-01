//! Process-global runtime counters for the admin `/metrics/runtime` endpoint.
//!
//! Recording APIs are intentionally tiny and hot-path friendly: existing keys
//! are a single relaxed atomic increment, and cold inserts are bounded by the
//! same status counter cap used elsewhere in the gateway.

use arc_swap::ArcSwap;
use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::plugins::{Direction, StreamTransactionSummary, TransactionSummary};
use crate::retry::ErrorClass;
use crate::system_metrics::SystemSnapshot;

pub static RUNTIME_METRICS: OnceLock<Arc<RuntimeMetrics>> = OnceLock::new();

pub fn global() -> Arc<RuntimeMetrics> {
    Arc::clone(RUNTIME_METRICS.get_or_init(|| Arc::new(RuntimeMetrics::new())))
}

pub fn global_ref() -> &'static RuntimeMetrics {
    RUNTIME_METRICS
        .get_or_init(|| Arc::new(RuntimeMetrics::new()))
        .as_ref()
}

pub type ErrorCounterMap = DashMap<&'static str, DashMap<Arc<str>, CachePadded<AtomicU64>>>;

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum PoolKind {
    HttpReqwest,
    Http2Direct,
    Http3,
    Grpc,
    Hbone,
    /// Sidecar egress SVID-mTLS HTTP/2 pool (`mesh_mtls_pool`).
    MeshMtls,
}

impl PoolKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpReqwest => "http_reqwest",
            Self::Http2Direct => "http2_direct",
            Self::Http3 => "http3",
            Self::Grpc => "grpc",
            Self::Hbone => "hbone",
            Self::MeshMtls => "mesh_mtls",
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct RstKey {
    pub proxy_id: Arc<str>,
    pub direction: &'static str,
}

#[repr(usize)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Trace => 0,
            Self::Debug => 1,
            Self::Info => 2,
            Self::Warn => 3,
            Self::Error => 4,
        }
    }
}

const LOG_LEVELS: [LogLevel; 5] = [
    LogLevel::Trace,
    LogLevel::Debug,
    LogLevel::Info,
    LogLevel::Warn,
    LogLevel::Error,
];

const ERROR_CLASSES: [&str; 17] = [
    "connection_timeout",
    "connection_refused",
    "connection_reset",
    "connection_closed",
    "dns_lookup_error",
    "tls_error",
    "read_write_timeout",
    "client_disconnect",
    "protocol_error",
    "response_body_too_large",
    "gateway_buffer_capacity",
    "request_body_too_large",
    "connection_pool_error",
    "port_exhaustion",
    "graceful_remote_close",
    "dispatch_policy_rejected",
    "request_error",
];

pub struct RuntimeMetrics {
    pub http_errors_by_class: ErrorCounterMap,
    pub grpc_errors_by_class: ErrorCounterMap,
    pub body_errors_by_class: ErrorCounterMap,
    pub stream_errors_by_class: ErrorCounterMap,
    error_entry_count: AtomicUsize,

    pub dns_lookups_total: CachePadded<AtomicU64>,
    pub dns_cache_hits: CachePadded<AtomicU64>,
    pub dns_cache_misses: CachePadded<AtomicU64>,
    pub dns_stale_serves: CachePadded<AtomicU64>,
    pub dns_lookup_errors: CachePadded<AtomicU64>,

    pub pool_handshakes_total: DashMap<PoolKind, CachePadded<AtomicU64>>,
    pub pool_evictions_total: DashMap<PoolKind, CachePadded<AtomicU64>>,
    pub pool_failures_total: DashMap<PoolKind, CachePadded<AtomicU64>>,

    pub tcp_rst_observed: DashMap<RstKey, CachePadded<AtomicU64>>,

    pub log_counts: [CachePadded<AtomicU64>; 5],
    pub log_counts_by_category: DashMap<(LogLevel, &'static str), CachePadded<AtomicU64>>,

    pub status_window_1m: DashMap<u16, AtomicU64>,
    pub status_window_5m: DashMap<u16, AtomicU64>,
    pub status_window_rotated_at: AtomicU64,

    pub system: ArcSwap<SystemSnapshot>,
    pub started_at: Instant,

    max_error_entries: AtomicUsize,
    pool_tracking_enabled: AtomicBool,
    status_tracking_enabled: AtomicBool,
    cache_ttl_ms: AtomicU64,
    client_disconnects: CachePadded<AtomicU64>,
    reqwest_active_backend_requests: CachePadded<AtomicU64>,
    status_count_window_1m: DashMap<u16, AtomicU64>,
    status_count_window_5m: DashMap<u16, AtomicU64>,
    status_current_1m: DashMap<u16, CachePadded<AtomicU64>>,
    status_current_5m: DashMap<u16, CachePadded<AtomicU64>>,
    requests_current_1m: CachePadded<AtomicU64>,
    requests_current_5m: CachePadded<AtomicU64>,
    requests_window_1m: CachePadded<AtomicU64>,
    requests_window_5m: CachePadded<AtomicU64>,
    requests_count_window_1m: CachePadded<AtomicU64>,
    requests_count_window_5m: CachePadded<AtomicU64>,
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        Self {
            http_errors_by_class: DashMap::new(),
            grpc_errors_by_class: DashMap::new(),
            body_errors_by_class: DashMap::new(),
            stream_errors_by_class: DashMap::new(),
            error_entry_count: AtomicUsize::new(0),
            dns_lookups_total: CachePadded::new(AtomicU64::new(0)),
            dns_cache_hits: CachePadded::new(AtomicU64::new(0)),
            dns_cache_misses: CachePadded::new(AtomicU64::new(0)),
            dns_stale_serves: CachePadded::new(AtomicU64::new(0)),
            dns_lookup_errors: CachePadded::new(AtomicU64::new(0)),
            pool_handshakes_total: DashMap::new(),
            pool_evictions_total: DashMap::new(),
            pool_failures_total: DashMap::new(),
            tcp_rst_observed: DashMap::new(),
            log_counts: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
            log_counts_by_category: DashMap::new(),
            status_window_1m: DashMap::new(),
            status_window_5m: DashMap::new(),
            status_window_rotated_at: AtomicU64::new(0),
            system: ArcSwap::from_pointee(SystemSnapshot::empty()),
            started_at: Instant::now(),
            max_error_entries: AtomicUsize::new(200),
            pool_tracking_enabled: AtomicBool::new(true),
            status_tracking_enabled: AtomicBool::new(true),
            cache_ttl_ms: AtomicU64::new(1000),
            client_disconnects: CachePadded::new(AtomicU64::new(0)),
            reqwest_active_backend_requests: CachePadded::new(AtomicU64::new(0)),
            status_count_window_1m: DashMap::new(),
            status_count_window_5m: DashMap::new(),
            status_current_1m: DashMap::new(),
            status_current_5m: DashMap::new(),
            requests_current_1m: CachePadded::new(AtomicU64::new(0)),
            requests_current_5m: CachePadded::new(AtomicU64::new(0)),
            requests_window_1m: CachePadded::new(AtomicU64::new(0)),
            requests_window_5m: CachePadded::new(AtomicU64::new(0)),
            requests_count_window_1m: CachePadded::new(AtomicU64::new(0)),
            requests_count_window_5m: CachePadded::new(AtomicU64::new(0)),
        }
    }

    pub fn configure(
        &self,
        max_error_entries: usize,
        pool_tracking_enabled: bool,
        status_tracking_enabled: bool,
        cache_ttl_ms: u64,
    ) {
        self.max_error_entries
            .store(max_error_entries.max(1), Ordering::Relaxed);
        self.pool_tracking_enabled
            .store(pool_tracking_enabled, Ordering::Relaxed);
        self.status_tracking_enabled
            .store(status_tracking_enabled, Ordering::Relaxed);
        self.cache_ttl_ms.store(cache_ttl_ms, Ordering::Relaxed);
    }

    pub fn cache_ttl_ms(&self) -> u64 {
        self.cache_ttl_ms.load(Ordering::Relaxed)
    }

    pub fn record_http_status(&self, status: u16) {
        if !self.status_tracking_enabled.load(Ordering::Relaxed) {
            return;
        }
        self.increment_status_current(status);
    }

    pub fn reqwest_backend_request_guard(&'static self) -> ReqwestBackendRequestGuard {
        self.reqwest_active_backend_requests
            .fetch_add(1, Ordering::Relaxed);
        ReqwestBackendRequestGuard { metrics: self }
    }

    pub fn reqwest_active_backend_requests(&self) -> u64 {
        self.reqwest_active_backend_requests.load(Ordering::Relaxed)
    }

    pub fn record_transaction(&self, summary: &TransactionSummary) {
        if summary.client_disconnected {
            self.client_disconnects.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(class) = summary.error_class {
            if is_grpc_summary(summary) {
                self.record_grpc_error_inner(summary.proxy_id.as_deref(), class, false);
            } else {
                self.record_http_error_inner(summary.proxy_id.as_deref(), class, false);
            }
        }

        if let Some(class) = summary.body_error_class {
            self.increment_error_map(
                &self.body_errors_by_class,
                summary.proxy_id.as_deref().unwrap_or("unknown"),
                class.as_str(),
            );
        }
    }

    pub fn record_http_error(&self, proxy_id: Option<&str>, class: ErrorClass) {
        self.record_http_error_inner(proxy_id, class, true);
    }

    pub fn record_grpc_error(&self, proxy_id: Option<&str>, class: ErrorClass) {
        self.record_grpc_error_inner(proxy_id, class, true);
    }

    fn record_http_error_inner(
        &self,
        proxy_id: Option<&str>,
        class: ErrorClass,
        count_client_disconnect_class: bool,
    ) {
        if count_client_disconnect_class && class == ErrorClass::ClientDisconnect {
            self.client_disconnects.fetch_add(1, Ordering::Relaxed);
        }
        self.increment_error_map(
            &self.http_errors_by_class,
            proxy_id.unwrap_or("unknown"),
            class.as_str(),
        );
    }

    fn record_grpc_error_inner(
        &self,
        proxy_id: Option<&str>,
        class: ErrorClass,
        count_client_disconnect_class: bool,
    ) {
        if count_client_disconnect_class && class == ErrorClass::ClientDisconnect {
            self.client_disconnects.fetch_add(1, Ordering::Relaxed);
        }
        self.increment_error_map(
            &self.grpc_errors_by_class,
            proxy_id.unwrap_or("unknown"),
            class.as_str(),
        );
    }

    pub fn record_stream_transaction(&self, summary: &StreamTransactionSummary) {
        if let Some(class) = summary.error_class {
            self.increment_error_map(
                &self.stream_errors_by_class,
                summary.proxy_id.as_str(),
                class.as_str(),
            );
        }
    }

    pub fn record_dns_hit(&self) {
        self.dns_lookups_total.fetch_add(1, Ordering::Relaxed);
        self.dns_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_miss(&self) {
        self.dns_lookups_total.fetch_add(1, Ordering::Relaxed);
        self.dns_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_stale(&self) {
        self.dns_lookups_total.fetch_add(1, Ordering::Relaxed);
        self.dns_stale_serves.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_error(&self) {
        self.dns_lookups_total.fetch_add(1, Ordering::Relaxed);
        self.dns_lookup_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pool_handshake(&self, kind: PoolKind) {
        if self.pool_tracking_enabled.load(Ordering::Relaxed) {
            self.increment_pool_map(&self.pool_handshakes_total, kind);
        }
    }

    pub fn record_pool_failure(&self, kind: PoolKind) {
        if self.pool_tracking_enabled.load(Ordering::Relaxed) {
            self.increment_pool_map(&self.pool_failures_total, kind);
        }
    }

    pub fn record_pool_eviction(&self, kind: PoolKind) {
        self.record_pool_evictions(kind, 1);
    }

    pub fn record_pool_evictions(&self, kind: PoolKind, count: u64) {
        if count == 0 {
            return;
        }
        if self.pool_tracking_enabled.load(Ordering::Relaxed) {
            self.increment_pool_map_by(&self.pool_evictions_total, kind, count);
        }
    }

    pub fn record_tcp_rst(&self, proxy_id: &str, direction: Direction) {
        let key = RstKey {
            proxy_id: Arc::<str>::from(proxy_id),
            direction: direction_label(direction),
        };
        if let Some(counter) = self.tcp_rst_observed.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else if self.tcp_rst_observed.len() < self.max_error_entries.load(Ordering::Relaxed) {
            self.tcp_rst_observed
                .entry(key)
                .or_insert_with(|| CachePadded::new(AtomicU64::new(0)))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_log(&self, level: LogLevel, category: &'static str) {
        self.log_counts[level.index()].fetch_add(1, Ordering::Relaxed);
        self.log_counts_by_category
            .entry((level, category))
            .or_insert_with(|| CachePadded::new(AtomicU64::new(0)))
            .fetch_add(1, Ordering::Relaxed);
    }

    fn increment_status_current(&self, status: u16) {
        self.requests_current_1m.fetch_add(1, Ordering::Relaxed);
        self.requests_current_5m.fetch_add(1, Ordering::Relaxed);
        increment_status_map(&self.status_current_1m, status);
        increment_status_map(&self.status_current_5m, status);
    }

    fn increment_error_map(&self, map: &ErrorCounterMap, proxy_id: &str, class: &'static str) {
        if let Some(class_counters) = map.get(class)
            && let Some(counter) = class_counters.get(proxy_id)
        {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Determine new-vs-existing via the Entry API, then reserve capacity
        // before inserting a vacant key. This keeps the cap strict even when
        // many distinct (class, proxy_id) pairs arrive concurrently.
        let class_map = map.entry(class).or_default();
        match class_map.entry(Arc::<str>::from(proxy_id)) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                occupied.get().fetch_add(1, Ordering::Relaxed);
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                if !self.try_reserve_error_entry() {
                    return;
                }
                vacant
                    .insert(CachePadded::new(AtomicU64::new(0)))
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn try_reserve_error_entry(&self) -> bool {
        let max = self.max_error_entries.load(Ordering::Relaxed);
        let mut observed = self.error_entry_count.load(Ordering::Relaxed);
        loop {
            if observed >= max {
                return false;
            }
            match self.error_entry_count.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => observed = actual,
            }
        }
    }

    fn increment_pool_map(&self, map: &DashMap<PoolKind, CachePadded<AtomicU64>>, kind: PoolKind) {
        self.increment_pool_map_by(map, kind, 1);
    }

    fn increment_pool_map_by(
        &self,
        map: &DashMap<PoolKind, CachePadded<AtomicU64>>,
        kind: PoolKind,
        count: u64,
    ) {
        map.entry(kind)
            .or_insert_with(|| CachePadded::new(AtomicU64::new(0)))
            .fetch_add(count, Ordering::Relaxed);
    }

    fn rotate_status_window(&self, window: StatusWindow) {
        let (
            current,
            published_rate,
            published_count,
            request_current,
            request_rate_published,
            request_count_published,
            seconds,
        ) = match window {
            StatusWindow::OneMinute(seconds) => (
                &self.status_current_1m,
                &self.status_window_1m,
                &self.status_count_window_1m,
                &self.requests_current_1m,
                &self.requests_window_1m,
                &self.requests_count_window_1m,
                seconds,
            ),
            StatusWindow::FiveMinutes(seconds) => (
                &self.status_current_5m,
                &self.status_window_5m,
                &self.status_count_window_5m,
                &self.requests_current_5m,
                &self.requests_window_5m,
                &self.requests_count_window_5m,
                seconds,
            ),
        };

        let seconds = seconds.max(1);
        let request_delta = request_current.swap(0, Ordering::Relaxed);
        request_rate_published.store(rounding_div(request_delta, seconds), Ordering::Relaxed);
        request_count_published.store(request_delta, Ordering::Relaxed);

        for entry in current.iter() {
            let code = *entry.key();
            let delta = entry.value().swap(0, Ordering::Relaxed);
            let rate = rounding_div(delta, seconds);
            published_rate
                .entry(code)
                .or_insert_with(|| AtomicU64::new(0))
                .store(rate, Ordering::Relaxed);
            published_count
                .entry(code)
                .or_insert_with(|| AtomicU64::new(0))
                .store(delta, Ordering::Relaxed);
        }

        self.status_window_rotated_at
            .store(unix_seconds(), Ordering::Relaxed);
    }
}

pub struct ReqwestBackendRequestGuard {
    metrics: &'static RuntimeMetrics,
}

impl Drop for ReqwestBackendRequestGuard {
    fn drop(&mut self) {
        self.metrics
            .reqwest_active_backend_requests
            .fetch_sub(1, Ordering::Relaxed);
    }
}

fn increment_status_map(map: &DashMap<u16, CachePadded<AtomicU64>>, status: u16) {
    if let Some(counter) = map.get(&status) {
        counter.fetch_add(1, Ordering::Relaxed);
    } else if map.len() < 256 {
        map.entry(status)
            .or_insert_with(|| CachePadded::new(AtomicU64::new(0)))
            .fetch_add(1, Ordering::Relaxed);
    }
}

enum StatusWindow {
    OneMinute(u64),
    FiveMinutes(u64),
}

pub fn start_window_rotator(
    window_1m_seconds: u64,
    window_5m_seconds: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let metrics = global();
    tokio::spawn(async move {
        let window_1m_seconds = window_1m_seconds.max(1);
        let window_5m_seconds = window_5m_seconds.max(1);
        let mut elapsed = 0u64;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                _ = shutdown_rx.changed() => return,
            }

            elapsed = elapsed.saturating_add(1);
            if elapsed.is_multiple_of(window_1m_seconds) {
                metrics.rotate_status_window(StatusWindow::OneMinute(window_1m_seconds));
            }
            if elapsed.is_multiple_of(window_5m_seconds) {
                metrics.rotate_status_window(StatusWindow::FiveMinutes(window_5m_seconds));
            }
        }
    })
}

#[derive(Debug, Serialize)]
pub struct RuntimeSnapshot {
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub mode: String,
    pub ferrum_version: &'static str,
    pub system: SystemSnapshot,
    pub http: HttpSnapshot,
    pub errors: ErrorsSnapshot,
    pub dns: DnsSnapshot,
    pub connections: ConnectionsSnapshot,
    pub logs: LogsSnapshot,
    pub overload: Value,
}

#[derive(Debug, Serialize)]
pub struct HttpSnapshot {
    pub total_requests: u64,
    pub requests_per_second_1s: u64,
    pub requests_per_second_1m: u64,
    pub requests_per_second_5m: u64,
    pub status_codes: StatusCodeSnapshot,
    pub client_disconnects: u64,
}

#[derive(Debug, Serialize)]
pub struct StatusCodeSnapshot {
    pub totals: BTreeMap<String, u64>,
    pub rate_1s: BTreeMap<String, u64>,
    pub rate_1m: BTreeMap<String, u64>,
    pub rate_5m: BTreeMap<String, u64>,
    pub percent_total: BTreeMap<String, f64>,
    pub percent_1m: BTreeMap<String, f64>,
    pub percent_5m: BTreeMap<String, f64>,
}

#[derive(Debug, Serialize)]
pub struct ErrorsSnapshot {
    pub by_class: BTreeMap<&'static str, ErrorClassCounts>,
    pub by_proxy: BTreeMap<String, BTreeMap<&'static str, u64>>,
}

#[derive(Debug, Default, Serialize)]
pub struct ErrorClassCounts {
    pub http: u64,
    pub grpc: u64,
    pub stream: u64,
    pub body: u64,
}

#[derive(Debug, Serialize)]
pub struct DnsSnapshot {
    pub lookups_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub stale_serves: u64,
    pub errors: u64,
    pub hit_ratio: f64,
    pub error_ratio: f64,
    pub cache_entries: usize,
}

#[derive(Debug, Serialize)]
pub struct ConnectionsSnapshot {
    pub active: u64,
    pub active_requests: u64,
    pub pool_handshakes_total: BTreeMap<&'static str, u64>,
    pub pool_evictions_total: BTreeMap<&'static str, u64>,
    pub pool_failures_total: BTreeMap<&'static str, u64>,
    pub tcp_rst_observed: TcpRstSnapshot,
}

#[derive(Debug, Serialize)]
pub struct TcpRstSnapshot {
    pub by_proxy: BTreeMap<String, BTreeMap<&'static str, u64>>,
    pub total: u64,
}

#[derive(Debug, Serialize)]
pub struct LogsSnapshot {
    pub by_level: BTreeMap<&'static str, u64>,
    pub by_category: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    pub sinks: crate::logging::LoggingSnapshot,
    pub kafka_logging: Vec<crate::plugins::kafka_logging::KafkaSinkSnapshot>,
}

pub fn build_snapshot(
    mode: &str,
    proxy_state: Option<&crate::proxy::ProxyState>,
) -> RuntimeSnapshot {
    let metrics = global();
    RuntimeSnapshot {
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        uptime_seconds: metrics.started_at.elapsed().as_secs(),
        mode: mode.to_string(),
        ferrum_version: crate::FERRUM_VERSION,
        system: (**metrics.system.load()).clone(),
        http: build_http_snapshot(&metrics, proxy_state),
        errors: build_errors_snapshot(&metrics),
        dns: build_dns_snapshot(&metrics, proxy_state),
        connections: build_connections_snapshot(&metrics, proxy_state),
        logs: build_logs_snapshot(&metrics),
        overload: build_overload_snapshot(proxy_state),
    }
}

fn build_http_snapshot(
    metrics: &RuntimeMetrics,
    proxy_state: Option<&crate::proxy::ProxyState>,
) -> HttpSnapshot {
    let total_requests = proxy_state
        .map(|ps| ps.request_count.load(Ordering::Relaxed))
        .unwrap_or(0);
    let requests_per_second_1s = proxy_state
        .map(|ps| {
            ps.windowed_metrics
                .requests_per_second
                .load(Ordering::Relaxed)
        })
        .unwrap_or(0);

    let totals = proxy_state
        .map(|ps| status_map_from_dashmap(&ps.status_counts))
        .unwrap_or_default();
    let rate_1s = proxy_state
        .map(|ps| status_map_from_dashmap(&ps.windowed_metrics.status_codes_per_second))
        .unwrap_or_default();
    let rate_1m = status_map_from_dashmap(&metrics.status_window_1m);
    let rate_5m = status_map_from_dashmap(&metrics.status_window_5m);
    let count_1m = status_map_from_dashmap(&metrics.status_count_window_1m);
    let count_5m = status_map_from_dashmap(&metrics.status_count_window_5m);

    let percent_total = percent_map(&totals, total_requests);
    let requests_1m = metrics.requests_window_1m.load(Ordering::Relaxed);
    let requests_5m = metrics.requests_window_5m.load(Ordering::Relaxed);
    let request_count_1m = metrics.requests_count_window_1m.load(Ordering::Relaxed);
    let request_count_5m = metrics.requests_count_window_5m.load(Ordering::Relaxed);
    let percent_1m = percent_map(&count_1m, request_count_1m);
    let percent_5m = percent_map(&count_5m, request_count_5m);

    HttpSnapshot {
        total_requests,
        requests_per_second_1s,
        requests_per_second_1m: requests_1m,
        requests_per_second_5m: requests_5m,
        status_codes: StatusCodeSnapshot {
            totals,
            rate_1s,
            rate_1m,
            rate_5m,
            percent_total,
            percent_1m,
            percent_5m,
        },
        client_disconnects: metrics.client_disconnects.load(Ordering::Relaxed),
    }
}

fn status_map_from_dashmap(map: &DashMap<u16, AtomicU64>) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for entry in map.iter() {
        out.insert(
            entry.key().to_string(),
            entry.value().load(Ordering::Relaxed),
        );
    }
    out
}

fn percent_map(values: &BTreeMap<String, u64>, total: u64) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    if total == 0 {
        return out;
    }
    for (code, count) in values {
        out.insert(
            code.clone(),
            ((*count as f64 / total as f64) * 10_000.0).round() / 100.0,
        );
    }
    out
}

fn build_errors_snapshot(metrics: &RuntimeMetrics) -> ErrorsSnapshot {
    let mut by_class: BTreeMap<&'static str, ErrorClassCounts> = ERROR_CLASSES
        .iter()
        .copied()
        .map(|class| (class, ErrorClassCounts::default()))
        .collect();
    let mut by_proxy: BTreeMap<String, BTreeMap<&'static str, u64>> = BTreeMap::new();

    fold_error_map(
        &metrics.http_errors_by_class,
        |counts| &mut counts.http,
        &mut by_class,
        &mut by_proxy,
    );
    fold_error_map(
        &metrics.grpc_errors_by_class,
        |counts| &mut counts.grpc,
        &mut by_class,
        &mut by_proxy,
    );
    fold_error_map(
        &metrics.stream_errors_by_class,
        |counts| &mut counts.stream,
        &mut by_class,
        &mut by_proxy,
    );
    fold_error_map(
        &metrics.body_errors_by_class,
        |counts| &mut counts.body,
        &mut by_class,
        &mut by_proxy,
    );

    ErrorsSnapshot { by_class, by_proxy }
}

fn fold_error_map(
    map: &ErrorCounterMap,
    slot: impl Fn(&mut ErrorClassCounts) -> &mut u64,
    by_class: &mut BTreeMap<&'static str, ErrorClassCounts>,
    by_proxy: &mut BTreeMap<String, BTreeMap<&'static str, u64>>,
) {
    for class_entry in map.iter() {
        let class = *class_entry.key();
        for proxy_entry in class_entry.value().iter() {
            let count = proxy_entry.value().load(Ordering::Relaxed);
            let counts = by_class.entry(class).or_default();
            let field = slot(counts);
            *field = field.saturating_add(count);
            by_proxy
                .entry(proxy_entry.key().to_string())
                .or_default()
                .entry(class)
                .and_modify(|value| *value = value.saturating_add(count))
                .or_insert(count);
        }
    }
}

// Covers the shared DnsCache only; the mesh DNS proxy (dns_proxy.rs) resolves
// from its own DnsResolutionTable and upstream forwarder — those lookups are
// not counted here.
fn build_dns_snapshot(
    metrics: &RuntimeMetrics,
    proxy_state: Option<&crate::proxy::ProxyState>,
) -> DnsSnapshot {
    let lookups_total = metrics.dns_lookups_total.load(Ordering::Relaxed);
    let cache_hits = metrics.dns_cache_hits.load(Ordering::Relaxed);
    let cache_misses = metrics.dns_cache_misses.load(Ordering::Relaxed);
    let stale_serves = metrics.dns_stale_serves.load(Ordering::Relaxed);
    let errors = metrics.dns_lookup_errors.load(Ordering::Relaxed);
    DnsSnapshot {
        lookups_total,
        cache_hits,
        cache_misses,
        stale_serves,
        errors,
        hit_ratio: ratio(cache_hits, lookups_total),
        error_ratio: ratio(errors, lookups_total),
        cache_entries: proxy_state.map(|ps| ps.dns_cache.cache_len()).unwrap_or(0),
    }
}

fn build_connections_snapshot(
    metrics: &RuntimeMetrics,
    proxy_state: Option<&crate::proxy::ProxyState>,
) -> ConnectionsSnapshot {
    let (active, active_requests) = proxy_state
        .map(|ps| {
            (
                ps.overload.active_connections.load(Ordering::Relaxed),
                ps.overload.active_requests.load(Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0));

    ConnectionsSnapshot {
        active,
        active_requests,
        pool_handshakes_total: pool_map(&metrics.pool_handshakes_total),
        pool_evictions_total: pool_map(&metrics.pool_evictions_total),
        pool_failures_total: pool_map(&metrics.pool_failures_total),
        tcp_rst_observed: tcp_rst_snapshot(metrics),
    }
}

fn pool_map(map: &DashMap<PoolKind, CachePadded<AtomicU64>>) -> BTreeMap<&'static str, u64> {
    let mut out = BTreeMap::new();
    for entry in map.iter() {
        out.insert(entry.key().as_str(), entry.value().load(Ordering::Relaxed));
    }
    out
}

fn tcp_rst_snapshot(metrics: &RuntimeMetrics) -> TcpRstSnapshot {
    let mut by_proxy: BTreeMap<String, BTreeMap<&'static str, u64>> = BTreeMap::new();
    let mut total = 0u64;
    for entry in metrics.tcp_rst_observed.iter() {
        let count = entry.value().load(Ordering::Relaxed);
        total = total.saturating_add(count);
        by_proxy
            .entry(entry.key().proxy_id.to_string())
            .or_default()
            .entry(entry.key().direction)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }
    TcpRstSnapshot { by_proxy, total }
}

fn build_logs_snapshot(metrics: &RuntimeMetrics) -> LogsSnapshot {
    let mut by_level = BTreeMap::new();
    for level in LOG_LEVELS {
        by_level.insert(
            level.as_str(),
            metrics.log_counts[level.index()].load(Ordering::Relaxed),
        );
    }

    let mut by_category: BTreeMap<&'static str, BTreeMap<&'static str, u64>> = BTreeMap::new();
    for entry in metrics.log_counts_by_category.iter() {
        let ((level, category), counter) = entry.pair();
        by_category
            .entry(level.as_str())
            .or_default()
            .insert(*category, counter.load(Ordering::Relaxed));
    }

    LogsSnapshot {
        by_level,
        by_category,
        sinks: crate::logging::snapshot(),
        kafka_logging: crate::plugins::kafka_logging::snapshots(),
    }
}

fn build_overload_snapshot(proxy_state: Option<&crate::proxy::ProxyState>) -> Value {
    let overload = proxy_state
        .map(|ps| ps.overload.snapshot())
        .unwrap_or_else(|| crate::overload::OverloadState::new().snapshot());
    let stream_listeners = proxy_state.map_or_else(
        || {
            json!({
                "dtls_demux_sessions_total": 0,
                "dtls_demux_sessions": [],
                "bind_failures_total": 0,
                "bind_failures": []
            })
        },
        |ps| {
            serde_json::to_value(ps.stream_listener_manager.overload_snapshot())
                .unwrap_or_else(|_| json!({}))
        },
    );

    let mut value = serde_json::to_value(overload).unwrap_or_else(|_| json!({}));
    if let Some(obj) = value.as_object_mut() {
        obj.insert("stream_listeners".to_string(), stream_listeners);
    }
    value
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn rounding_div(numerator: u64, denominator: u64) -> u64 {
    (numerator + denominator / 2) / denominator
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_grpc_summary(summary: &TransactionSummary) -> bool {
    summary
        .metadata
        .get("request_protocol")
        .or_else(|| summary.metadata.get("mesh.request_protocol"))
        .is_some_and(|value| value == "grpc" || value == "grpc-web")
        || summary.metadata.contains_key("grpc_status")
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToBackend => "client_to_backend",
        Direction::BackendToClient => "backend_to_client",
        Direction::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::ErrorClass;

    #[test]
    fn counters_increment_by_class_and_proxy() {
        let metrics = RuntimeMetrics::new();
        let summary = TransactionSummary {
            proxy_id: Some("proxy-a".to_string()),
            response_status_code: 502,
            error_class: Some(ErrorClass::ConnectionTimeout),
            ..TransactionSummary::default()
        };

        metrics.record_transaction(&summary);
        let snapshot = build_errors_snapshot(&metrics);

        assert_eq!(
            snapshot.by_class.get("connection_timeout").map(|c| c.http),
            Some(1)
        );
        assert_eq!(
            snapshot
                .by_proxy
                .get("proxy-a")
                .and_then(|classes| classes.get("connection_timeout"))
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn error_entry_count_bumps_once_per_unique_pair() {
        let metrics = RuntimeMetrics::new();

        metrics.record_http_error(Some("proxy-a"), ErrorClass::ConnectionTimeout);
        metrics.record_http_error(Some("proxy-a"), ErrorClass::ConnectionTimeout);
        metrics.record_http_error(Some("proxy-a"), ErrorClass::ConnectionTimeout);
        // Second class for the same proxy adds one entry.
        metrics.record_http_error(Some("proxy-a"), ErrorClass::TlsError);
        // Same class on a different proxy adds one entry.
        metrics.record_http_error(Some("proxy-b"), ErrorClass::ConnectionTimeout);

        assert_eq!(metrics.error_entry_count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn error_entry_count_respects_configured_cap() {
        let metrics = RuntimeMetrics::new();
        metrics.configure(2, true, true, 1000);

        metrics.record_http_error(Some("proxy-a"), ErrorClass::ConnectionTimeout);
        metrics.record_http_error(Some("proxy-b"), ErrorClass::ConnectionTimeout);
        metrics.record_http_error(Some("proxy-c"), ErrorClass::ConnectionTimeout);

        assert_eq!(metrics.error_entry_count.load(Ordering::Relaxed), 2);
        let snapshot = build_errors_snapshot(&metrics);
        assert_eq!(
            snapshot
                .by_proxy
                .get("proxy-c")
                .and_then(|classes| classes.get("connection_timeout"))
                .copied(),
            None
        );
    }

    #[test]
    fn status_window_rotation_publishes_rates() {
        let metrics = RuntimeMetrics::new();
        for _ in 0..120 {
            metrics.record_http_status(200);
        }

        metrics.rotate_status_window(StatusWindow::OneMinute(60));

        assert_eq!(metrics.requests_window_1m.load(Ordering::Relaxed), 2);
        assert_eq!(
            metrics
                .status_window_1m
                .get(&200)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(2)
        );
        assert_eq!(
            metrics.requests_count_window_1m.load(Ordering::Relaxed),
            120
        );
        assert_eq!(
            metrics
                .status_count_window_1m
                .get(&200)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(120)
        );
    }

    #[test]
    fn status_window_rotation_rounds_instead_of_truncating() {
        let metrics = RuntimeMetrics::new();
        // 59 requests in 60 seconds: truncation gives 0, rounding gives 1.
        for _ in 0..59 {
            metrics.record_http_status(200);
        }

        metrics.rotate_status_window(StatusWindow::OneMinute(60));

        assert_eq!(metrics.requests_window_1m.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .status_window_1m
                .get(&200)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(1)
        );
        assert_eq!(metrics.requests_count_window_1m.load(Ordering::Relaxed), 59);
        assert_eq!(
            metrics
                .status_count_window_1m
                .get(&200)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(59)
        );
    }

    #[test]
    fn status_window_percentages_use_counts_not_rounded_rates() {
        let metrics = RuntimeMetrics::new();
        for _ in 0..30 {
            metrics.record_http_status(200);
            metrics.record_http_status(500);
        }

        metrics.rotate_status_window(StatusWindow::OneMinute(60));
        let snapshot = build_http_snapshot(&metrics, None);

        assert_eq!(snapshot.requests_per_second_1m, 1);
        assert_eq!(snapshot.status_codes.rate_1m.get("200"), Some(&1));
        assert_eq!(snapshot.status_codes.rate_1m.get("500"), Some(&1));
        assert_eq!(snapshot.status_codes.percent_1m.get("200"), Some(&50.0));
        assert_eq!(snapshot.status_codes.percent_1m.get("500"), Some(&50.0));
    }

    #[test]
    fn dns_ratios_handle_zero_denominator() {
        let metrics = RuntimeMetrics::new();
        let dns = build_dns_snapshot(&metrics, None);
        assert_eq!(dns.hit_ratio, 0.0);
        assert_eq!(dns.error_ratio, 0.0);

        metrics.record_dns_hit();
        metrics.record_dns_error();
        let dns = build_dns_snapshot(&metrics, None);
        assert_eq!(dns.lookups_total, 2);
        assert_eq!(dns.hit_ratio, 0.5);
        assert_eq!(dns.error_ratio, 0.5);
    }

    #[test]
    fn grpc_status_metadata_classifies_error_as_grpc() {
        let metrics = RuntimeMetrics::new();
        let mut summary = TransactionSummary {
            proxy_id: Some("grpc-a".to_string()),
            response_status_code: 200,
            error_class: Some(ErrorClass::ReadWriteTimeout),
            ..TransactionSummary::default()
        };
        summary
            .metadata
            .insert("grpc_status".to_string(), "14".to_string());

        metrics.record_transaction(&summary);
        let snapshot = build_errors_snapshot(&metrics);

        assert_eq!(
            snapshot
                .by_class
                .get("read_write_timeout")
                .map(|counts| (counts.http, counts.grpc)),
            Some((0, 1))
        );
    }

    #[test]
    fn request_protocol_metadata_classifies_error_as_grpc() {
        let metrics = RuntimeMetrics::new();
        let mut summary = TransactionSummary {
            proxy_id: Some("grpc-a".to_string()),
            response_status_code: 200,
            error_class: Some(ErrorClass::RequestBodyTooLarge),
            ..TransactionSummary::default()
        };
        summary
            .metadata
            .insert("request_protocol".to_string(), "grpc".to_string());

        metrics.record_transaction(&summary);
        let snapshot = build_errors_snapshot(&metrics);

        assert_eq!(
            snapshot
                .by_class
                .get("request_body_too_large")
                .map(|counts| (counts.http, counts.grpc)),
            Some((0, 1))
        );
    }

    #[test]
    fn status_tracking_can_be_disabled() {
        let metrics = RuntimeMetrics::new();
        metrics.configure(200, true, false, 1000);

        metrics.record_http_status(200);
        metrics.rotate_status_window(StatusWindow::OneMinute(60));

        assert_eq!(metrics.requests_window_1m.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.requests_count_window_1m.load(Ordering::Relaxed), 0);
        assert!(metrics.status_window_1m.is_empty());
        assert!(metrics.status_count_window_1m.is_empty());
    }

    #[test]
    fn status_window_rotation_clamps_zero_second_windows() {
        let metrics = RuntimeMetrics::new();

        metrics.record_http_status(200);
        metrics.rotate_status_window(StatusWindow::OneMinute(0));

        assert_eq!(metrics.requests_window_1m.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .status_window_1m
                .get(&200)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(1)
        );
        assert_eq!(metrics.requests_count_window_1m.load(Ordering::Relaxed), 1);

        metrics.record_http_status(500);
        metrics.rotate_status_window(StatusWindow::FiveMinutes(0));

        assert_eq!(metrics.requests_window_5m.load(Ordering::Relaxed), 2);
        assert_eq!(
            metrics
                .status_window_5m
                .get(&200)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(1)
        );
        assert_eq!(
            metrics
                .status_window_5m
                .get(&500)
                .map(|v| v.load(Ordering::Relaxed)),
            Some(1)
        );
        assert_eq!(metrics.requests_count_window_5m.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn configure_clamps_zero_error_entry_cap_to_one() {
        let metrics = RuntimeMetrics::new();
        metrics.configure(0, true, true, 1000);

        metrics.record_http_error(Some("proxy-a"), ErrorClass::ConnectionTimeout);
        metrics.record_http_error(Some("proxy-b"), ErrorClass::TlsError);

        let snapshot = build_errors_snapshot(&metrics);
        assert_eq!(metrics.error_entry_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            snapshot
                .by_proxy
                .get("proxy-a")
                .and_then(|classes| classes.get("connection_timeout"))
                .copied(),
            Some(1)
        );
        assert!(
            !snapshot.by_proxy.contains_key("proxy-b"),
            "second distinct error entry should be dropped once the clamped cap is full"
        );
    }

    #[test]
    fn pool_tracking_can_be_disabled_and_zero_eviction_batches_are_ignored() {
        let metrics = RuntimeMetrics::new();
        metrics.configure(200, false, true, 1234);

        metrics.record_pool_handshake(PoolKind::HttpReqwest);
        metrics.record_pool_failure(PoolKind::Http3);
        metrics.record_pool_eviction(PoolKind::Grpc);
        metrics.record_pool_evictions(PoolKind::Hbone, 4);

        let connections = build_connections_snapshot(&metrics, None);
        assert!(connections.pool_handshakes_total.is_empty());
        assert!(connections.pool_failures_total.is_empty());
        assert!(connections.pool_evictions_total.is_empty());
        assert_eq!(metrics.cache_ttl_ms(), 1234);

        metrics.configure(200, true, true, 1234);
        metrics.record_pool_evictions(PoolKind::Grpc, 0);
        assert!(
            build_connections_snapshot(&metrics, None)
                .pool_evictions_total
                .is_empty()
        );

        metrics.record_pool_evictions(PoolKind::Grpc, 3);
        let connections = build_connections_snapshot(&metrics, None);
        assert_eq!(connections.pool_evictions_total.get("grpc"), Some(&3));
    }

    #[test]
    fn tcp_rst_counts_by_proxy_and_direction_and_respects_cap() {
        let metrics = RuntimeMetrics::new();
        metrics.configure(2, true, true, 1000);

        metrics.record_tcp_rst("proxy-a", Direction::ClientToBackend);
        metrics.record_tcp_rst("proxy-a", Direction::ClientToBackend);
        metrics.record_tcp_rst("proxy-a", Direction::BackendToClient);
        metrics.record_tcp_rst("proxy-b", Direction::Unknown);

        let snapshot = tcp_rst_snapshot(&metrics);
        assert_eq!(snapshot.total, 3);
        assert_eq!(
            snapshot
                .by_proxy
                .get("proxy-a")
                .and_then(|directions| directions.get("client_to_backend"))
                .copied(),
            Some(2)
        );
        assert_eq!(
            snapshot
                .by_proxy
                .get("proxy-a")
                .and_then(|directions| directions.get("backend_to_client"))
                .copied(),
            Some(1)
        );
        assert!(
            !snapshot.by_proxy.contains_key("proxy-b"),
            "new RST keys should be dropped once the configured cap is full"
        );
    }

    #[test]
    fn transaction_body_errors_without_proxy_use_unknown_bucket() {
        let metrics = RuntimeMetrics::new();
        metrics.record_transaction(&TransactionSummary {
            body_error_class: Some(ErrorClass::ResponseBodyTooLarge),
            ..TransactionSummary::default()
        });

        let snapshot = build_errors_snapshot(&metrics);
        assert_eq!(
            snapshot
                .by_class
                .get("response_body_too_large")
                .map(|counts| counts.body),
            Some(1)
        );
        assert_eq!(
            snapshot
                .by_proxy
                .get("unknown")
                .and_then(|classes| classes.get("response_body_too_large"))
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn mesh_grpc_web_metadata_classifies_error_as_grpc() {
        let metrics = RuntimeMetrics::new();
        let mut summary = TransactionSummary {
            proxy_id: Some("mesh-grpc-web".to_string()),
            error_class: Some(ErrorClass::ProtocolError),
            ..TransactionSummary::default()
        };
        summary
            .metadata
            .insert("mesh.request_protocol".to_string(), "grpc-web".to_string());

        metrics.record_transaction(&summary);
        let snapshot = build_errors_snapshot(&metrics);

        assert_eq!(
            snapshot
                .by_class
                .get("protocol_error")
                .map(|counts| (counts.http, counts.grpc)),
            Some((0, 1))
        );
    }

    #[test]
    fn stream_transaction_without_error_is_noop() {
        let metrics = RuntimeMetrics::new();
        let summary = StreamTransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: "tcp-a".to_string(),
            proxy_lifecycle_generation: None,
            proxy_name: None,
            client_ip: "127.0.0.1".to_string(),
            consumer_username: None,
            auth_method: None,
            backend_target: "tcp://127.0.0.1:9001".to_string(),
            backend_resolved_ip: None,
            protocol: "tcp".to_string(),
            listen_port: 9000,
            duration_ms: 1.0,
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: None,
            timestamp_connected: "2026-05-14T00:00:00Z".to_string(),
            timestamp_disconnected: "2026-05-14T00:00:01Z".to_string(),
            sni_hostname: None,
            metadata: Default::default(),
        };

        metrics.record_stream_transaction(&summary);

        assert!(build_errors_snapshot(&metrics).by_proxy.is_empty());
        assert!(metrics.stream_errors_by_class.is_empty());
    }

    #[test]
    fn reqwest_backend_request_guard_decrements_on_drop() {
        let metrics: &'static RuntimeMetrics = Box::leak(Box::new(RuntimeMetrics::new()));

        assert_eq!(metrics.reqwest_active_backend_requests(), 0);
        let guard = metrics.reqwest_backend_request_guard();
        assert_eq!(metrics.reqwest_active_backend_requests(), 1);
        drop(guard);
        assert_eq!(metrics.reqwest_active_backend_requests(), 0);
    }

    #[test]
    fn direct_http_error_recording_covers_no_plugin_path() {
        let metrics = RuntimeMetrics::new();

        metrics.record_http_error(Some("proxy-a"), ErrorClass::ClientDisconnect);

        assert_eq!(metrics.client_disconnects.load(Ordering::Relaxed), 1);
        let snapshot = build_errors_snapshot(&metrics);
        assert_eq!(
            snapshot
                .by_proxy
                .get("proxy-a")
                .and_then(|classes| classes.get("client_disconnect"))
                .copied(),
            Some(1)
        );
        assert_eq!(
            snapshot
                .by_class
                .get("client_disconnect")
                .map(|counts| counts.http),
            Some(1)
        );
    }

    #[test]
    fn error_snapshot_prepopulates_every_error_class() {
        let metrics = RuntimeMetrics::new();
        let snapshot = build_errors_snapshot(&metrics);
        let expected = [
            ErrorClass::ConnectionTimeout,
            ErrorClass::ConnectionRefused,
            ErrorClass::ConnectionReset,
            ErrorClass::ConnectionClosed,
            ErrorClass::DnsLookupError,
            ErrorClass::TlsError,
            ErrorClass::ReadWriteTimeout,
            ErrorClass::ClientDisconnect,
            ErrorClass::ProtocolError,
            ErrorClass::ResponseBodyTooLarge,
            ErrorClass::GatewayBufferCapacity,
            ErrorClass::RequestBodyTooLarge,
            ErrorClass::ConnectionPoolError,
            ErrorClass::PortExhaustion,
            ErrorClass::GracefulRemoteClose,
            ErrorClass::DispatchPolicyRejected,
            ErrorClass::RequestError,
        ];

        assert_eq!(snapshot.by_class.len(), expected.len());
        for class in expected {
            let counts = snapshot
                .by_class
                .get(class.as_str())
                .unwrap_or_else(|| panic!("missing zero-count slot for {class}"));
            assert_eq!(counts.http, 0);
            assert_eq!(counts.grpc, 0);
            assert_eq!(counts.stream, 0);
            assert_eq!(counts.body, 0);
        }
    }
}
