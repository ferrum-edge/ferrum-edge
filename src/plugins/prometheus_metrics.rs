//! Prometheus Metrics Plugin
//!
//! Records request metrics in Prometheus format. The actual `/metrics`
//! endpoint is served by the authenticated admin observability API.
//! This plugin uses the `log()` hook to record metrics from TransactionSummary.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::mesh::prometheus_helpers::{self, MeshRequestKey};
use super::{
    AI_COST_SUBMICRO_SCALE, AiCost, Direction, Plugin, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext,
};
use crate::ebpf::NodeAgentMetrics;
use crate::retry::ErrorClass;

/// Global metrics registry (singleton per process).
static METRICS_REGISTRY: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();

pub fn global_registry() -> Arc<MetricsRegistry> {
    METRICS_REGISTRY
        .get_or_init(|| Arc::new(MetricsRegistry::new()))
        .clone()
}

pub(crate) fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Composite key for request counter: (proxy_id, method, status_code, grpc_status).
///
/// `method` and `grpc_status` are normalized to bounded static label sets before
/// insertion. Request-controlled extension methods and malformed gRPC status
/// values can therefore never create unbounded registry keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterKey {
    pub proxy_id: Arc<str>,
    pub method: &'static str,
    pub status_code: u16,
    pub grpc_status: Option<&'static str>,
}

/// Bounded AI usage key. Provider is normalized to one of the compiled-in
/// provider labels; raw model names and arbitrary metadata never become labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AiUsageKey {
    pub proxy_id: Arc<str>,
    pub provider: &'static str,
}

fn ai_provider_label(value: &str) -> Option<&'static str> {
    match value {
        "openai" | "azure_openai" | "xai" | "deepseek" | "meta_llama" | "hugging_face" => {
            Some("openai")
        }
        "anthropic" => Some("anthropic"),
        "google" | "google_gemini" | "google_vertex" => Some("google"),
        "cohere" => Some("cohere"),
        "mistral" => Some("mistral"),
        "bedrock" | "aws_bedrock" => Some("bedrock"),
        _ => None,
    }
}

/// Composite key for stream connection counter: (proxy_id, protocol).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamCounterKey {
    pub proxy_id: Arc<str>,
    pub protocol: Arc<str>,
}

/// Bounded WebSocket terminal-series key.
///
/// Every non-proxy label is derived from a compiled-in enum; no error message,
/// close reason, URL, or other peer-controlled string is retained.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WsSessionKey {
    pub proxy_id: Arc<str>,
    pub result: &'static str,
    pub direction: &'static str,
    pub io_side: &'static str,
    pub error_class: &'static str,
}

/// Bounded directional WebSocket traffic key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WsTrafficKey {
    pub proxy_id: Arc<str>,
    pub direction: &'static str,
}

/// Composite key for the HTTP-family client-disconnect counter.
///
/// Populated whenever a `TransactionSummary` is logged with
/// `client_disconnected == true`. A forthcoming deferred-log path will make
/// this field meaningful for HTTP/1.1, HTTP/2, HTTP/3, gRPC, and WebSocket
/// flows; until then the counter will only fire for protocols that already
/// populate the field (none, at time of introduction), but we wire it now so
/// that dashboards reading `ferrum_client_disconnects_total` work the moment
/// the plumbing lands — no registry change needed at that time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientDisconnectKey {
    pub proxy_id: Arc<str>,
}

/// Composite key for the stream (TCP/UDP) disconnect counter.
///
/// `cause` is the snake_case `DisconnectCause` variant (or `"unknown"` when
/// `None`). `direction` is the snake_case `Direction` variant (or
/// `"unknown"` when `None`). Both are bounded-cardinality enums so they are
/// safe as Prometheus labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamDisconnectKey {
    pub proxy_id: Arc<str>,
    pub protocol: Arc<str>,
    pub cause: &'static str,
    pub direction: &'static str,
}

/// Composite key for HBONE tunnel relay failures.
///
/// HBONE CONNECT responds with `200 OK` before the tunneled TCP relay runs,
/// so post-upgrade copy failures need a side-channel metric instead of an
/// HTTP status code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HboneRelayFailureKey {
    pub proxy_id: Arc<str>,
    pub direction: &'static str,
    pub error_class: &'static str,
}

/// Composite key for raw-TCP mesh egress relay connections, labelled by the
/// transport that carried them (`hbone` for Ambient, `mtls` for Sidecar) and
/// the relay outcome. Bounded cardinality: both labels are compiled-in
/// constants, never attacker-controllable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeshTcpEgressConnKey {
    pub transport: &'static str,
    pub result: &'static str,
}

/// TLS certificate inventory gauge key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsCertGaugeKey {
    pub cert_id: Arc<str>,
    pub surface: Arc<str>,
    pub source_kind: Arc<str>,
}

/// TLS source refresh counter key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsSourceRefreshKey {
    pub scheme: Arc<str>,
    pub kind: Arc<str>,
    pub surface: Arc<str>,
    pub outcome: Arc<str>,
}

/// TLS source fetch duration key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsSourceFetchKey {
    pub scheme: Arc<str>,
    pub kind: Arc<str>,
}

/// TLS source fetch failure counter key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsSourceFetchFailureKey {
    pub scheme: Arc<str>,
    pub kind: Arc<str>,
    pub reason: Arc<str>,
}

/// TLS certificate rotation counter key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsCertRotationKey {
    pub cert_id: Arc<str>,
    pub reason: Arc<str>,
    pub outcome: Arc<str>,
}

/// Scrape-time certificate inventory gauge values.
pub struct TlsCertGaugeValues {
    pub not_after_unix_seconds: CachePadded<AtomicI64>,
    pub not_before_unix_seconds: CachePadded<AtomicI64>,
}

impl TlsCertGaugeValues {
    fn new(not_after_unix_seconds: i64, not_before_unix_seconds: i64) -> Self {
        Self {
            not_after_unix_seconds: CachePadded::new(AtomicI64::new(not_after_unix_seconds)),
            not_before_unix_seconds: CachePadded::new(AtomicI64::new(not_before_unix_seconds)),
        }
    }

    /// Update absolute certificate timestamps and report whether the inventory
    /// materially changed. Relative expiry is derived only during an uncached
    /// render so the passage of one wall-clock second cannot defeat the render
    /// cache on every scrape.
    fn update(&self, not_after_unix_seconds: i64, not_before_unix_seconds: i64) -> bool {
        let old_not_after = self
            .not_after_unix_seconds
            .swap(not_after_unix_seconds, Ordering::Relaxed);
        let old_not_before = self
            .not_before_unix_seconds
            .swap(not_before_unix_seconds, Ordering::Relaxed);
        old_not_after != not_after_unix_seconds || old_not_before != not_before_unix_seconds
    }
}

/// Mesh outbound registry admit/deny counters for one namespace/host pair.
pub struct MeshOutboundRegistryDecisionCounters {
    pub admit: TimestampedCounter,
    pub deny: TimestampedCounter,
}

impl MeshOutboundRegistryDecisionCounters {
    fn new(epoch: Instant) -> Self {
        Self {
            admit: TimestampedCounter::new(epoch),
            deny: TimestampedCounter::new(epoch),
        }
    }

    fn increment(&self, decision: &'static str, epoch: Instant) {
        match decision {
            "admit" => self.admit.increment(epoch),
            "deny" => self.deny.increment(epoch),
            _ => {}
        }
    }
}

/// Map a `DisconnectCause` variant to its snake_case label, reusing static
/// strings so hot-path label values cost nothing to copy.
fn disconnect_cause_label(cause: Option<super::DisconnectCause>) -> &'static str {
    match cause {
        Some(super::DisconnectCause::IdleTimeout) => "idle_timeout",
        Some(super::DisconnectCause::RecvError) => "recv_error",
        Some(super::DisconnectCause::BackendError) => "backend_error",
        Some(super::DisconnectCause::GracefulShutdown) => "graceful_shutdown",
        None => "unknown",
    }
}

/// Map a `Direction` variant to its snake_case label (static strings).
fn direction_label(direction: Option<super::Direction>) -> &'static str {
    match direction {
        Some(super::Direction::ClientToBackend) => "client_to_backend",
        Some(super::Direction::BackendToClient) => "backend_to_client",
        Some(super::Direction::Unknown) => "unknown",
        None => "unknown",
    }
}

fn ws_io_side_label(side: Option<crate::proxy::tcp_proxy::StreamIoSide>) -> &'static str {
    match side {
        Some(crate::proxy::tcp_proxy::StreamIoSide::Read) => "read",
        Some(crate::proxy::tcp_proxy::StreamIoSide::Write) => "write",
        None => "unknown",
    }
}

/// Normalize request-controlled HTTP methods to a finite label set. HTTP
/// extension methods remain routable, but all share the `OTHER` metrics bucket.
fn method_label(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => "OTHER",
    }
}

/// Convert the internal gRPC terminal-status metadata to a bounded Prometheus
/// label. Standard codes retain their numeric representation; malformed or
/// future non-standard codes share one `OTHER` bucket.
fn grpc_status_label(metadata: &std::collections::HashMap<String, String>) -> Option<&'static str> {
    let status = match metadata.get("grpc_status")?.trim().parse::<u32>() {
        Ok(status) => status,
        Err(_) => return Some("OTHER"),
    };
    Some(match status {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        4 => "4",
        5 => "5",
        6 => "6",
        7 => "7",
        8 => "8",
        9 => "9",
        10 => "10",
        11 => "11",
        12 => "12",
        13 => "13",
        14 => "14",
        15 => "15",
        16 => "16",
        _ => "OTHER",
    })
}

/// Atomic counter paired with a last-updated timestamp for stale entry eviction.
pub struct TimestampedCounter {
    pub value: CachePadded<AtomicU64>,
    pub last_updated: CachePadded<AtomicU64>, // Instant encoded as nanos since registry creation
}

impl TimestampedCounter {
    fn new(epoch: Instant) -> Self {
        Self {
            value: CachePadded::new(AtomicU64::new(0)),
            last_updated: CachePadded::new(AtomicU64::new(epoch.elapsed().as_nanos() as u64)),
        }
    }

    fn increment(&self, epoch: Instant) {
        self.add(1, epoch);
    }

    fn add(&self, value: u64, epoch: Instant) {
        self.value.fetch_add(value, Ordering::Relaxed);
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn saturating_add(&self, value: u64, epoch: Instant) {
        let _ = self
            .value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(value))
            });
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// Fixed-point cost counter that retains sub-micro remainders without reducing
/// the supported whole-cost range. Both fields remain bounded atomics on the
/// logging hot path; fractional carry is applied with a lock-free update.
pub struct TimestampedCostCounter {
    pub microunits: CachePadded<AtomicU64>,
    pub submicrounits: CachePadded<AtomicU64>,
    published_microunits: CachePadded<AtomicU64>,
    pub last_updated: CachePadded<AtomicU64>,
}

impl TimestampedCostCounter {
    fn new(epoch: Instant) -> Self {
        Self {
            microunits: CachePadded::new(AtomicU64::new(0)),
            submicrounits: CachePadded::new(AtomicU64::new(0)),
            published_microunits: CachePadded::new(AtomicU64::new(0)),
            last_updated: CachePadded::new(AtomicU64::new(epoch.elapsed().as_nanos() as u64)),
        }
    }

    fn add_microunits(&self, value: u64) {
        let _ = self
            .microunits
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(value))
            });
    }

    fn add(&self, value: &AiCost, epoch: Instant) {
        self.add_microunits(
            value
                .microunits
                .saturating_add(value.submicrounits / AI_COST_SUBMICRO_SCALE),
        );
        let submicrounits = value.submicrounits % AI_COST_SUBMICRO_SCALE;
        if submicrounits != 0 {
            let mut carried = false;
            let _ =
                self.submicrounits
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        let sum = current + submicrounits;
                        carried = sum >= AI_COST_SUBMICRO_SCALE;
                        Some(sum % AI_COST_SUBMICRO_SCALE)
                    });
            if carried {
                self.add_microunits(1);
            }
        }
        // Whole and fractional updates are deliberately split so the full
        // supported whole-cost range remains available. Publish only after
        // both parts have settled, and advance the scrape-facing value with
        // one monotonic atomic so a concurrent carry gap can only delay an
        // increase, never expose a counter decrease.
        let whole = self.microunits.load(Ordering::Relaxed);
        let remainder = self.submicrounits.load(Ordering::Relaxed);
        let rounded = whole.saturating_add(u64::from(remainder >= AI_COST_SUBMICRO_SCALE / 2));
        self.published_microunits
            .fetch_max(rounded, Ordering::Release);
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }

    fn rounded_microunits(&self) -> u64 {
        self.published_microunits.load(Ordering::Acquire)
    }
}

/// Histogram with predefined buckets and a last-updated timestamp.
pub struct HistogramBuckets {
    /// Bucket boundaries in the metric's native unit.
    pub boundaries: Vec<f64>,
    /// Count of observations <= each boundary
    pub counts: Vec<CachePadded<AtomicU64>>,
    /// Sum of all observations
    pub sum: CachePadded<AtomicU64>, // stored as bits of f64
    /// Total count
    pub count: CachePadded<AtomicU64>,
    /// Last-updated timestamp (nanos since registry epoch)
    last_updated: CachePadded<AtomicU64>,
}

impl HistogramBuckets {
    fn new(epoch: Instant) -> Self {
        Self::new_with_boundaries(
            vec![
                5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
            ],
            epoch,
        )
    }

    fn new_seconds(epoch: Instant) -> Self {
        Self::new_with_boundaries(
            vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            ],
            epoch,
        )
    }

    fn new_with_boundaries(boundaries: Vec<f64>, epoch: Instant) -> Self {
        let counts = boundaries
            .iter()
            .map(|_| CachePadded::new(AtomicU64::new(0)))
            .collect();
        Self {
            boundaries,
            counts,
            sum: CachePadded::new(AtomicU64::new(0)),
            count: CachePadded::new(AtomicU64::new(0)),
            last_updated: CachePadded::new(AtomicU64::new(epoch.elapsed().as_nanos() as u64)),
        }
    }

    fn observe(&self, value: f64, epoch: Instant) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
        // Add to sum (using u64 bit representation of f64)
        loop {
            let old = self.sum.load(Ordering::Relaxed);
            let old_f = f64::from_bits(old);
            let new_f = old_f + value;
            match self.sum.compare_exchange_weak(
                old,
                new_f.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        // Increment bucket counters
        for (i, boundary) in self.boundaries.iter().enumerate() {
            if value <= *boundary {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// Default stale entry TTL: 1 hour in nanoseconds.
const DEFAULT_STALE_TTL_NANOS: u64 = 3_600_000_000_000;

/// Default render cache TTL: 5 seconds.
const DEFAULT_RENDER_CACHE_TTL_SECS: u64 = 5;

/// Default minimum cache age (in nanoseconds) before record() will invalidate.
/// At high RPS this prevents an Arc allocation on every single request.
const DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS: u64 = 500_000_000; // 500ms

/// Metrics registry holding all Prometheus-compatible counters and histograms.
pub struct MetricsRegistry {
    /// Monotonic epoch for all timestamp calculations (avoids system clock issues).
    epoch: Instant,
    /// Total requests by (proxy_id, method, status_code)
    pub request_counter: DashMap<CounterKey, TimestampedCounter>,
    /// Request duration histogram buckets by proxy_id
    pub request_duration_buckets: DashMap<Arc<str>, HistogramBuckets>,
    /// Backend duration histogram buckets by proxy_id
    pub backend_duration_buckets: DashMap<Arc<str>, HistogramBuckets>,
    /// Gateway overhead histogram buckets by proxy_id
    pub gateway_overhead_buckets: DashMap<Arc<str>, HistogramBuckets>,
    /// Prompt tokens from one selected ai_token_metrics instance per request.
    pub ai_prompt_tokens_counter: DashMap<AiUsageKey, TimestampedCounter>,
    /// Completion tokens from one selected ai_token_metrics instance per request.
    pub ai_completion_tokens_counter: DashMap<AiUsageKey, TimestampedCounter>,
    /// Total tokens from one selected ai_token_metrics instance per request.
    pub ai_total_tokens_counter: DashMap<AiUsageKey, TimestampedCounter>,
    /// Estimated configured-currency cost with a retained sub-micro remainder.
    pub ai_estimated_cost_counter: DashMap<AiUsageKey, TimestampedCostCounter>,
    /// Mesh request count by Istio/GAMMA RED label set.
    pub mesh_request_counter: DashMap<MeshRequestKey, TimestampedCounter>,
    /// Mesh request duration histogram by the same bounded RED label set.
    pub mesh_request_duration_buckets: DashMap<MeshRequestKey, HistogramBuckets>,
    /// Rate limit exceeded counter
    pub rate_limit_exceeded: AtomicU64,
    /// `request_mirror` detached tasks admitted past concurrency + byte budgets.
    request_mirror_dispatched: AtomicU64,
    /// `request_mirror` tasks that fully drained a response within bounds.
    request_mirror_completed: AtomicU64,
    /// `request_mirror` request-phase deadline expiries.
    request_mirror_request_timeouts: AtomicU64,
    /// `request_mirror` pre-response transport failures.
    request_mirror_request_failures: AtomicU64,
    /// `request_mirror` response-body drain deadline expiries.
    request_mirror_drain_timeouts: AtomicU64,
    /// `request_mirror` response-body drain transport failures.
    request_mirror_drain_failures: AtomicU64,
    /// `request_mirror` responses truncated at `max_response_body_bytes`.
    request_mirror_drain_truncations: AtomicU64,
    /// `request_mirror` tasks dropped before a terminal outcome.
    request_mirror_cancellations: AtomicU64,
    /// `request_mirror` attempts dropped because `max_in_flight` was full.
    request_mirror_concurrency_drops: AtomicU64,
    /// `request_mirror` attempts dropped because the retained-body budget was full.
    request_mirror_budget_drops: AtomicU64,
    /// Current ai_federation circuits in an open/half-open recovery state.
    ai_federation_circuits_open: AtomicI64,
    /// ai_federation closed-to-open transitions.
    ai_federation_circuits_opened: AtomicU64,
    /// ai_federation half-open-to-closed recoveries.
    ai_federation_circuits_closed: AtomicU64,
    /// ai_federation half-open probes admitted.
    ai_federation_circuit_half_open_probes: AtomicU64,
    /// Provider attempts skipped because an ai_federation circuit was open.
    ai_federation_circuit_open_skips: AtomicU64,
    /// Stream connections by (proxy_id, protocol)
    pub stream_connection_counter: DashMap<StreamCounterKey, TimestampedCounter>,
    /// Stream connection duration histogram by proxy_id
    pub stream_duration_buckets: DashMap<Arc<str>, HistogramBuckets>,
    /// Completed WebSocket sessions by bounded terminal classification.
    pub ws_session_counter: DashMap<WsSessionKey, TimestampedCounter>,
    /// WebSocket session duration by the same bounded terminal classification.
    pub ws_session_duration_buckets: DashMap<WsSessionKey, HistogramBuckets>,
    /// WebSocket payload bytes by proxy and direction.
    pub ws_bytes_counter: DashMap<WsTrafficKey, TimestampedCounter>,
    /// WebSocket frames by proxy and direction.
    pub ws_frames_counter: DashMap<WsTrafficKey, TimestampedCounter>,
    /// HTTP-family client disconnect counter keyed by proxy_id. Incremented
    /// on every `record()` where `client_disconnected == true`.
    pub client_disconnect_counter: DashMap<ClientDisconnectKey, TimestampedCounter>,
    /// Stream disconnect counter keyed by (proxy_id, protocol, cause, direction).
    /// Incremented on every `record_stream()` so operators can distinguish
    /// idle timeouts from genuine errors and see which side initiated the
    /// disconnect.
    pub stream_disconnect_counter: DashMap<StreamDisconnectKey, TimestampedCounter>,
    /// Mesh DNS upstream transaction-ID exhaustion events. This is process-wide
    /// because the transparent mesh DNS proxy uses one shared upstream socket.
    pub mesh_dns_upstream_id_exhaustions: AtomicU64,
    /// HBONE tunnel relay failures keyed by (proxy_id, direction, error_class).
    /// Incremented when the background CONNECT relay observes a copy failure
    /// after the client already received `200 OK`.
    pub hbone_relay_failure_counter: DashMap<HboneRelayFailureKey, TimestampedCounter>,
    /// Raw-TCP mesh egress relay connections keyed by (transport, result).
    /// Incremented once per captured raw-TCP connection that established a
    /// tunnel, labelled by the transport (`hbone`/`mtls`) and relay outcome
    /// (`success`/`failure`). Unlike `hbone_relay_failure_counter` this also
    /// counts successes and covers BOTH transports, giving operators a
    /// per-transport view of raw-TCP egress volume + health.
    pub mesh_tcp_egress_connection_counter: DashMap<MeshTcpEgressConnKey, TimestampedCounter>,
    /// Mesh outbound registry decisions keyed by mesh namespace and host.
    ///
    /// Cardinality contract: caller must never pass attacker-controllable
    /// values as `host`. Callers must pass only the fixed `<admit_explicit>`,
    /// `<admit_wildcard>`, or `<denied>` buckets so /metrics stays bounded
    /// under hostile traffic.
    pub mesh_outbound_registry_decisions:
        DashMap<Arc<str>, DashMap<Arc<str>, MeshOutboundRegistryDecisionCounters>>,
    /// Mesh outbound registry decisions for stream-family egress, keyed by
    /// mesh namespace and protocol (`tcp` / `tcp_tls` / `udp` / `udp_dtls`).
    ///
    /// Sibling to `mesh_outbound_registry_decisions` rather than an extra
    /// label on it, because the Wave-1 Grafana dashboards already consume
    /// the HTTP-only counter without a `protocol` dimension — adding one
    /// would split the existing time series in incompatible ways. Stream
    /// rejects always bucket under a small fixed set of protocol labels,
    /// so the cardinality stays bounded without the attacker-supplied-host
    /// concern that the HTTP counter has.
    pub mesh_outbound_registry_stream_decisions:
        DashMap<Arc<str>, DashMap<&'static str, MeshOutboundRegistryDecisionCounters>>,
    /// TLS certificate expiry and validity-window gauges, refreshed on scrape
    /// from the cached, non-secret TLS inventory snapshot
    /// (`crate::tls::inventory_cache`) — never by loading TLS material on the
    /// scrape path (issue #2410). Labels are derived from configured resources,
    /// never from request input.
    pub tls_cert_gauges: DashMap<TlsCertGaugeKey, TlsCertGaugeValues>,
    /// Freshness of the cached TLS inventory snapshot backing `tls_cert_gauges`:
    /// `(collected_at unix seconds, configured max age seconds)`. `None` until
    /// the first background collection publishes a snapshot.
    tls_inventory_freshness: ArcSwap<Option<(i64, u64)>>,
    /// TLS material source refresh outcomes from background source watchers.
    pub tls_source_refresh_counter: DashMap<TlsSourceRefreshKey, TimestampedCounter>,
    /// TLS material source fetch durations from background source watchers.
    pub tls_source_fetch_duration_buckets: DashMap<TlsSourceFetchKey, HistogramBuckets>,
    /// TLS material source fetch failures from background source watchers.
    pub tls_source_fetch_failure_counter: DashMap<TlsSourceFetchFailureKey, TimestampedCounter>,
    /// TLS certificate rotation outcomes from source watchers.
    pub tls_cert_rotation_counter: DashMap<TlsCertRotationKey, TimestampedCounter>,
    /// Node-agent metrics registered by `FERRUM_MODE=node_agent`.
    node_agent_metrics: ArcSwap<Option<Arc<NodeAgentMetrics>>>,
    /// Admin/management-plane connection limiter, registered when an admin
    /// listener starts. Rendered as gauge/counter so operators can observe
    /// management-plane connection pressure and rejections.
    admin_conn_metrics: ArcSwap<Option<Arc<crate::admin::AdminConnLimiter>>>,
    /// Database-mode incremental polling rejection/backoff metrics.
    database_delta_poll_metrics:
        ArcSwap<Option<Arc<crate::modes::database::DatabaseDeltaPollMetrics>>>,
    /// Cached render output with generation timestamp
    render_cache: ArcSwap<Option<(Instant, String)>>,
    /// Configurable render cache TTL in seconds
    render_cache_ttl_secs: AtomicU64,
    /// Configurable stale entry TTL in nanoseconds
    stale_entry_ttl_nanos: AtomicU64,
    /// Minimum cache age (nanos) before record() bothers to invalidate.
    /// Prevents an Arc allocation on every request under high load.
    cache_invalidation_min_age_nanos: AtomicU64,
    /// Extra label fragment for namespace isolation. Injected into every
    /// metric's label set during render so that multiple gateway instances with
    /// different namespaces produce distinct time series.
    namespace_label: std::sync::RwLock<String>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            request_counter: DashMap::new(),
            request_duration_buckets: DashMap::new(),
            backend_duration_buckets: DashMap::new(),
            gateway_overhead_buckets: DashMap::new(),
            ai_prompt_tokens_counter: DashMap::new(),
            ai_completion_tokens_counter: DashMap::new(),
            ai_total_tokens_counter: DashMap::new(),
            ai_estimated_cost_counter: DashMap::new(),
            mesh_request_counter: DashMap::new(),
            mesh_request_duration_buckets: DashMap::new(),
            rate_limit_exceeded: AtomicU64::new(0),
            request_mirror_dispatched: AtomicU64::new(0),
            request_mirror_completed: AtomicU64::new(0),
            request_mirror_request_timeouts: AtomicU64::new(0),
            request_mirror_request_failures: AtomicU64::new(0),
            request_mirror_drain_timeouts: AtomicU64::new(0),
            request_mirror_drain_failures: AtomicU64::new(0),
            request_mirror_drain_truncations: AtomicU64::new(0),
            request_mirror_cancellations: AtomicU64::new(0),
            request_mirror_concurrency_drops: AtomicU64::new(0),
            request_mirror_budget_drops: AtomicU64::new(0),
            ai_federation_circuits_open: AtomicI64::new(0),
            ai_federation_circuits_opened: AtomicU64::new(0),
            ai_federation_circuits_closed: AtomicU64::new(0),
            ai_federation_circuit_half_open_probes: AtomicU64::new(0),
            ai_federation_circuit_open_skips: AtomicU64::new(0),
            stream_connection_counter: DashMap::new(),
            stream_duration_buckets: DashMap::new(),
            ws_session_counter: DashMap::new(),
            ws_session_duration_buckets: DashMap::new(),
            ws_bytes_counter: DashMap::new(),
            ws_frames_counter: DashMap::new(),
            client_disconnect_counter: DashMap::new(),
            stream_disconnect_counter: DashMap::new(),
            mesh_dns_upstream_id_exhaustions: AtomicU64::new(0),
            hbone_relay_failure_counter: DashMap::new(),
            mesh_tcp_egress_connection_counter: DashMap::new(),
            mesh_outbound_registry_decisions: DashMap::new(),
            mesh_outbound_registry_stream_decisions: DashMap::new(),
            tls_cert_gauges: DashMap::new(),
            tls_inventory_freshness: ArcSwap::from_pointee(None),
            tls_source_refresh_counter: DashMap::new(),
            tls_source_fetch_duration_buckets: DashMap::new(),
            tls_source_fetch_failure_counter: DashMap::new(),
            tls_cert_rotation_counter: DashMap::new(),
            node_agent_metrics: ArcSwap::from_pointee(None),
            admin_conn_metrics: ArcSwap::from_pointee(None),
            database_delta_poll_metrics: ArcSwap::from_pointee(None),
            render_cache: ArcSwap::from_pointee(None),
            render_cache_ttl_secs: AtomicU64::new(DEFAULT_RENDER_CACHE_TTL_SECS),
            stale_entry_ttl_nanos: AtomicU64::new(DEFAULT_STALE_TTL_NANOS),
            cache_invalidation_min_age_nanos: AtomicU64::new(
                DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS,
            ),
            namespace_label: std::sync::RwLock::new(String::new()),
        }
    }

    /// Update process-wide tunable parameters from the single enabled global
    /// plugin instance. Config validation rejects scoped or duplicate enabled
    /// instances before plugin construction.
    pub fn configure(
        &self,
        render_cache_ttl_secs: u64,
        stale_entry_ttl_secs: u64,
        cache_invalidation_min_age_ms: u64,
        namespace: &str,
    ) {
        self.render_cache_ttl_secs
            .store(render_cache_ttl_secs, Ordering::Relaxed);
        self.stale_entry_ttl_nanos.store(
            stale_entry_ttl_secs.saturating_mul(1_000_000_000),
            Ordering::Relaxed,
        );
        self.cache_invalidation_min_age_nanos.store(
            cache_invalidation_min_age_ms.saturating_mul(1_000_000),
            Ordering::Relaxed,
        );
        // Set namespace label fragment for every namespace.
        if let Ok(mut ns_label) = self.namespace_label.write() {
            *ns_label = format!(",namespace=\"{}\"", escape_label_value(namespace));
        }
        self.render_cache.store(Arc::new(None));
    }

    pub fn record_stream(&self, summary: &StreamTransactionSummary) {
        let proxy_id: Arc<str> = Arc::from(summary.proxy_id.as_str());

        let counter_key = StreamCounterKey {
            proxy_id: Arc::clone(&proxy_id),
            protocol: Arc::from(summary.protocol.as_str()),
        };
        self.stream_connection_counter
            .entry(counter_key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);

        self.stream_duration_buckets
            .entry(Arc::clone(&proxy_id))
            .or_insert_with(|| HistogramBuckets::new(self.epoch))
            .observe(summary.duration_ms, self.epoch);

        // Always record disconnect cause+direction, even on clean shutdowns,
        // so operators can compare ratios (e.g., graceful vs. error) without
        // having to subtract from the connections-total counter.
        let disconnect_key = StreamDisconnectKey {
            proxy_id,
            protocol: Arc::from(summary.protocol.as_str()),
            cause: disconnect_cause_label(summary.disconnect_cause),
            direction: direction_label(summary.disconnect_direction),
        };
        self.stream_disconnect_counter
            .entry(disconnect_key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);

        self.maybe_invalidate_cache();
    }

    pub fn record_ws_session(&self, ctx: &WsDisconnectContext) {
        let proxy_id: Arc<str> = Arc::from(ctx.proxy_id.as_str());
        let session_key = WsSessionKey {
            proxy_id: Arc::clone(&proxy_id),
            result: if ctx.error_class.is_some() {
                "error"
            } else {
                "success"
            },
            direction: direction_label(ctx.direction),
            io_side: ws_io_side_label(ctx.io_side),
            error_class: ctx
                .error_class
                .as_ref()
                .map(ErrorClass::as_str)
                .unwrap_or("none"),
        };
        self.ws_session_counter
            .entry(session_key.clone())
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);
        self.ws_session_duration_buckets
            .entry(session_key)
            .or_insert_with(|| HistogramBuckets::new(self.epoch))
            .observe(ctx.duration_ms.max(0.0), self.epoch);

        for (direction, bytes, frames) in [
            (
                "client_to_backend",
                ctx.bytes_client_to_backend,
                ctx.frames_client_to_backend,
            ),
            (
                "backend_to_client",
                ctx.bytes_backend_to_client,
                ctx.frames_backend_to_client,
            ),
        ] {
            let key = WsTrafficKey {
                proxy_id: Arc::clone(&proxy_id),
                direction,
            };
            self.ws_bytes_counter
                .entry(key.clone())
                .or_insert_with(|| TimestampedCounter::new(self.epoch))
                .add(bytes, self.epoch);
            self.ws_frames_counter
                .entry(key)
                .or_insert_with(|| TimestampedCounter::new(self.epoch))
                .add(frames, self.epoch);
        }

        self.maybe_invalidate_cache();
    }

    /// Record one rejection/drop/connection-close produced by any built-in
    /// rate-limiter plugin.
    pub fn record_rate_limit_exceeded(&self) {
        self.rate_limit_exceeded.fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    /// Process-wide `request_mirror` lifecycle counters. Labels are never used:
    /// outcomes are fixed aggregate tallies with no URLs, header names, plugin
    /// IDs, or attacker-controlled dimensions.
    pub fn record_request_mirror_dispatched(&self) {
        self.request_mirror_dispatched
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_completed(&self) {
        self.request_mirror_completed
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_request_timeout(&self) {
        self.request_mirror_request_timeouts
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_request_failure(&self) {
        self.request_mirror_request_failures
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_drain_timeout(&self) {
        self.request_mirror_drain_timeouts
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_drain_failure(&self) {
        self.request_mirror_drain_failures
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_drain_truncation(&self) {
        self.request_mirror_drain_truncations
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_cancellation(&self) {
        self.request_mirror_cancellations
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_concurrency_drop(&self) {
        self.request_mirror_concurrency_drops
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_request_mirror_budget_drop(&self) {
        self.request_mirror_budget_drops
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_ai_federation_circuit_opened(&self) {
        self.ai_federation_circuits_open
            .fetch_add(1, Ordering::Relaxed);
        self.ai_federation_circuits_opened
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_ai_federation_circuit_closed(&self) {
        let _ = self.ai_federation_circuits_open.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(1)),
        );
        self.ai_federation_circuits_closed
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn release_ai_federation_open_circuit(&self) {
        let _ = self.ai_federation_circuits_open.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(1)),
        );
        self.maybe_invalidate_cache();
    }

    pub fn record_ai_federation_half_open_probe(&self) {
        self.ai_federation_circuit_half_open_probes
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_ai_federation_open_skip(&self) {
        self.ai_federation_circuit_open_skips
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_mesh_dns_upstream_id_exhaustion(&self) {
        self.mesh_dns_upstream_id_exhaustions
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_invalidate_cache();
    }

    pub fn record_hbone_relay_failure(
        &self,
        proxy_id: &str,
        direction: Direction,
        error_class: ErrorClass,
    ) {
        let key = HboneRelayFailureKey {
            proxy_id: Arc::from(proxy_id),
            direction: direction_label(Some(direction)),
            error_class: error_class.as_str(),
        };
        self.hbone_relay_failure_counter
            .entry(key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);

        self.maybe_invalidate_cache();
    }

    /// Record one completed raw-TCP mesh egress relay connection. `transport`
    /// is the static transport label (`"hbone"` / `"mtls"`); `success` is the
    /// relay outcome (no copy failure observed). Both labels are compiled-in
    /// constants, so cardinality stays bounded.
    pub fn record_mesh_tcp_egress_connection(&self, transport: &'static str, success: bool) {
        let key = MeshTcpEgressConnKey {
            transport,
            result: if success { "success" } else { "failure" },
        };
        self.mesh_tcp_egress_connection_counter
            .entry(key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);

        self.maybe_invalidate_cache();
    }

    pub fn set_node_agent_metrics(&self, metrics: Arc<NodeAgentMetrics>) {
        self.node_agent_metrics.store(Arc::new(Some(metrics)));
        self.render_cache.store(Arc::new(None));
    }

    /// Register the admin connection limiter so `/metrics` exposes its
    /// gauge/counters. Idempotent: an admin mode that starts both a plaintext
    /// and a TLS listener registers the same shared limiter `Arc` twice.
    pub fn set_admin_conn_metrics(&self, limiter: Arc<crate::admin::AdminConnLimiter>) {
        self.admin_conn_metrics.store(Arc::new(Some(limiter)));
        self.render_cache.store(Arc::new(None));
    }

    pub fn set_database_delta_poll_metrics(
        &self,
        metrics: Arc<crate::modes::database::DatabaseDeltaPollMetrics>,
    ) {
        self.database_delta_poll_metrics
            .store(Arc::new(Some(metrics)));
        self.render_cache.store(Arc::new(None));
    }

    pub fn invalidate_database_delta_poll_metrics_cache(&self) {
        self.render_cache.store(Arc::new(None));
    }

    pub fn database_delta_poll_metrics_snapshot(
        &self,
    ) -> Option<crate::modes::database::DatabaseDeltaPollMetricsSnapshot> {
        let metrics = self.database_delta_poll_metrics.load_full();
        metrics.as_ref().as_ref().map(|metrics| metrics.snapshot())
    }

    /// Publish the freshness of the cached TLS inventory snapshot that backs the
    /// certificate gauges: `Some((collected_at unix seconds, configured max age
    /// seconds))`, or `None` while no snapshot has been collected yet.
    ///
    /// The render cache is invalidated only on an actual change, so repeated
    /// scrapes inside the render TTL keep hitting the cache (issue #2240).
    pub fn set_tls_inventory_freshness(&self, freshness: Option<(i64, u64)>) {
        if **self.tls_inventory_freshness.load() == freshness {
            return;
        }
        self.tls_inventory_freshness.store(Arc::new(freshness));
        self.render_cache.store(Arc::new(None));
    }

    pub fn refresh_tls_certificate_inventory(
        &self,
        inventory: &crate::tls::inventory::TlsInventory,
    ) {
        let mut seen = std::collections::HashSet::new();
        let mut changed = false;

        for entry in &inventory.entries {
            let Some(not_after) = entry.not_after else {
                continue;
            };
            let not_after_ts = not_after.timestamp();
            let not_before_ts = entry
                .not_before
                .map(|not_before| not_before.timestamp())
                .unwrap_or(0);
            let mut surfaces = entry
                .used_by
                .iter()
                .map(|usage| usage.surface.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if surfaces.is_empty() {
                surfaces.insert("unknown");
            }
            for surface in surfaces {
                let key = TlsCertGaugeKey {
                    cert_id: Arc::from(entry.id.as_str()),
                    surface: Arc::from(surface),
                    source_kind: Arc::from(entry.source.kind.as_str()),
                };
                seen.insert(key.clone());
                match self.tls_cert_gauges.entry(key) {
                    dashmap::mapref::entry::Entry::Occupied(existing) => {
                        changed |= existing.get().update(not_after_ts, not_before_ts);
                    }
                    dashmap::mapref::entry::Entry::Vacant(vacant) => {
                        vacant.insert(TlsCertGaugeValues::new(not_after_ts, not_before_ts));
                        changed = true;
                    }
                }
            }
        }

        let old_len = self.tls_cert_gauges.len();
        self.tls_cert_gauges.retain(|key, _| seen.contains(key));
        changed |= self.tls_cert_gauges.len() != old_len;
        if changed {
            self.render_cache.store(Arc::new(None));
        }
    }

    pub fn record_tls_source_refresh(
        &self,
        scheme: &str,
        kind: &str,
        surface: &str,
        outcome: &str,
    ) {
        let key = TlsSourceRefreshKey {
            scheme: Arc::from(scheme),
            kind: Arc::from(kind),
            surface: Arc::from(surface),
            outcome: Arc::from(outcome),
        };
        self.tls_source_refresh_counter
            .entry(key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);
        self.maybe_invalidate_cache();
    }

    pub fn record_tls_source_fetch_duration(&self, scheme: &str, kind: &str, duration_secs: f64) {
        let key = TlsSourceFetchKey {
            scheme: Arc::from(scheme),
            kind: Arc::from(kind),
        };
        self.tls_source_fetch_duration_buckets
            .entry(key)
            .or_insert_with(|| HistogramBuckets::new_seconds(self.epoch))
            .observe(duration_secs.max(0.0), self.epoch);
        self.maybe_invalidate_cache();
    }

    pub fn record_tls_source_fetch_failure(&self, scheme: &str, kind: &str, reason: &str) {
        let key = TlsSourceFetchFailureKey {
            scheme: Arc::from(scheme),
            kind: Arc::from(kind),
            reason: Arc::from(reason),
        };
        self.tls_source_fetch_failure_counter
            .entry(key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);
        self.maybe_invalidate_cache();
    }

    pub fn record_tls_cert_rotation(&self, cert_id: &str, reason: &str, outcome: &str) {
        let key = TlsCertRotationKey {
            cert_id: Arc::from(cert_id),
            reason: Arc::from(reason),
            outcome: Arc::from(outcome),
        };
        self.tls_cert_rotation_counter
            .entry(key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);
        self.maybe_invalidate_cache();
    }

    pub fn record_mesh_outbound_registry_decision(
        &self,
        mesh_namespace: &str,
        host: &str,
        decision: &'static str,
    ) {
        if let Some(hosts) = self.mesh_outbound_registry_decisions.get(mesh_namespace)
            && let Some(counters) = hosts.get(host)
        {
            counters.increment(decision, self.epoch);
            self.maybe_invalidate_cache();
            return;
        }

        let hosts = self
            .mesh_outbound_registry_decisions
            .entry(Arc::from(mesh_namespace))
            .or_default();
        hosts
            .entry(Arc::from(host))
            .or_insert_with(|| MeshOutboundRegistryDecisionCounters::new(self.epoch))
            .increment(decision, self.epoch);

        self.maybe_invalidate_cache();
    }

    /// Record an outbound enforcement decision for stream-family egress
    /// (TCP / TCP+TLS / UDP / UDP+DTLS). Sibling to
    /// [`Self::record_mesh_outbound_registry_decision`] — see the field
    /// doc on `mesh_outbound_registry_stream_decisions` for why this is
    /// a separate counter rather than an extra label on the HTTP one.
    ///
    /// `protocol` must be one of the pre-interned `'static` strings
    /// from [`crate::modes::mesh::outbound_enforcement`] so the metric
    /// label set stays bounded under hostile traffic. Unlike the HTTP
    /// counter, there is no per-host label here — stream rejects drop
    /// the inbound TCP / UDP datagram before SNI / Host material is
    /// observed in a structured way, so the protocol label is the only
    /// dimension that matters for dashboards.
    pub fn record_mesh_outbound_registry_stream_decision(
        &self,
        mesh_namespace: &str,
        protocol: &'static str,
        decision: &'static str,
    ) {
        if let Some(protocols) = self
            .mesh_outbound_registry_stream_decisions
            .get(mesh_namespace)
            && let Some(counters) = protocols.get(protocol)
        {
            counters.increment(decision, self.epoch);
            self.maybe_invalidate_cache();
            return;
        }

        let protocols = self
            .mesh_outbound_registry_stream_decisions
            .entry(Arc::from(mesh_namespace))
            .or_default();
        protocols
            .entry(protocol)
            .or_insert_with(|| MeshOutboundRegistryDecisionCounters::new(self.epoch))
            .increment(decision, self.epoch);

        self.maybe_invalidate_cache();
    }

    pub fn record(&self, summary: &TransactionSummary) {
        let mesh_key = prometheus_helpers::mesh_request_key(summary);
        self.record_with_mesh_key(summary, mesh_key.as_ref());
    }

    pub fn record_with_mesh_key(
        &self,
        summary: &TransactionSummary,
        mesh_key: Option<&MeshRequestKey>,
    ) {
        // Mirror/shadow summaries represent internal backend probes rather
        // than client-facing proxy results. They must not affect normal
        // request counters/histograms exposed on unauthenticated /metrics.
        if summary.mirror {
            return;
        }

        let proxy_id: Arc<str> = Arc::from(summary.proxy_id.as_deref().unwrap_or("unknown"));

        // Increment request counter (composite key — no format!() allocation)
        let counter_key = CounterKey {
            proxy_id: Arc::clone(&proxy_id),
            method: method_label(summary.http_method.as_str()),
            status_code: summary.response_status_code,
            grpc_status: grpc_status_label(&summary.metadata),
        };
        self.request_counter
            .entry(counter_key)
            .or_insert_with(|| TimestampedCounter::new(self.epoch))
            .increment(self.epoch);

        self.request_duration_buckets
            .entry(Arc::clone(&proxy_id))
            .or_insert_with(|| HistogramBuckets::new(self.epoch))
            .observe(summary.latency_total_ms, self.epoch);

        // Guard against sentinel value (-1.0) used for streaming responses
        // where total backend latency is unknown at log time.
        if summary.latency_backend_total_ms >= 0.0 {
            self.backend_duration_buckets
                .entry(Arc::clone(&proxy_id))
                .or_insert_with(|| HistogramBuckets::new(self.epoch))
                .observe(summary.latency_backend_total_ms, self.epoch);
        }

        // Same sentinel guard for gateway overhead: streamed responses with an
        // unknown backend total emit LATENCY_UNKNOWN_MS rather than inventing
        // overhead from TTFB (issue #2532).
        if summary.latency_gateway_overhead_ms >= 0.0 {
            self.gateway_overhead_buckets
                .entry(Arc::clone(&proxy_id))
                .or_insert_with(|| HistogramBuckets::new(self.epoch))
                .observe(summary.latency_gateway_overhead_ms, self.epoch);
        }

        if let Some(usage) = summary.ai_usage_export.as_ref()
            && let Some(provider) = ai_provider_label(usage.provider)
        {
            let key = AiUsageKey {
                proxy_id: Arc::clone(&proxy_id),
                provider,
            };
            if let Some(value) = usage.prompt_tokens {
                self.ai_prompt_tokens_counter
                    .entry(key.clone())
                    .or_insert_with(|| TimestampedCounter::new(self.epoch))
                    .saturating_add(value, self.epoch);
            }
            if let Some(value) = usage.completion_tokens {
                self.ai_completion_tokens_counter
                    .entry(key.clone())
                    .or_insert_with(|| TimestampedCounter::new(self.epoch))
                    .saturating_add(value, self.epoch);
            }
            if let Some(value) = usage.total_tokens {
                self.ai_total_tokens_counter
                    .entry(key.clone())
                    .or_insert_with(|| TimestampedCounter::new(self.epoch))
                    .saturating_add(value, self.epoch);
            }
            if let Some(value) = usage.cost.as_ref() {
                self.ai_estimated_cost_counter
                    .entry(key)
                    .or_insert_with(|| TimestampedCostCounter::new(self.epoch))
                    .add(value, self.epoch);
            }
        }

        if let Some(mesh_key) = mesh_key {
            if !prometheus_helpers::mesh_metric_disabled(
                summary,
                prometheus_helpers::MeshMetricFamily::RequestCount,
            ) {
                let count_key = prometheus_helpers::mesh_request_key_for_family(
                    summary,
                    mesh_key,
                    prometheus_helpers::MeshMetricFamily::RequestCount,
                );
                self.mesh_request_counter
                    .entry(count_key)
                    .or_insert_with(|| TimestampedCounter::new(self.epoch))
                    .increment(self.epoch);
            }
            if !prometheus_helpers::mesh_metric_disabled(
                summary,
                prometheus_helpers::MeshMetricFamily::RequestDuration,
            ) {
                let duration_key = prometheus_helpers::mesh_request_key_for_family(
                    summary,
                    mesh_key,
                    prometheus_helpers::MeshMetricFamily::RequestDuration,
                );
                self.mesh_request_duration_buckets
                    .entry(duration_key)
                    .or_insert_with(|| HistogramBuckets::new(self.epoch))
                    .observe(summary.latency_total_ms, self.epoch);
            }
        }

        // Increment the client-disconnect counter whenever the summary flags
        // the client as having aborted before receiving the full response.
        // Today this stays at zero for HTTP-family protocols (the field is
        // hardcoded false in all literal constructors); once the deferred-log
        // refactor populates it, this counter starts reporting automatically.
        if summary.client_disconnected {
            let key = ClientDisconnectKey { proxy_id };
            self.client_disconnect_counter
                .entry(key)
                .or_insert_with(|| TimestampedCounter::new(self.epoch))
                .increment(self.epoch);
        }

        self.maybe_invalidate_cache();
    }

    /// Invalidate the render cache only if it's older than the configured
    /// minimum age. Under extreme load this avoids an Arc allocation on
    /// every single request — the TTL in render() is the real freshness
    /// guarantee, this just ensures it gets rebuilt promptly at low RPS.
    fn maybe_invalidate_cache(&self) {
        let min_age_nanos = self
            .cache_invalidation_min_age_nanos
            .load(Ordering::Relaxed);
        let cached = self.render_cache.load();
        let Some((generated_at, _)) = &**cached else {
            return; // Already invalid: avoid another Arc allocation + atomic store.
        };
        let age_nanos = generated_at.elapsed().as_nanos() as u64;
        if age_nanos < min_age_nanos {
            return; // Cache is young enough, skip invalidation
        }
        self.render_cache.store(Arc::new(None));
    }

    /// Evict entries that haven't been updated within `ttl_nanos`.
    /// Returns the number of entries evicted across all maps.
    pub fn evict_stale(&self, ttl_nanos: u64) -> usize {
        let mut evicted = 0;

        self.request_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.request_duration_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.backend_duration_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.gateway_overhead_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        for counters in [
            &self.ai_prompt_tokens_counter,
            &self.ai_completion_tokens_counter,
            &self.ai_total_tokens_counter,
        ] {
            counters.retain(|_, value| {
                let keep = value.nanos_since_update(self.epoch) < ttl_nanos;
                if !keep {
                    evicted += 1;
                }
                keep
            });
        }
        self.ai_estimated_cost_counter.retain(|_, value| {
            let keep = value.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.mesh_request_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.mesh_request_duration_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.stream_connection_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.stream_duration_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.ws_session_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.ws_session_duration_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.ws_bytes_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.ws_frames_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.client_disconnect_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.stream_disconnect_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.hbone_relay_failure_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.mesh_tcp_egress_connection_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.mesh_outbound_registry_decisions.retain(|_, hosts| {
            hosts.retain(|_, counters| {
                let keep = counters.admit.nanos_since_update(self.epoch) < ttl_nanos
                    || counters.deny.nanos_since_update(self.epoch) < ttl_nanos;
                if !keep {
                    evicted += 1;
                }
                keep
            });
            let keep = !hosts.is_empty();
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.mesh_outbound_registry_stream_decisions
            .retain(|_, protocols| {
                protocols.retain(|_, counters| {
                    let keep = counters.admit.nanos_since_update(self.epoch) < ttl_nanos
                        || counters.deny.nanos_since_update(self.epoch) < ttl_nanos;
                    if !keep {
                        evicted += 1;
                    }
                    keep
                });
                let keep = !protocols.is_empty();
                if !keep {
                    evicted += 1;
                }
                keep
            });

        self.tls_source_refresh_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.tls_source_fetch_duration_buckets.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.tls_source_fetch_failure_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        self.tls_cert_rotation_counter.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });

        if evicted > 0 {
            // Invalidate render cache after eviction
            self.render_cache.store(Arc::new(None));
        }

        evicted
    }

    /// Render metrics in Prometheus exposition format.
    /// Returns a cached result if the cache is still fresh (within render_cache_ttl_secs).
    /// Also runs lazy stale-entry eviction on each cache miss to bound memory growth.
    pub fn render(&self) -> String {
        // Check cache
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let cached = self.render_cache.load();
        if let Some((generated_at, ref output)) = **cached
            && generated_at.elapsed().as_secs() < ttl_secs
        {
            return output.clone();
        }

        // Lazy eviction: piggyback on cache-miss (at most once per render_cache_ttl_secs)
        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        let output = self.render_uncached();

        self.render_cache
            .store(Arc::new(Some((Instant::now(), output.clone()))));

        output
    }

    /// Render metrics without caching. Used internally and for testing.
    pub fn render_uncached(&self) -> String {
        // Pre-estimate capacity: ~200 bytes per counter entry, ~800 per histogram proxy
        let estimated_cap = 512
            + self.request_counter.len() * 200
            + self.request_duration_buckets.len() * 800
            + self.backend_duration_buckets.len() * 800
            + self.gateway_overhead_buckets.len() * 800
            + self.ai_prompt_tokens_counter.len() * 180
            + self.ai_completion_tokens_counter.len() * 180
            + self.ai_total_tokens_counter.len() * 180
            + self.ai_estimated_cost_counter.len() * 300
            + self.mesh_request_counter.len() * 600
            + self.mesh_request_duration_buckets.len() * 1800
            + self.stream_connection_counter.len() * 200
            + self.stream_duration_buckets.len() * 800
            + self.ws_session_counter.len() * 320
            + self.ws_session_duration_buckets.len() * 1000
            + self.ws_bytes_counter.len() * 180
            + self.ws_frames_counter.len() * 180
            + self.hbone_relay_failure_counter.len() * 240
            + self.mesh_tcp_egress_connection_counter.len() * 120
            + self
                .mesh_outbound_registry_decisions
                .iter()
                .map(|entry| entry.value().len())
                .sum::<usize>()
                * 320
            + self
                .mesh_outbound_registry_stream_decisions
                .iter()
                .map(|entry| entry.value().len())
                .sum::<usize>()
                * 240
            + self.tls_cert_gauges.len() * 260
            + self.tls_source_refresh_counter.len() * 220
            + self.tls_source_fetch_duration_buckets.len() * 700
            + self.tls_source_fetch_failure_counter.len() * 220
            + self.tls_cert_rotation_counter.len() * 220
            + if self.database_delta_poll_metrics.load().is_some() {
                1400
            } else {
                0
            }
            + if self.node_agent_metrics.load().is_some() {
                512
            } else {
                0
            }
            + if self.admin_conn_metrics.load().is_some() {
                512
            } else {
                0
            };
        let mut output = String::with_capacity(estimated_cap);

        // Read namespace label fragment once for the render pass.
        let ns_label = self
            .namespace_label
            .read()
            .map(|l| l.clone())
            .unwrap_or_default();
        // Mesh families reserve `namespace` for workload/resource namespaces,
        // so the gateway's configured namespace uses a distinct stable label.
        let gateway_ns_label = gateway_namespace_label(&ns_label);

        // Request counter
        output.push_str("# HELP ferrum_requests_total Total number of requests processed.\n");
        output.push_str("# TYPE ferrum_requests_total counter\n");
        for entry in self.request_counter.iter() {
            let key = entry.key();
            let count = entry.value().value.load(Ordering::Relaxed);
            let proxy_id = escape_label_value(&key.proxy_id);
            if let Some(grpc_status) = key.grpc_status {
                output.push_str(&format!(
                    "ferrum_requests_total{{proxy_id=\"{}\",method=\"{}\",status_code=\"{}\",grpc_status=\"{}\"{}}} {}\n",
                    proxy_id, key.method, key.status_code, grpc_status, ns_label, count
                ));
            } else {
                output.push_str(&format!(
                    "ferrum_requests_total{{proxy_id=\"{}\",method=\"{}\",status_code=\"{}\"{}}} {}\n",
                    proxy_id, key.method, key.status_code, ns_label, count
                ));
            }
        }

        render_ai_counter_family(
            &mut output,
            "ferrum_ai_prompt_tokens_total",
            "Prompt tokens reported by AI providers.",
            &self.ai_prompt_tokens_counter,
            &ns_label,
        );
        render_ai_counter_family(
            &mut output,
            "ferrum_ai_completion_tokens_total",
            "Completion tokens reported by AI providers.",
            &self.ai_completion_tokens_counter,
            &ns_label,
        );
        render_ai_counter_family(
            &mut output,
            "ferrum_ai_tokens_total",
            "Total tokens reported by AI providers.",
            &self.ai_total_tokens_counter,
            &ns_label,
        );
        if !self.ai_estimated_cost_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_ai_estimated_cost_currency_units_total Estimated AI cost in the configured currency units, retaining sub-micro precision and rounding the aggregate to six decimals.\n",
            );
            output.push_str("# TYPE ferrum_ai_estimated_cost_currency_units_total counter\n");
            for entry in self.ai_estimated_cost_counter.iter() {
                let key = entry.key();
                let value = entry.value().rounded_microunits();
                let proxy_id = escape_label_value(&key.proxy_id);
                output.push_str(&format!(
                    "ferrum_ai_estimated_cost_currency_units_total{{proxy_id=\"{}\",provider=\"{}\"{}}} {}.{:06}\n",
                    proxy_id,
                    key.provider,
                    ns_label,
                    value / 1_000_000,
                    value % 1_000_000
                ));
            }
        }

        // Request duration histogram
        output.push_str("# HELP ferrum_request_duration_ms Request duration in milliseconds.\n");
        output.push_str("# TYPE ferrum_request_duration_ms histogram\n");
        for entry in self.request_duration_buckets.iter() {
            let proxy_id = escape_label_value(entry.key());
            render_histogram(
                &mut output,
                "ferrum_request_duration_ms",
                &proxy_id,
                entry.value(),
                &ns_label,
            );
        }

        // Backend duration histogram
        output
            .push_str("# HELP ferrum_backend_duration_ms Backend response time in milliseconds.\n");
        output.push_str("# TYPE ferrum_backend_duration_ms histogram\n");
        for entry in self.backend_duration_buckets.iter() {
            let proxy_id = escape_label_value(entry.key());
            render_histogram(
                &mut output,
                "ferrum_backend_duration_ms",
                &proxy_id,
                entry.value(),
                &ns_label,
            );
        }

        // Gateway overhead histogram
        output.push_str(
            "# HELP ferrum_edge_overhead_ms Gateway overhead (excluding backend and plugins) in milliseconds.\n",
        );
        output.push_str("# TYPE ferrum_edge_overhead_ms histogram\n");
        for entry in self.gateway_overhead_buckets.iter() {
            let proxy_id = escape_label_value(entry.key());
            render_histogram(
                &mut output,
                "ferrum_edge_overhead_ms",
                &proxy_id,
                entry.value(),
                &ns_label,
            );
        }

        if !self.mesh_request_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_mesh_requests_total Mesh requests by Istio/GAMMA identity labels.\n",
            );
            output.push_str("# TYPE ferrum_mesh_requests_total counter\n");
            for entry in self.mesh_request_counter.iter() {
                let count = entry.value().value.load(Ordering::Relaxed);
                let labels = prometheus_helpers::mesh_label_fragment(entry.key(), None);
                let counter_gateway_ns_label = if labels.is_empty() {
                    gateway_ns_label
                        .strip_prefix(',')
                        .unwrap_or(gateway_ns_label.as_str())
                } else {
                    gateway_ns_label.as_str()
                };
                output.push_str(&format!(
                    "ferrum_mesh_requests_total{{{}{}}} {}\n",
                    labels, counter_gateway_ns_label, count
                ));
            }
        }

        if !self.mesh_request_duration_buckets.is_empty() {
            output.push_str(
                "# HELP ferrum_mesh_request_duration_ms Mesh request duration in milliseconds.\n",
            );
            output.push_str("# TYPE ferrum_mesh_request_duration_ms histogram\n");
            for entry in self.mesh_request_duration_buckets.iter() {
                prometheus_helpers::render_mesh_histogram(
                    &mut output,
                    entry.key(),
                    entry.value(),
                    &gateway_ns_label,
                );
            }
        }

        // Rate limit exceeded
        output.push_str("# HELP ferrum_rate_limit_exceeded_total Total rate limit rejections.\n");
        output.push_str("# TYPE ferrum_rate_limit_exceeded_total counter\n");
        if ns_label.is_empty() {
            output.push_str(&format!(
                "ferrum_rate_limit_exceeded_total {}\n",
                self.rate_limit_exceeded.load(Ordering::Relaxed)
            ));
        } else {
            output.push_str(&format!(
                "ferrum_rate_limit_exceeded_total{{{}}} {}\n",
                namespace_label_body(&ns_label),
                self.rate_limit_exceeded.load(Ordering::Relaxed)
            ));
        }

        // request_mirror lifecycle (aggregate, label-safe; no URLs/plugin IDs).
        // Terminal outcomes for dispatched tasks sum to dispatched:
        // completed + request_timeouts + request_failures + drain_timeouts +
        // drain_failures + drain_truncations + cancellations == dispatched.
        // Admission drops are separate (never dispatched).
        for (name, help, value) in [
            (
                "ferrum_request_mirror_dispatched_total",
                "request_mirror detached tasks admitted past concurrency and retained-body budgets.",
                self.request_mirror_dispatched.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_completed_total",
                "request_mirror tasks that fully drained a response within byte and time bounds.",
                self.request_mirror_completed.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_request_timeouts_total",
                "request_mirror request-phase deadline expiries (connect/headers/body).",
                self.request_mirror_request_timeouts.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_request_failures_total",
                "request_mirror pre-response transport failures (DNS, refused, reset, TLS, …).",
                self.request_mirror_request_failures.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_drain_timeouts_total",
                "request_mirror response-body drain deadline expiries.",
                self.request_mirror_drain_timeouts.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_drain_failures_total",
                "request_mirror response-body drain transport failures.",
                self.request_mirror_drain_failures.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_drain_truncations_total",
                "request_mirror responses truncated at max_response_body_bytes during bounded drain.",
                self.request_mirror_drain_truncations
                    .load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_cancellations_total",
                "request_mirror tasks dropped before a terminal outcome (shutdown/panic/cancellation).",
                self.request_mirror_cancellations.load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_concurrency_drops_total",
                "request_mirror attempts dropped because max_in_flight was saturated.",
                self.request_mirror_concurrency_drops
                    .load(Ordering::Relaxed),
            ),
            (
                "ferrum_request_mirror_budget_drops_total",
                "request_mirror attempts dropped because max_retained_request_body_bytes was exhausted.",
                self.request_mirror_budget_drops.load(Ordering::Relaxed),
            ),
        ] {
            output.push_str(&format!("# HELP {name} {help}\n"));
            output.push_str(&format!("# TYPE {name} counter\n"));
            render_process_counter(&mut output, name, value, &ns_label);
        }

        // Compression codec admission / worker outcomes (process-wide).
        let compression_codec = crate::plugins::compression::compression_codec_metrics();
        for (name, help, value) in [
            (
                "ferrum_compression_codec_admitted_total",
                "Compression codec jobs admitted to the bounded spawn_blocking pool.",
                compression_codec.admitted,
            ),
            (
                "ferrum_compression_codec_saturated_total",
                "Compression codec admission refusals when the bounded pool is saturated.",
                compression_codec.saturated,
            ),
            (
                "ferrum_compression_codec_join_failures_total",
                "Compression codec spawn_blocking tasks that failed to join.",
                compression_codec.join_failures,
            ),
            (
                "ferrum_compression_codec_worker_failures_total",
                "Compression codec worker errors (encode/decode failures inside spawn_blocking).",
                compression_codec.worker_failures,
            ),
        ] {
            output.push_str(&format!("# HELP {name} {help}\n"));
            output.push_str(&format!("# TYPE {name} counter\n"));
            render_process_counter(&mut output, name, value, &ns_label);
        }

        output.push_str(
            "# HELP ferrum_ai_federation_circuits_open Current ai_federation provider circuits in open or half-open recovery state.\n",
        );
        output.push_str("# TYPE ferrum_ai_federation_circuits_open gauge\n");
        render_process_gauge(
            &mut output,
            "ferrum_ai_federation_circuits_open",
            self.ai_federation_circuits_open.load(Ordering::Relaxed),
            &ns_label,
        );
        for (name, help, value) in [
            (
                "ferrum_ai_federation_circuits_opened_total",
                "ai_federation provider circuit closed-to-open transitions.",
                self.ai_federation_circuits_opened.load(Ordering::Relaxed),
            ),
            (
                "ferrum_ai_federation_circuits_closed_total",
                "ai_federation provider circuit half-open recoveries.",
                self.ai_federation_circuits_closed.load(Ordering::Relaxed),
            ),
            (
                "ferrum_ai_federation_circuit_half_open_probes_total",
                "ai_federation provider half-open probes admitted.",
                self.ai_federation_circuit_half_open_probes
                    .load(Ordering::Relaxed),
            ),
            (
                "ferrum_ai_federation_circuit_open_skips_total",
                "ai_federation provider attempts skipped by an open circuit.",
                self.ai_federation_circuit_open_skips
                    .load(Ordering::Relaxed),
            ),
        ] {
            output.push_str(&format!("# HELP {name} {help}\n"));
            output.push_str(&format!("# TYPE {name} counter\n"));
            render_process_counter(&mut output, name, value, &ns_label);
        }

        // Stream connection counter
        if !self.stream_connection_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_stream_connections_total Total stream connections (TCP/UDP).\n",
            );
            output.push_str("# TYPE ferrum_stream_connections_total counter\n");
            for entry in self.stream_connection_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                let protocol = escape_label_value(&key.protocol);
                output.push_str(&format!(
                    "ferrum_stream_connections_total{{proxy_id=\"{}\",protocol=\"{}\"{}}} {}\n",
                    proxy_id, protocol, ns_label, count
                ));
            }
        }

        // Stream duration histogram
        if !self.stream_duration_buckets.is_empty() {
            output.push_str(
                "# HELP ferrum_stream_duration_ms Stream connection duration in milliseconds.\n",
            );
            output.push_str("# TYPE ferrum_stream_duration_ms histogram\n");
            for entry in self.stream_duration_buckets.iter() {
                let proxy_id = escape_label_value(entry.key());
                render_histogram(
                    &mut output,
                    "ferrum_stream_duration_ms",
                    &proxy_id,
                    entry.value(),
                    &ns_label,
                );
            }
        }

        if !self.ws_session_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_websocket_sessions_total Completed WebSocket sessions by bounded terminal classification.\n",
            );
            output.push_str("# TYPE ferrum_websocket_sessions_total counter\n");
            for entry in self.ws_session_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                output.push_str(&format!(
                    "ferrum_websocket_sessions_total{{proxy_id=\"{}\",result=\"{}\",direction=\"{}\",io_side=\"{}\",error_class=\"{}\"{}}} {}\n",
                    proxy_id,
                    key.result,
                    key.direction,
                    key.io_side,
                    key.error_class,
                    ns_label,
                    count
                ));
            }
        }

        if !self.ws_session_duration_buckets.is_empty() {
            output.push_str(
                "# HELP ferrum_websocket_session_duration_ms WebSocket session duration in milliseconds.\n",
            );
            output.push_str("# TYPE ferrum_websocket_session_duration_ms histogram\n");
            for entry in self.ws_session_duration_buckets.iter() {
                render_ws_histogram(&mut output, entry.key(), entry.value(), &ns_label);
            }
        }

        if !self.ws_bytes_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_websocket_bytes_total WebSocket payload bytes relayed by direction.\n",
            );
            output.push_str("# TYPE ferrum_websocket_bytes_total counter\n");
            for entry in self.ws_bytes_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                output.push_str(&format!(
                    "ferrum_websocket_bytes_total{{proxy_id=\"{}\",direction=\"{}\"{}}} {}\n",
                    proxy_id, key.direction, ns_label, count
                ));
            }
        }

        if !self.ws_frames_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_websocket_frames_total WebSocket frames relayed by direction.\n",
            );
            output.push_str("# TYPE ferrum_websocket_frames_total counter\n");
            for entry in self.ws_frames_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                output.push_str(&format!(
                    "ferrum_websocket_frames_total{{proxy_id=\"{}\",direction=\"{}\"{}}} {}\n",
                    proxy_id, key.direction, ns_label, count
                ));
            }
        }

        // HTTP-family client disconnect counter. Emitted only when non-empty
        // so the exposition stays tidy for deployments where it never fires.
        if !self.client_disconnect_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_client_disconnects_total Requests where the client disconnected before receiving the full response.\n",
            );
            output.push_str("# TYPE ferrum_client_disconnects_total counter\n");
            for entry in self.client_disconnect_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                output.push_str(&format!(
                    "ferrum_client_disconnects_total{{proxy_id=\"{}\"{}}} {}\n",
                    proxy_id, ns_label, count
                ));
            }
        }

        // Stream disconnect counter, labelled by cause and direction. Unlike
        // the connection counter this is always emitted because graceful vs.
        // error ratios are useful to operators even on well-behaved traffic.
        if !self.stream_disconnect_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_stream_disconnects_total Stream disconnects (TCP/UDP) by cause and direction.\n",
            );
            output.push_str("# TYPE ferrum_stream_disconnects_total counter\n");
            for entry in self.stream_disconnect_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                let protocol = escape_label_value(&key.protocol);
                // cause and direction are &'static str from bounded enums —
                // no escaping needed (snake_case ASCII only).
                output.push_str(&format!(
                    "ferrum_stream_disconnects_total{{proxy_id=\"{}\",protocol=\"{}\",cause=\"{}\",direction=\"{}\"{}}} {}\n",
                    proxy_id, protocol, key.cause, key.direction, ns_label, count
                ));
            }
        }

        let mesh_dns_exhaustions = self
            .mesh_dns_upstream_id_exhaustions
            .load(Ordering::Relaxed);
        output.push_str(
            "# HELP ferrum_mesh_dns_upstream_id_exhaustions_total Mesh DNS upstream transaction ID exhaustion events.\n",
        );
        output.push_str("# TYPE ferrum_mesh_dns_upstream_id_exhaustions_total counter\n");
        if ns_label.is_empty() {
            output.push_str(&format!(
                "ferrum_mesh_dns_upstream_id_exhaustions_total {}\n",
                mesh_dns_exhaustions
            ));
        } else {
            output.push_str(&format!(
                "ferrum_mesh_dns_upstream_id_exhaustions_total{{{}}} {}\n",
                namespace_label_body(&ns_label),
                mesh_dns_exhaustions
            ));
        }

        if !self.hbone_relay_failure_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_mesh_hbone_relay_failures_total HBONE CONNECT tunnel relay failures after the 200 response has been sent.\n",
            );
            output.push_str("# TYPE ferrum_mesh_hbone_relay_failures_total counter\n");
            for entry in self.hbone_relay_failure_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                let proxy_id = escape_label_value(&key.proxy_id);
                let error_class = escape_label_value(key.error_class);
                output.push_str(&format!(
                    "ferrum_mesh_hbone_relay_failures_total{{proxy_id=\"{}\",direction=\"{}\",error_class=\"{}\"{}}} {}\n",
                    proxy_id, key.direction, error_class, ns_label, count
                ));
            }
        }

        if !self.mesh_tcp_egress_connection_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_mesh_tcp_egress_connections_total Raw-TCP mesh egress relay connections by transport and outcome.\n",
            );
            output.push_str("# TYPE ferrum_mesh_tcp_egress_connections_total counter\n");
            for entry in self.mesh_tcp_egress_connection_counter.iter() {
                let key = entry.key();
                let count = entry.value().value.load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_mesh_tcp_egress_connections_total{{transport=\"{}\",result=\"{}\"{}}} {}\n",
                    key.transport, key.result, ns_label, count
                ));
            }
        }

        if !self.mesh_outbound_registry_decisions.is_empty() {
            output.push_str(
                "# HELP ferrum_mesh_outbound_registry_decisions_total Mesh outbound registry decisions with bounded host buckets (<admit_explicit>, <admit_wildcard>, <denied>).\n",
            );
            output.push_str("# TYPE ferrum_mesh_outbound_registry_decisions_total counter\n");
            for namespace_entry in self.mesh_outbound_registry_decisions.iter() {
                let mesh_namespace = escape_label_value(namespace_entry.key().as_ref());
                for host_entry in namespace_entry.value().iter() {
                    let host = escape_label_value(host_entry.key().as_ref());
                    let counters = host_entry.value();
                    let admit = counters.admit.value.load(Ordering::Relaxed);
                    if admit > 0 {
                        output.push_str(&format!(
                            "ferrum_mesh_outbound_registry_decisions_total{{mesh_namespace=\"{}\",host=\"{}\",decision=\"admit\"{}}} {}\n",
                            mesh_namespace, host, ns_label, admit
                        ));
                    }
                    let deny = counters.deny.value.load(Ordering::Relaxed);
                    if deny > 0 {
                        output.push_str(&format!(
                            "ferrum_mesh_outbound_registry_decisions_total{{mesh_namespace=\"{}\",host=\"{}\",decision=\"deny\"{}}} {}\n",
                            mesh_namespace, host, ns_label, deny
                        ));
                    }
                }
            }
        }

        if !self.mesh_outbound_registry_stream_decisions.is_empty() {
            output.push_str(
                "# HELP ferrum_mesh_outbound_registry_stream_decisions_total Mesh outbound registry decisions for stream-family egress (TCP/UDP/TCP+TLS/UDP+DTLS) by protocol.\n",
            );
            output
                .push_str("# TYPE ferrum_mesh_outbound_registry_stream_decisions_total counter\n");
            for namespace_entry in self.mesh_outbound_registry_stream_decisions.iter() {
                let mesh_namespace = escape_label_value(namespace_entry.key().as_ref());
                for protocol_entry in namespace_entry.value().iter() {
                    // Protocol values come from a fixed, pre-interned set,
                    // so escape_label_value is defensive only — there is no
                    // attacker path that supplies these strings.
                    let protocol = escape_label_value(protocol_entry.key());
                    let counters = protocol_entry.value();
                    let admit = counters.admit.value.load(Ordering::Relaxed);
                    if admit > 0 {
                        output.push_str(&format!(
                            "ferrum_mesh_outbound_registry_stream_decisions_total{{mesh_namespace=\"{}\",protocol=\"{}\",decision=\"admit\"{}}} {}\n",
                            mesh_namespace, protocol, ns_label, admit
                        ));
                    }
                    let deny = counters.deny.value.load(Ordering::Relaxed);
                    if deny > 0 {
                        output.push_str(&format!(
                            "ferrum_mesh_outbound_registry_stream_decisions_total{{mesh_namespace=\"{}\",protocol=\"{}\",decision=\"deny\"{}}} {}\n",
                            mesh_namespace, protocol, ns_label, deny
                        ));
                    }
                }
            }
        }

        if !self.tls_cert_gauges.is_empty() {
            let now_ts = Utc::now().timestamp();
            output.push_str(
                "# HELP ferrum_tls_cert_expiry_seconds Seconds until the certificate leaf not_after timestamp. Negative means expired.\n",
            );
            output.push_str("# TYPE ferrum_tls_cert_expiry_seconds gauge\n");
            output.push_str(
                "# HELP ferrum_tls_cert_not_before_seconds Certificate leaf not_before timestamp as Unix seconds.\n",
            );
            output.push_str("# TYPE ferrum_tls_cert_not_before_seconds gauge\n");
            for entry in self.tls_cert_gauges.iter() {
                let key = entry.key();
                let cert_id = escape_label_value(&key.cert_id);
                let surface = escape_label_value(&key.surface);
                let source_kind = escape_label_value(&key.source_kind);
                let expiry = entry
                    .value()
                    .not_after_unix_seconds
                    .load(Ordering::Relaxed)
                    .saturating_sub(now_ts);
                let not_before = entry
                    .value()
                    .not_before_unix_seconds
                    .load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_tls_cert_expiry_seconds{{cert_id=\"{}\",surface=\"{}\",source_kind=\"{}\"{}}} {}\n",
                    cert_id, surface, source_kind, ns_label, expiry
                ));
                output.push_str(&format!(
                    "ferrum_tls_cert_not_before_seconds{{cert_id=\"{}\",surface=\"{}\",source_kind=\"{}\"{}}} {}\n",
                    cert_id, surface, source_kind, ns_label, not_before
                ));
            }
        }

        if let Some((collected_at, max_age_seconds)) = **self.tls_inventory_freshness.load() {
            // Explicit, bounded freshness for the cached snapshot the
            // certificate gauges are rendered from (issue #2410). Alerts read
            // `time() - ferrum_tls_inventory_snapshot_timestamp_seconds` against
            // the exported bound instead of assuming scrape-time collection.
            output.push_str(
                "# HELP ferrum_tls_inventory_snapshot_timestamp_seconds Unix timestamp of the cached, non-secret TLS inventory snapshot backing the certificate gauges.\n",
            );
            output.push_str("# TYPE ferrum_tls_inventory_snapshot_timestamp_seconds gauge\n");
            render_process_gauge(
                &mut output,
                "ferrum_tls_inventory_snapshot_timestamp_seconds",
                collected_at,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_tls_inventory_snapshot_max_age_seconds Configured maximum snapshot age (FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS) before a scrape schedules a background refresh.\n",
            );
            output.push_str("# TYPE ferrum_tls_inventory_snapshot_max_age_seconds gauge\n");
            render_process_counter(
                &mut output,
                "ferrum_tls_inventory_snapshot_max_age_seconds",
                max_age_seconds,
                &ns_label,
            );
        }

        if !self.tls_source_refresh_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_tls_source_refresh_total TLS material source refresh attempts by scheme, kind, surface, and outcome.\n",
            );
            output.push_str("# TYPE ferrum_tls_source_refresh_total counter\n");
            for entry in self.tls_source_refresh_counter.iter() {
                let key = entry.key();
                let scheme = escape_label_value(&key.scheme);
                let kind = escape_label_value(&key.kind);
                let surface = escape_label_value(&key.surface);
                let outcome = escape_label_value(&key.outcome);
                let count = entry.value().value.load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_tls_source_refresh_total{{scheme=\"{}\",kind=\"{}\",surface=\"{}\",outcome=\"{}\"{}}} {}\n",
                    scheme, kind, surface, outcome, ns_label, count
                ));
            }
        }

        if !self.tls_source_fetch_duration_buckets.is_empty() {
            output.push_str(
                "# HELP ferrum_tls_source_fetch_duration_seconds TLS material source fetch duration in seconds.\n",
            );
            output.push_str("# TYPE ferrum_tls_source_fetch_duration_seconds histogram\n");
            for entry in self.tls_source_fetch_duration_buckets.iter() {
                render_tls_source_fetch_histogram(
                    &mut output,
                    entry.key(),
                    entry.value(),
                    &ns_label,
                );
            }
        }

        if !self.tls_source_fetch_failure_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_tls_source_fetch_failures_total TLS material source fetch failures by scheme, kind, and bounded reason.\n",
            );
            output.push_str("# TYPE ferrum_tls_source_fetch_failures_total counter\n");
            for entry in self.tls_source_fetch_failure_counter.iter() {
                let key = entry.key();
                let scheme = escape_label_value(&key.scheme);
                let kind = escape_label_value(&key.kind);
                let reason = escape_label_value(&key.reason);
                let count = entry.value().value.load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_tls_source_fetch_failures_total{{scheme=\"{}\",kind=\"{}\",reason=\"{}\"{}}} {}\n",
                    scheme, kind, reason, ns_label, count
                ));
            }
        }

        if !self.tls_cert_rotation_counter.is_empty() {
            output.push_str(
                "# HELP ferrum_tls_cert_rotations_total TLS certificate rotation outcomes by cert ID, reason, and outcome.\n",
            );
            output.push_str("# TYPE ferrum_tls_cert_rotations_total counter\n");
            for entry in self.tls_cert_rotation_counter.iter() {
                let key = entry.key();
                let cert_id = escape_label_value(&key.cert_id);
                let reason = escape_label_value(&key.reason);
                let outcome = escape_label_value(&key.outcome);
                let count = entry.value().value.load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_tls_cert_rotations_total{{cert_id=\"{}\",reason=\"{}\",outcome=\"{}\"{}}} {}\n",
                    cert_id, reason, outcome, ns_label, count
                ));
            }
        }

        prometheus_helpers::render_mesh_observability_metrics_with_gateway_namespace(
            &mut output,
            &gateway_ns_label,
        );

        if let Some(snapshot) = self.database_delta_poll_metrics_snapshot() {
            output.push_str(
                "# HELP ferrum_database_delta_rejections_total Database incremental deltas rejected by validation, bucketed by bounded resource category.\n",
            );
            output.push_str("# TYPE ferrum_database_delta_rejections_total counter\n");
            for category in crate::modes::database::DATABASE_DELTA_RESOURCE_CATEGORY_LABELS {
                let count = snapshot
                    .rejected_deltas_by_resource_category
                    .get(category)
                    .copied()
                    .unwrap_or(0);
                output.push_str(&format!(
                    "ferrum_database_delta_rejections_total{{resource_category=\"{}\"{}}} {}\n",
                    category, ns_label, count
                ));
            }

            output.push_str(
                "# HELP ferrum_database_delta_consecutive_identical_rejections Consecutive identical rejected database deltas currently being retried.\n",
            );
            output
                .push_str("# TYPE ferrum_database_delta_consecutive_identical_rejections gauge\n");
            render_process_counter(
                &mut output,
                "ferrum_database_delta_consecutive_identical_rejections",
                snapshot.consecutive_identical_rejections,
                &ns_label,
            );

            output.push_str(
                "# HELP ferrum_database_delta_backoff_bucket Current rejected-delta retry backoff bucket. Exactly one bucket is 1.\n",
            );
            output.push_str("# TYPE ferrum_database_delta_backoff_bucket gauge\n");
            for bucket in crate::modes::database::DATABASE_DELTA_BACKOFF_BUCKET_LABELS {
                let value = if bucket == snapshot.current_backoff_bucket {
                    1
                } else {
                    0
                };
                output.push_str(&format!(
                    "ferrum_database_delta_backoff_bucket{{bucket=\"{}\"{}}} {}\n",
                    bucket, ns_label, value
                ));
            }

            output.push_str(
                "# HELP ferrum_database_delta_forced_full_reloads_total Authoritative full reload attempts triggered by repeated rejected database deltas.\n",
            );
            output.push_str("# TYPE ferrum_database_delta_forced_full_reloads_total counter\n");
            render_process_counter(
                &mut output,
                "ferrum_database_delta_forced_full_reloads_total",
                snapshot.forced_full_reloads_total,
                &ns_label,
            );

            output.push_str(
                "# HELP ferrum_database_delta_recoveries_total Rejected database delta recovery events after an accepted incremental apply or full reload.\n",
            );
            output.push_str("# TYPE ferrum_database_delta_recoveries_total counter\n");
            render_process_counter(
                &mut output,
                "ferrum_database_delta_recoveries_total",
                snapshot.recoveries_total,
                &ns_label,
            );
        }

        let admin_conn_metrics = self.admin_conn_metrics.load_full();
        if let Some(limiter) = admin_conn_metrics.as_ref() {
            let snapshot = limiter.snapshot();
            output.push_str(
                "# HELP ferrum_admin_active_connections Admin/management-plane connections currently in flight.\n",
            );
            output.push_str("# TYPE ferrum_admin_active_connections gauge\n");
            render_process_counter(
                &mut output,
                "ferrum_admin_active_connections",
                snapshot.active_connections,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_admin_max_connections Configured admin connection cap (0 = unlimited).\n",
            );
            output.push_str("# TYPE ferrum_admin_max_connections gauge\n");
            render_process_counter(
                &mut output,
                "ferrum_admin_max_connections",
                snapshot.max_connections as u64,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_admin_max_connections_per_ip Configured per-source-IP admin connection cap (0 = unlimited).\n",
            );
            output.push_str("# TYPE ferrum_admin_max_connections_per_ip gauge\n");
            render_process_counter(
                &mut output,
                "ferrum_admin_max_connections_per_ip",
                snapshot.max_connections_per_ip as u64,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_admin_rejected_connections_total Admin connections rejected by the connection limiter, by reason.\n",
            );
            output.push_str("# TYPE ferrum_admin_rejected_connections_total counter\n");
            // Emit both reason buckets even at zero so dashboards can pin them.
            for (reason, value) in [
                ("max_connections", snapshot.rejected_max_connections),
                (
                    "max_connections_per_ip",
                    snapshot.rejected_max_connections_per_ip,
                ),
            ] {
                output.push_str(&format!(
                    "ferrum_admin_rejected_connections_total{{reason=\"{reason}\"{ns_label}}} {value}\n"
                ));
            }
        }

        let node_agent_metrics = self.node_agent_metrics.load_full();
        if let Some(metrics) = node_agent_metrics.as_ref() {
            let snapshot = metrics.snapshot();
            output.push_str(
                "# HELP ferrum_node_agent_pods_enrolled_total Pods enrolled for node-agent capture.\n",
            );
            output.push_str("# TYPE ferrum_node_agent_pods_enrolled_total counter\n");
            render_process_counter(
                &mut output,
                "ferrum_node_agent_pods_enrolled_total",
                snapshot.pods_enrolled,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_node_agent_pods_unenrolled_total Pods unenrolled from node-agent capture.\n",
            );
            output.push_str("# TYPE ferrum_node_agent_pods_unenrolled_total counter\n");
            render_process_counter(
                &mut output,
                "ferrum_node_agent_pods_unenrolled_total",
                snapshot.pods_unenrolled,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_node_agent_attach_errors_total Node-agent BPF attachment or map update errors.\n",
            );
            output.push_str("# TYPE ferrum_node_agent_attach_errors_total counter\n");
            render_process_counter(
                &mut output,
                "ferrum_node_agent_attach_errors_total",
                snapshot.attach_errors,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_node_agent_pod_annotation_updates_applied_total Mid-life pod includeOutboundPorts annotation changes re-applied to the BPF map.\n",
            );
            output.push_str(
                "# TYPE ferrum_node_agent_pod_annotation_updates_applied_total counter\n",
            );
            render_process_counter(
                &mut output,
                "ferrum_node_agent_pod_annotation_updates_applied_total",
                snapshot.pod_annotation_updates_applied,
                &ns_label,
            );
            output.push_str(
                "# HELP ferrum_node_agent_pod_annotation_updates_failed_total Mid-life pod includeOutboundPorts annotation changes that failed to re-apply (annotation parse error or BPF map write error). Cgroup-id-unavailable retries are intentionally not counted here because they are routinely observed during early pod startup and are retried on the next Apply event.\n",
            );
            output
                .push_str("# TYPE ferrum_node_agent_pod_annotation_updates_failed_total counter\n");
            render_process_counter(
                &mut output,
                "ferrum_node_agent_pod_annotation_updates_failed_total",
                snapshot.pod_annotation_updates_failed,
                &ns_label,
            );

            output.push_str(
                "# HELP ferrum_node_agent_cni_socket_lifecycle_total Node-agent CNI socket lifecycle failures by bounded reason.\n",
            );
            output.push_str("# TYPE ferrum_node_agent_cni_socket_lifecycle_total counter\n");
            for reason in crate::ebpf::CniSocketLifecycleReason::all() {
                let value = snapshot.cni_socket_lifecycle[reason as usize];
                if ns_label.is_empty() {
                    output.push_str(&format!(
                        "ferrum_node_agent_cni_socket_lifecycle_total{{reason=\"{}\"}} {}\n",
                        reason.label(),
                        value,
                    ));
                } else {
                    output.push_str(&format!(
                        "ferrum_node_agent_cni_socket_lifecycle_total{{reason=\"{}\"{}}} {}\n",
                        reason.label(),
                        ns_label,
                        value,
                    ));
                }
            }

            // Capture-state gauge — one hot label from a closed set. This is
            // the readiness/condition surface operators alert on; the
            // topology-degraded gauge below explains the first degradation
            // reason in more detail.
            output.push_str(
                "# HELP ferrum_node_agent_capture_state \
                 Node-agent capture backend condition. Exactly one state label is 1.\n",
            );
            output.push_str("# TYPE ferrum_node_agent_capture_state gauge\n");
            for state in crate::ebpf::NODE_AGENT_CAPTURE_STATES {
                let value = u64::from(snapshot.capture_state == *state);
                if ns_label.is_empty() {
                    output.push_str(&format!(
                        "ferrum_node_agent_capture_state{{state=\"{}\"}} {}\n",
                        state, value,
                    ));
                } else {
                    output.push_str(&format!(
                        "ferrum_node_agent_capture_state{{state=\"{}\"{}}} {}\n",
                        state, ns_label, value,
                    ));
                }
            }

            // Topology-degraded gauge — emitted whenever the node-agent
            // metrics are registered so dashboards can pin "expected: 0"
            // even on healthy nodes. `reason` is a closed snake_case set
            // from KernelProbeResult::degradation_reason (kernel_too_old,
            // cgroup_v1, bpffs_missing), plus ebpf_feature_disabled when the
            // binary was built without `--features ebpf` and falls back to the
            // mock backend (GAP-1b), plus a single "none" series on nominal
            // nodes — total cardinality is bounded per node.
            output.push_str(
                "# HELP ferrum_mesh_node_topology_degraded \
                 Node-agent detected missing eBPF prerequisites or a build without eBPF capture. \
                 1 with a reason label means degraded, 0 with reason=\"none\" means nominal.\n",
            );
            output.push_str("# TYPE ferrum_mesh_node_topology_degraded gauge\n");
            let (reason, value) = match snapshot.topology_degraded_reason {
                Some(reason) => (reason, 1u64),
                None => ("none", 0u64),
            };
            if ns_label.is_empty() {
                output.push_str(&format!(
                    "ferrum_mesh_node_topology_degraded{{reason=\"{}\"}} {}\n",
                    reason, value,
                ));
            } else {
                output.push_str(&format!(
                    "ferrum_mesh_node_topology_degraded{{reason=\"{}\"{}}} {}\n",
                    reason, ns_label, value,
                ));
            }
        }

        output
    }
}

fn render_ai_counter_family(
    output: &mut String,
    metric_name: &str,
    help: &str,
    counters: &DashMap<AiUsageKey, TimestampedCounter>,
    ns_label: &str,
) {
    if counters.is_empty() {
        return;
    }
    output.push_str(&format!("# HELP {metric_name} {help}\n"));
    output.push_str(&format!("# TYPE {metric_name} counter\n"));
    for entry in counters.iter() {
        let key = entry.key();
        let value = entry.value().value.load(Ordering::Relaxed);
        let proxy_id = escape_label_value(&key.proxy_id);
        output.push_str(&format!(
            "{metric_name}{{proxy_id=\"{}\",provider=\"{}\"{}}} {}\n",
            proxy_id, key.provider, ns_label, value
        ));
    }
}

fn render_process_counter(output: &mut String, metric_name: &str, value: u64, ns_label: &str) {
    if ns_label.is_empty() {
        output.push_str(&format!("{metric_name} {value}\n"));
    } else {
        output.push_str(&format!(
            "{metric_name}{{{}}} {value}\n",
            namespace_label_body(ns_label)
        ));
    }
}

fn render_process_gauge(output: &mut String, metric_name: &str, value: i64, ns_label: &str) {
    if ns_label.is_empty() {
        output.push_str(&format!("{metric_name} {value}\n"));
    } else {
        output.push_str(&format!(
            "{metric_name}{{{}}} {value}\n",
            namespace_label_body(ns_label)
        ));
    }
}

fn namespace_label_body(ns_label: &str) -> &str {
    debug_assert!(ns_label.starts_with(','));
    ns_label.strip_prefix(',').unwrap_or(ns_label)
}

fn gateway_namespace_label(ns_label: &str) -> String {
    if ns_label.is_empty() {
        String::new()
    } else {
        format!(",gateway_{}", namespace_label_body(ns_label))
    }
}

/// Render a single histogram's buckets, sum, and count into the output buffer.
fn render_histogram(
    output: &mut String,
    metric_name: &str,
    proxy_id: &str,
    histogram: &HistogramBuckets,
    ns_label: &str,
) {
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let count = histogram.counts[i].load(Ordering::Relaxed);
        output.push_str(&format!(
            "{}_bucket{{proxy_id=\"{}\",le=\"{}\"{}}} {}\n",
            metric_name, proxy_id, boundary, ns_label, count
        ));
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    output.push_str(&format!(
        "{}_bucket{{proxy_id=\"{}\",le=\"+Inf\"{}}} {}\n",
        metric_name, proxy_id, ns_label, total_count
    ));
    output.push_str(&format!(
        "{}_sum{{proxy_id=\"{}\"{}}} {:.2}\n",
        metric_name, proxy_id, ns_label, sum
    ));
    output.push_str(&format!(
        "{}_count{{proxy_id=\"{}\"{}}} {}\n",
        metric_name, proxy_id, ns_label, total_count
    ));
}

fn render_ws_histogram(
    output: &mut String,
    key: &WsSessionKey,
    histogram: &HistogramBuckets,
    ns_label: &str,
) {
    let proxy_id = escape_label_value(&key.proxy_id);
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let count = histogram.counts[i].load(Ordering::Relaxed);
        output.push_str(&format!(
            "ferrum_websocket_session_duration_ms_bucket{{proxy_id=\"{}\",result=\"{}\",direction=\"{}\",io_side=\"{}\",error_class=\"{}\",le=\"{}\"{}}} {}\n",
            proxy_id,
            key.result,
            key.direction,
            key.io_side,
            key.error_class,
            boundary,
            ns_label,
            count
        ));
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    let labels = format!(
        "proxy_id=\"{}\",result=\"{}\",direction=\"{}\",io_side=\"{}\",error_class=\"{}\"",
        proxy_id, key.result, key.direction, key.io_side, key.error_class
    );
    output.push_str(&format!(
        "ferrum_websocket_session_duration_ms_bucket{{{},le=\"+Inf\"{}}} {}\n",
        labels, ns_label, total_count
    ));
    output.push_str(&format!(
        "ferrum_websocket_session_duration_ms_sum{{{}{}}} {:.2}\n",
        labels, ns_label, sum
    ));
    output.push_str(&format!(
        "ferrum_websocket_session_duration_ms_count{{{}{}}} {}\n",
        labels, ns_label, total_count
    ));
}

fn render_tls_source_fetch_histogram(
    output: &mut String,
    key: &TlsSourceFetchKey,
    histogram: &HistogramBuckets,
    ns_label: &str,
) {
    let scheme = escape_label_value(&key.scheme);
    let kind = escape_label_value(&key.kind);
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let count = histogram.counts[i].load(Ordering::Relaxed);
        output.push_str(&format!(
            "ferrum_tls_source_fetch_duration_seconds_bucket{{scheme=\"{}\",kind=\"{}\",le=\"{}\"{}}} {}\n",
            scheme, kind, boundary, ns_label, count
        ));
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    output.push_str(&format!(
        "ferrum_tls_source_fetch_duration_seconds_bucket{{scheme=\"{}\",kind=\"{}\",le=\"+Inf\"{}}} {}\n",
        scheme, kind, ns_label, total_count
    ));
    output.push_str(&format!(
        "ferrum_tls_source_fetch_duration_seconds_sum{{scheme=\"{}\",kind=\"{}\"{}}} {:.6}\n",
        scheme, kind, ns_label, sum
    ));
    output.push_str(&format!(
        "ferrum_tls_source_fetch_duration_seconds_count{{scheme=\"{}\",kind=\"{}\"{}}} {}\n",
        scheme, kind, ns_label, total_count
    ));
}

pub struct PrometheusMetrics {
    registry: Arc<MetricsRegistry>,
}

fn optional_u64(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("prometheus_metrics: '{key}' must be an unsigned integer")),
        None => Ok(default),
    }
}

impl PrometheusMetrics {
    pub fn new(config: &Value, namespace: &str) -> Result<Self, String> {
        if !(config.is_object() || config.is_null()) {
            return Err("prometheus_metrics: config must be an object".to_string());
        }
        if config.get("schema").is_some() || config.get("schema_ref").is_some() {
            return Err(
                "prometheus_metrics: 'schema' / 'schema_ref' is not supported \
                 (transaction-log schema customization applies only to log-shipping plugins; \
                 see docs/plugins.md)"
                    .to_string(),
            );
        }

        let registry = global_registry();

        let render_cache_ttl_secs = optional_u64(
            config,
            "render_cache_ttl_seconds",
            DEFAULT_RENDER_CACHE_TTL_SECS,
        )?;
        let stale_entry_ttl_secs = optional_u64(
            config,
            "stale_entry_ttl_seconds",
            DEFAULT_STALE_TTL_NANOS / 1_000_000_000,
        )?;
        let cache_invalidation_min_age_ms = optional_u64(
            config,
            "cache_invalidation_min_age_ms",
            DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS / 1_000_000,
        )?;

        registry.configure(
            render_cache_ttl_secs,
            stale_entry_ttl_secs,
            cache_invalidation_min_age_ms,
            namespace,
        );

        Ok(Self { registry })
    }
}

#[async_trait]
impl Plugin for PrometheusMetrics {
    fn name(&self) -> &str {
        "prometheus_metrics"
    }

    fn priority(&self) -> u16 {
        super::priority::PROMETHEUS_METRICS
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.registry.record_stream(summary);
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.registry.record_ws_session(ctx);
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.registry.record(summary);
    }

    async fn log_with_mesh_key(
        &self,
        summary: &TransactionSummary,
        mesh_key: Option<&MeshRequestKey>,
    ) {
        self.registry.record_with_mesh_key(summary, mesh_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::inventory::{
        TlsInventory, TlsInventoryEntry, TlsInventorySource, TlsInventoryState, TlsInventoryUsage,
    };
    use std::collections::HashMap;

    fn mesh_summary() -> TransactionSummary {
        TransactionSummary {
            proxy_id: Some("orders".to_string()),
            proxy_name: Some("orders".to_string()),
            response_status_code: 200,
            latency_total_ms: 12.0,
            metadata: HashMap::from([
                ("mesh.source.workload".to_string(), "frontend".to_string()),
                (
                    "mesh.destination.workload".to_string(),
                    "orders".to_string(),
                ),
            ]),
            ..TransactionSummary::default()
        }
    }

    fn test_inventory(
        not_before: chrono::DateTime<Utc>,
        not_after: chrono::DateTime<Utc>,
    ) -> TlsInventory {
        TlsInventory {
            entries: vec![TlsInventoryEntry {
                id: "certificate-test".to_string(),
                material_kind: "certificate".to_string(),
                source: TlsInventorySource {
                    kind: "file".to_string(),
                    identifier: "/tmp/cert.pem".to_string(),
                    refreshable: true,
                    version: None,
                },
                state: TlsInventoryState::Loaded,
                used_by: vec![TlsInventoryUsage {
                    surface: "frontend_tls".to_string(),
                    role: "server_certificate".to_string(),
                    resource_type: "env".to_string(),
                    resource_id: "runtime".to_string(),
                    field: "FERRUM_FRONTEND_TLS_CERT".to_string(),
                }],
                subject: Some("CN=localhost".to_string()),
                issuer: Some("CN=localhost".to_string()),
                sans: vec!["dns:localhost".to_string()],
                not_before: Some(not_before),
                not_after: Some(not_after),
                days_until_expiry: Some(30),
                fingerprint_sha256: Some("abc123".to_string()),
                certificate_count: Some(1),
                crl_count: None,
                error: None,
            }],
        }
    }

    #[test]
    fn renders_tls_certificate_inventory_gauges() {
        let registry = MetricsRegistry::new();
        let not_before = Utc::now() - chrono::Duration::days(1);
        let not_after = Utc::now() + chrono::Duration::days(30);
        let inventory = test_inventory(not_before, not_after);

        registry.refresh_tls_certificate_inventory(&inventory);
        let output = registry.render_uncached();

        assert!(output.contains("ferrum_tls_cert_expiry_seconds"));
        assert!(output.contains("ferrum_tls_cert_not_before_seconds"));
        assert!(output.contains("cert_id=\"certificate-test\""));
        assert!(output.contains("surface=\"frontend_tls\""));
        assert!(output.contains("source_kind=\"file\""));
    }

    #[test]
    fn unchanged_tls_inventory_preserves_render_cache() {
        let registry = MetricsRegistry::new();
        let inventory = test_inventory(
            Utc::now() - chrono::Duration::days(1),
            Utc::now() + chrono::Duration::days(30),
        );
        registry.refresh_tls_certificate_inventory(&inventory);
        let _ = registry.render();
        let before = registry.render_cache.load_full();

        registry.refresh_tls_certificate_inventory(&inventory);
        let after = registry.render_cache.load_full();

        assert!(Arc::ptr_eq(&before, &after));
        assert!(after.is_some());
    }

    #[test]
    fn changed_or_removed_tls_inventory_invalidates_render_cache() {
        let registry = MetricsRegistry::new();
        let mut inventory = test_inventory(
            Utc::now() - chrono::Duration::days(1),
            Utc::now() + chrono::Duration::days(30),
        );
        registry.refresh_tls_certificate_inventory(&inventory);
        let _ = registry.render();

        inventory.entries[0].not_after = Some(Utc::now() + chrono::Duration::days(60));
        registry.refresh_tls_certificate_inventory(&inventory);
        assert!(registry.render_cache.load().is_none());

        let _ = registry.render();
        registry.refresh_tls_certificate_inventory(&TlsInventory {
            entries: Vec::new(),
        });
        assert!(registry.render_cache.load().is_none());
        assert!(registry.tls_cert_gauges.is_empty());
    }

    #[test]
    fn recording_while_cache_is_invalid_does_not_replace_empty_arc() {
        let registry = MetricsRegistry::new();
        let before = registry.render_cache.load_full();
        registry.record_rate_limit_exceeded();
        let after = registry.render_cache.load_full();

        assert!(Arc::ptr_eq(&before, &after));
        assert!(after.is_none());
    }

    #[test]
    fn renders_tls_source_refresh_counters() {
        let registry = MetricsRegistry::new();
        registry.record_tls_source_refresh("file", "cert", "proxy_https", "rotated");

        let output = registry.render_uncached();

        assert!(output.contains("ferrum_tls_source_refresh_total"));
        assert!(output.contains("scheme=\"file\""));
        assert!(output.contains("kind=\"cert\""));
        assert!(output.contains("surface=\"proxy_https\""));
        assert!(output.contains("outcome=\"rotated\""));
    }

    #[test]
    fn renders_tls_source_fetch_metrics() {
        let registry = MetricsRegistry::new();
        registry.record_tls_source_fetch_duration("vault", "cert", 0.042);
        registry.record_tls_source_fetch_failure("vault", "cert", "secret");

        let output = registry.render_uncached();

        assert!(output.contains("ferrum_tls_source_fetch_duration_seconds_bucket"));
        assert!(output.contains("ferrum_tls_source_fetch_duration_seconds_sum"));
        assert!(output.contains("ferrum_tls_source_fetch_failures_total"));
        assert!(output.contains("scheme=\"vault\""));
        assert!(output.contains("kind=\"cert\""));
        assert!(output.contains("reason=\"secret\""));
    }

    #[test]
    fn renders_tls_cert_rotation_counters() {
        let registry = MetricsRegistry::new();
        registry.record_tls_cert_rotation("cert-a", "source_refresh", "success");

        let output = registry.render_uncached();

        assert!(output.contains("ferrum_tls_cert_rotations_total"));
        assert!(output.contains("cert_id=\"cert-a\""));
        assert!(output.contains("reason=\"source_refresh\""));
        assert!(output.contains("outcome=\"success\""));
    }

    #[test]
    fn disabled_mesh_metric_families_stop_recording_independently() {
        let registry = MetricsRegistry::new();
        let mut summary = mesh_summary();
        summary.metadata.insert(
            prometheus_helpers::MESH_METRICS_DISABLED_METADATA.to_string(),
            "request_count".to_string(),
        );

        registry.record(&summary);

        assert!(registry.mesh_request_counter.is_empty());
        assert_eq!(registry.mesh_request_duration_buckets.len(), 1);

        let registry = MetricsRegistry::new();
        summary.metadata.insert(
            prometheus_helpers::MESH_METRICS_DISABLED_METADATA.to_string(),
            "request_duration".to_string(),
        );
        registry.record(&summary);
        assert_eq!(registry.mesh_request_counter.len(), 1);
        assert!(registry.mesh_request_duration_buckets.is_empty());
    }

    #[test]
    fn metric_overrides_change_only_the_selected_rendered_family() {
        let registry = MetricsRegistry::new();
        let mut summary = mesh_summary();
        summary.metadata.insert(
            prometheus_helpers::MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
            "s0,4:edge;r11;".to_string(),
        );

        registry.record(&summary);
        let output = registry.render_uncached();
        let counter = output
            .lines()
            .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
            .expect("mesh request counter");
        let duration = output
            .lines()
            .find(|line| line.starts_with("ferrum_mesh_request_duration_ms_count{"))
            .expect("mesh duration count");

        assert!(counter.contains("source_workload=\"edge\""), "{counter}");
        assert!(!counter.contains("response_flags="), "{counter}");
        assert!(
            duration.contains("source_workload=\"frontend\""),
            "{duration}"
        );
        assert!(duration.contains("response_flags="), "{duration}");
    }

    #[test]
    fn reenabled_mesh_metric_records_subsequent_transactions() {
        let registry = MetricsRegistry::new();
        let mut disabled = mesh_summary();
        disabled.metadata.insert(
            prometheus_helpers::MESH_METRICS_DISABLED_METADATA.to_string(),
            "request_count".to_string(),
        );
        registry.record(&disabled);
        registry.record(&mesh_summary());

        assert_eq!(registry.mesh_request_counter.len(), 1);
        assert_eq!(
            registry
                .mesh_request_counter
                .iter()
                .next()
                .expect("mesh counter")
                .value()
                .value
                .load(Ordering::Relaxed),
            1
        );
    }
}
