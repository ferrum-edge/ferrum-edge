//! API Chargeback Plugin
//!
//! Tracks per-consumer API usage charges across three pricing dimensions:
//!
//! 1. **Per-call pricing** keyed by HTTP status code (`pricing_tiers`) — used
//!    for HTTP-family transactions (HTTP/1.1, H2, H3, gRPC, WebSocket upgrades).
//! 2. **Bandwidth pricing** keyed by direction (`bandwidth_pricing`) — applied
//!    to both HTTP-family transactions and stream transactions (TCP, TCP+TLS,
//!    UDP, DTLS) using the gateway-perspective `bytes_sent` / `bytes_received`
//!    counters that the unified [`TransactionSummary`] /
//!    [`StreamTransactionSummary`] schema exposes.
//! 3. **Per-connection pricing** for stream sessions (`stream_connection_pricing`).
//!    Streams have no HTTP status code so they cannot use `pricing_tiers`; this
//!    knob charges a flat fee per stream session at disconnect time.
//!
//! Charges accumulate in-memory via a global singleton registry and are exposed
//! via the admin `/charges` endpoint in both Prometheus and JSON formats for
//! external billing system integration. Only requests with an identified
//! consumer (or authenticated identity) are charged — anonymous traffic is not
//! tracked.
//!
//! **Hot-path optimization**: The recording methods use a thread-local `String`
//! buffer for the DashMap lookup key, achieving **zero heap allocation on cache
//! hits** (99%+ of requests). Only the first record per unique
//! (consumer, proxy, status_code) combination allocates — subsequent records
//! reuse the existing DashMap entry via a read-lock `get()` on a borrowed `&str`.
//! Stream entries use a `status_code` sentinel of `0` to share the same key
//! format and code path.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};
use crate::plugins::chargeback::pricing::PricingConfig;

/// Global chargeback registry (singleton per process).
static CHARGEBACK_REGISTRY: OnceLock<Arc<ChargebackRegistry>> = OnceLock::new();

pub fn global_registry() -> Arc<ChargebackRegistry> {
    CHARGEBACK_REGISTRY
        .get_or_init(|| Arc::new(ChargebackRegistry::new()))
        .clone()
}

fn escape_label_value(value: &str) -> String {
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

/// Protocol family of a recorded entry. Stored on `ChargebackEntry` so the
/// render path can label HTTP and stream activity distinctly without re-parsing
/// the entry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFamily {
    Http,
    Stream,
}

impl ProtocolFamily {
    fn label(&self) -> &'static str {
        match self {
            ProtocolFamily::Http => "http",
            ProtocolFamily::Stream => "stream",
        }
    }
}

/// Atomic chargeback entry. Tracks call counts, per-call charges, bandwidth
/// counters (bytes + monetary), staleness, and render metadata.
///
/// The `consumer`, `proxy_id`, `proxy_name`, `status_code`, and
/// `protocol_family` fields are set once on creation and read during render.
/// They are NOT in the DashMap key (which is a plain `String`) — this allows
/// the hot-path `get()` to use a borrowed `&str` from a thread-local buffer
/// with zero allocation.
///
/// For stream entries the `status_code` is `0` and there is exactly one entry
/// per `(consumer, proxy_id)` (streams have no HTTP status).
pub struct ChargebackEntry {
    pub call_count: AtomicU64,
    /// Accumulated per-call (transaction or stream-session) charge, stored as
    /// the u64 bits of an f64.
    pub charge_total_bits: AtomicU64,
    /// Bytes the gateway sent onward toward the backend on the client's behalf
    /// (request body for HTTP, client→backend half of a stream relay).
    pub bytes_sent_total: AtomicU64,
    /// Bytes the gateway received from the backend and forwarded to the client
    /// (response body for HTTP, backend→client half of a stream relay).
    pub bytes_received_total: AtomicU64,
    /// Accumulated bandwidth charge for client→backend bytes, f64 bits.
    pub bandwidth_charge_sent_bits: AtomicU64,
    /// Accumulated bandwidth charge for backend→client bytes, f64 bits.
    pub bandwidth_charge_received_bits: AtomicU64,
    pub last_updated: AtomicU64,
    // --- Render metadata (immutable after creation) ---
    pub consumer: Arc<str>,
    pub proxy_id: Arc<str>,
    pub proxy_name: Arc<str>,
    pub status_code: u16,
    pub protocol_family: ProtocolFamily,
}

impl ChargebackEntry {
    fn new(
        epoch: Instant,
        consumer: Arc<str>,
        proxy_id: Arc<str>,
        proxy_name: Arc<str>,
        status_code: u16,
        protocol_family: ProtocolFamily,
    ) -> Self {
        Self {
            call_count: AtomicU64::new(0),
            charge_total_bits: AtomicU64::new(0f64.to_bits()),
            bytes_sent_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            bandwidth_charge_sent_bits: AtomicU64::new(0f64.to_bits()),
            bandwidth_charge_received_bits: AtomicU64::new(0f64.to_bits()),
            last_updated: AtomicU64::new(epoch.elapsed().as_nanos() as u64),
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            protocol_family,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
        count_call: bool,
        epoch: Instant,
    ) {
        if count_call {
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }
        if call_price > 0.0 {
            add_f64_atomic(&self.charge_total_bits, call_price);
        }
        if bytes_sent > 0 {
            self.bytes_sent_total
                .fetch_add(bytes_sent, Ordering::Relaxed);
            if bw_price_sent > 0.0 {
                let charge = bytes_sent as f64 * bw_price_sent;
                add_f64_atomic(&self.bandwidth_charge_sent_bits, charge);
            }
        }
        if bytes_received > 0 {
            self.bytes_received_total
                .fetch_add(bytes_received, Ordering::Relaxed);
            if bw_price_received > 0.0 {
                let charge = bytes_received as f64 * bw_price_received;
                add_f64_atomic(&self.bandwidth_charge_received_bits, charge);
            }
        }
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// CAS loop to atomically add `delta` to an f64 stored as u64 bits.
fn add_f64_atomic(slot: &AtomicU64, delta: f64) {
    loop {
        let old = slot.load(Ordering::Relaxed);
        let new_val = f64::from_bits(old) + delta;
        match slot.compare_exchange_weak(
            old,
            new_val.to_bits(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
}

/// Default stale entry TTL: 1 hour in nanoseconds.
const DEFAULT_STALE_TTL_NANOS: u64 = 3_600_000_000_000;

/// Default render cache TTL: 5 seconds.
const DEFAULT_RENDER_CACHE_TTL_SECS: u64 = 5;

/// Default minimum cache age (in nanoseconds) before record() will invalidate.
const DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS: u64 = 500_000_000; // 500ms

/// Sentinel `status_code` for stream entries (TCP/UDP/DTLS). HTTP status codes
/// are always in the 100..=599 range so `0` cannot collide.
const STREAM_STATUS_SENTINEL: u16 = 0;

/// Chargeback registry holding per-consumer, per-proxy charge accumulators.
///
/// **Key design**: The DashMap uses plain `String` keys formatted as
/// `"consumer|proxy_id|status_code"`. Render metadata (consumer, proxy_id,
/// proxy_name, status_code, protocol_family) is stored in the `ChargebackEntry`
/// value. This allows the hot-path recording methods to use
/// `DashMap::get(&str)` with a thread-local buffer — zero allocation on cache
/// hits. Only the cold path (first record per unique combination) allocates a
/// `String` key and `Arc<str>` metadata. This matches the connection pool key
/// pattern in `connection_pool.rs`.
pub struct ChargebackRegistry {
    epoch: Instant,
    pub entries: DashMap<String, ChargebackEntry>,
    /// Currency label (e.g., "USD", "EUR"). Set by the first plugin instance.
    currency: ArcSwap<String>,
    /// Cached render output with generation timestamp.
    prometheus_cache: ArcSwap<Option<(Instant, String)>>,
    json_cache: ArcSwap<Option<(Instant, String)>>,
    render_cache_ttl_secs: AtomicU64,
    stale_entry_ttl_nanos: AtomicU64,
    cache_invalidation_min_age_nanos: AtomicU64,
    /// Extra label fragment for namespace isolation.
    namespace_label: std::sync::RwLock<String>,
    /// Guards against spawning duplicate background cleanup tasks.
    cleanup_task_started: AtomicBool,
}

impl Default for ChargebackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChargebackRegistry {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            entries: DashMap::new(),
            currency: ArcSwap::from_pointee("USD".to_string()),
            prometheus_cache: ArcSwap::from_pointee(None),
            json_cache: ArcSwap::from_pointee(None),
            render_cache_ttl_secs: AtomicU64::new(DEFAULT_RENDER_CACHE_TTL_SECS),
            stale_entry_ttl_nanos: AtomicU64::new(DEFAULT_STALE_TTL_NANOS),
            cache_invalidation_min_age_nanos: AtomicU64::new(
                DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS,
            ),
            namespace_label: std::sync::RwLock::new(String::new()),
            cleanup_task_started: AtomicBool::new(false),
        }
    }

    pub fn configure(
        &self,
        currency: &str,
        render_cache_ttl_secs: u64,
        stale_entry_ttl_secs: u64,
        cache_invalidation_min_age_ms: u64,
        namespace: &str,
    ) {
        self.currency.store(Arc::new(currency.to_string()));
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
        if let Ok(mut ns_label) = self.namespace_label.write() {
            *ns_label = format!(",namespace=\"{}\"", escape_label_value(namespace));
        }
    }

    /// Start a background task that periodically evicts stale entries.
    /// Uses `compare_exchange` to ensure only one cleanup task runs per registry.
    /// Guard with `Handle::try_current()` so `new()` works in non-tokio test contexts.
    pub fn start_cleanup_task(self: &Arc<Self>, interval_seconds: u64) {
        if interval_seconds == 0 {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return; // No tokio runtime (e.g., unit tests)
        }
        if self
            .cleanup_task_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return; // Already started by another plugin instance
        }
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(interval_seconds));
            loop {
                timer.tick().await;
                let ttl_nanos = registry.stale_entry_ttl_nanos.load(Ordering::Relaxed);
                registry.evict_stale(ttl_nanos);
            }
        });
    }

    /// Record a chargeable HTTP-family transaction (HTTP/1.1, H2, H3, gRPC,
    /// WebSocket upgrade). Status code is the response status.
    #[allow(clippy::too_many_arguments)]
    pub fn record_http(
        &self,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            consumer,
            proxy_id,
            proxy_name,
            status_code,
            ProtocolFamily::Http,
            call_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            true,
        );
    }

    /// Record a chargeable stream session (TCP, TCP+TLS, UDP, DTLS). Streams
    /// have no HTTP status code; entries are keyed by `(consumer, proxy_id)`
    /// with the [`STREAM_STATUS_SENTINEL`].
    #[allow(clippy::too_many_arguments)]
    pub fn record_stream(
        &self,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        connection_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            consumer,
            proxy_id,
            proxy_name,
            STREAM_STATUS_SENTINEL,
            ProtocolFamily::Stream,
            connection_price,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            true,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_websocket_bandwidth(
        &self,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
    ) {
        self.record_inner(
            consumer,
            proxy_id,
            proxy_name,
            STREAM_STATUS_SENTINEL,
            ProtocolFamily::Http,
            0.0,
            bytes_sent,
            bytes_received,
            bw_price_sent,
            bw_price_received,
            false,
        );
    }

    /// Shared hot-path implementation behind `record_http` / `record_stream`.
    ///
    /// **Hot-path (cache hit)**: Uses `DashMap::get(&str)` with a thread-local
    /// buffer — one `write!` into a pre-allocated `String`, one DashMap read-lock,
    /// a handful of atomic operations. Zero heap allocation.
    ///
    /// **Cold-path (first record per unique combination)**: Allocates the `String`
    /// key, three `Arc<str>` for render metadata, and a new `ChargebackEntry`.
    /// This runs once per unique `(consumer, proxy, status_code)` combination
    /// (per `(consumer, proxy)` for streams).
    #[allow(clippy::too_many_arguments)]
    fn record_inner(
        &self,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        protocol_family: ProtocolFamily,
        call_price: f64,
        bytes_sent: u64,
        bytes_received: u64,
        bw_price_sent: f64,
        bw_price_received: f64,
        count_call: bool,
    ) {
        thread_local! {
            static KEY_BUF: std::cell::RefCell<String> =
                std::cell::RefCell::new(String::with_capacity(128));
        }

        // Fast path: build key in thread-local buffer, look up with borrowed &str.
        // DashMap::get takes &Q where String: Borrow<Q>, so &str works directly.
        let hit = KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let _ = write!(buf, "{}|{}|{}", consumer, proxy_id, status_code);

            if let Some(entry) = self.entries.get(buf.as_str()) {
                entry.record(
                    if count_call { call_price } else { 0.0 },
                    bytes_sent,
                    bytes_received,
                    bw_price_sent,
                    bw_price_received,
                    count_call,
                    self.epoch,
                );
                return true;
            }
            false
        });

        if !hit {
            // Cold path: allocate owned key + metadata for DashMap insertion.
            let owned_key = format!("{}|{}|{}", consumer, proxy_id, status_code);
            self.entries
                .entry(owned_key)
                .or_insert_with(|| {
                    ChargebackEntry::new(
                        self.epoch,
                        Arc::from(consumer),
                        Arc::from(proxy_id),
                        Arc::from(proxy_name),
                        status_code,
                        protocol_family,
                    )
                })
                .record(
                    if count_call { call_price } else { 0.0 },
                    bytes_sent,
                    bytes_received,
                    bw_price_sent,
                    bw_price_received,
                    count_call,
                    self.epoch,
                );
        }

        self.maybe_invalidate_caches();
    }

    fn maybe_invalidate_caches(&self) {
        let min_age_nanos = self
            .cache_invalidation_min_age_nanos
            .load(Ordering::Relaxed);

        let cached = self.prometheus_cache.load();
        if let Some((generated_at, _)) = **cached {
            let age_nanos = generated_at.elapsed().as_nanos() as u64;
            if age_nanos < min_age_nanos {
                return;
            }
        }
        self.prometheus_cache.store(Arc::new(None));
        self.json_cache.store(Arc::new(None));
    }

    pub fn evict_stale(&self, ttl_nanos: u64) -> usize {
        let mut evicted = 0;
        self.entries.retain(|_, v| {
            let keep = v.nanos_since_update(self.epoch) < ttl_nanos;
            if !keep {
                evicted += 1;
            }
            keep
        });
        if evicted > 0 {
            self.prometheus_cache.store(Arc::new(None));
            self.json_cache.store(Arc::new(None));
        }
        evicted
    }

    /// Render in Prometheus exposition format with caching.
    pub fn render_prometheus(&self) -> String {
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let cached = self.prometheus_cache.load();
        if let Some((generated_at, ref output)) = **cached
            && generated_at.elapsed().as_secs() < ttl_secs
        {
            return output.clone();
        }

        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        let output = self.render_prometheus_uncached();
        self.prometheus_cache
            .store(Arc::new(Some((Instant::now(), output.clone()))));
        output
    }

    pub fn render_prometheus_uncached(&self) -> String {
        let currency = self.currency.load();
        let ns_label = self
            .namespace_label
            .read()
            .map(|l| l.clone())
            .unwrap_or_default();

        // Multiple counter families × ~200 bytes per entry
        let estimated_cap = 1024 + self.entries.len() * 600;
        let mut output = String::with_capacity(estimated_cap);

        // --- Per-call metrics (HTTP entries only — streams have no status code) ---

        output.push_str(
            "# HELP ferrum_api_chargeable_calls_total Total chargeable HTTP-family API calls per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeable_calls_total counter\n");
        for entry in self.entries.iter() {
            let v = entry.value();
            if v.protocol_family != ProtocolFamily::Http {
                continue;
            }
            let count = v.call_count.load(Ordering::Relaxed);
            output.push_str(&format!(
                "ferrum_api_chargeable_calls_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\"{}}} {}\n",
                escape_label_value(&v.consumer),
                escape_label_value(&v.proxy_id),
                escape_label_value(&v.proxy_name),
                v.status_code,
                ns_label,
                count
            ));
        }

        output.push_str(
            "# HELP ferrum_api_charges_total Total per-call charges accumulated per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_charges_total counter\n");
        for entry in self.entries.iter() {
            let v = entry.value();
            if v.protocol_family != ProtocolFamily::Http {
                continue;
            }
            let charge = f64::from_bits(v.charge_total_bits.load(Ordering::Relaxed));
            output.push_str(&format!(
                "ferrum_api_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\",currency=\"{}\"{}}} {:.10}\n",
                escape_label_value(&v.consumer),
                escape_label_value(&v.proxy_id),
                escape_label_value(&v.proxy_name),
                v.status_code,
                escape_label_value(&currency),
                ns_label,
                charge
            ));
        }

        // --- Stream connection metrics (stream entries only) ---

        output.push_str(
            "# HELP ferrum_api_stream_connections_total Total stream sessions (TCP/UDP/DTLS) per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_stream_connections_total counter\n");
        for entry in self.entries.iter() {
            let v = entry.value();
            if v.protocol_family != ProtocolFamily::Stream {
                continue;
            }
            let count = v.call_count.load(Ordering::Relaxed);
            output.push_str(&format!(
                "ferrum_api_stream_connections_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\"{}}} {}\n",
                escape_label_value(&v.consumer),
                escape_label_value(&v.proxy_id),
                escape_label_value(&v.proxy_name),
                ns_label,
                count
            ));
        }

        output.push_str(
            "# HELP ferrum_api_stream_connection_charges_total Total per-connection charges for stream sessions.\n",
        );
        output.push_str("# TYPE ferrum_api_stream_connection_charges_total counter\n");
        for entry in self.entries.iter() {
            let v = entry.value();
            if v.protocol_family != ProtocolFamily::Stream {
                continue;
            }
            let charge = f64::from_bits(v.charge_total_bits.load(Ordering::Relaxed));
            output.push_str(&format!(
                "ferrum_api_stream_connection_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",currency=\"{}\"{}}} {:.10}\n",
                escape_label_value(&v.consumer),
                escape_label_value(&v.proxy_id),
                escape_label_value(&v.proxy_name),
                escape_label_value(&currency),
                ns_label,
                charge
            ));
        }

        // --- Bandwidth metrics (both HTTP and stream entries, aggregated per
        //     (consumer, proxy_id) so HTTP entries spread across status codes
        //     collapse to one row per direction) ---

        #[derive(Default)]
        struct BandwidthAggregate {
            proxy_name: String,
            protocol_family: Option<ProtocolFamily>,
            bytes_sent: u64,
            bytes_received: u64,
            charge_sent: f64,
            charge_received: f64,
        }

        let mut bw_aggregates: HashMap<(String, String), BandwidthAggregate> = HashMap::new();
        for entry in self.entries.iter() {
            let v = entry.value();
            let agg = bw_aggregates
                .entry((v.consumer.to_string(), v.proxy_id.to_string()))
                .or_default();
            if agg.proxy_name.is_empty() {
                agg.proxy_name = v.proxy_name.to_string();
            }
            agg.protocol_family.get_or_insert(v.protocol_family);
            agg.bytes_sent += v.bytes_sent_total.load(Ordering::Relaxed);
            agg.bytes_received += v.bytes_received_total.load(Ordering::Relaxed);
            agg.charge_sent += f64::from_bits(v.bandwidth_charge_sent_bits.load(Ordering::Relaxed));
            agg.charge_received +=
                f64::from_bits(v.bandwidth_charge_received_bits.load(Ordering::Relaxed));
        }

        output.push_str(
            "# HELP ferrum_api_bytes_sent_total Total bytes the gateway sent client->backend on this consumer's behalf.\n",
        );
        output.push_str("# TYPE ferrum_api_bytes_sent_total counter\n");
        for ((consumer, proxy_id), agg) in &bw_aggregates {
            let family = agg.protocol_family.unwrap_or(ProtocolFamily::Http);
            output.push_str(&format!(
                "ferrum_api_bytes_sent_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",protocol_family=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                family.label(),
                ns_label,
                agg.bytes_sent
            ));
        }

        output.push_str(
            "# HELP ferrum_api_bytes_received_total Total bytes the gateway received backend->client and forwarded to this consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_bytes_received_total counter\n");
        for ((consumer, proxy_id), agg) in &bw_aggregates {
            let family = agg.protocol_family.unwrap_or(ProtocolFamily::Http);
            output.push_str(&format!(
                "ferrum_api_bytes_received_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",protocol_family=\"{}\"{}}} {}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                family.label(),
                ns_label,
                agg.bytes_received
            ));
        }

        output.push_str(
            "# HELP ferrum_api_bandwidth_charges_total Total bandwidth charges per consumer, split by direction.\n",
        );
        output.push_str("# TYPE ferrum_api_bandwidth_charges_total counter\n");
        for ((consumer, proxy_id), agg) in &bw_aggregates {
            let family = agg.protocol_family.unwrap_or(ProtocolFamily::Http);
            output.push_str(&format!(
                "ferrum_api_bandwidth_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",direction=\"sent\",currency=\"{}\",protocol_family=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&currency),
                family.label(),
                ns_label,
                agg.charge_sent
            ));
            output.push_str(&format!(
                "ferrum_api_bandwidth_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",direction=\"received\",currency=\"{}\",protocol_family=\"{}\"{}}} {:.10}\n",
                escape_label_value(consumer),
                escape_label_value(proxy_id),
                escape_label_value(&agg.proxy_name),
                escape_label_value(&currency),
                family.label(),
                ns_label,
                agg.charge_received
            ));
        }

        output
    }

    /// Render as JSON with caching.
    pub fn render_json(&self) -> String {
        let ttl_secs = self.render_cache_ttl_secs.load(Ordering::Relaxed);
        let cached = self.json_cache.load();
        if let Some((generated_at, ref output)) = **cached
            && generated_at.elapsed().as_secs() < ttl_secs
        {
            return output.clone();
        }

        let stale_ttl = self.stale_entry_ttl_nanos.load(Ordering::Relaxed);
        self.evict_stale(stale_ttl);

        let output = self.render_json_uncached();
        self.json_cache
            .store(Arc::new(Some((Instant::now(), output.clone()))));
        output
    }

    pub fn render_json_uncached(&self) -> String {
        let currency = self.currency.load();

        // Nested structure: consumer -> proxy -> {protocol, by_status, stream_summary, bandwidth}
        #[derive(Default)]
        struct ProxyAggregate {
            proxy_name: String,
            protocol_family: Option<ProtocolFamily>,
            by_status: HashMap<u16, (u64, f64)>,
            stream_connections: u64,
            stream_charges: f64,
            bytes_sent: u64,
            bytes_received: u64,
            bandwidth_charge_sent: f64,
            bandwidth_charge_received: f64,
        }

        let mut consumers: HashMap<String, HashMap<String, ProxyAggregate>> = HashMap::new();

        for entry in self.entries.iter() {
            let v = entry.value();
            let calls = v.call_count.load(Ordering::Relaxed);
            let charge = f64::from_bits(v.charge_total_bits.load(Ordering::Relaxed));
            let bytes_sent = v.bytes_sent_total.load(Ordering::Relaxed);
            let bytes_received = v.bytes_received_total.load(Ordering::Relaxed);
            let bw_sent = f64::from_bits(v.bandwidth_charge_sent_bits.load(Ordering::Relaxed));
            let bw_received =
                f64::from_bits(v.bandwidth_charge_received_bits.load(Ordering::Relaxed));

            let proxy_map = consumers.entry(v.consumer.to_string()).or_default();
            let proxy_entry = proxy_map.entry(v.proxy_id.to_string()).or_default();
            proxy_entry.proxy_name = v.proxy_name.to_string();
            proxy_entry.protocol_family.get_or_insert(v.protocol_family);
            proxy_entry.bytes_sent += bytes_sent;
            proxy_entry.bytes_received += bytes_received;
            proxy_entry.bandwidth_charge_sent += bw_sent;
            proxy_entry.bandwidth_charge_received += bw_received;

            match v.protocol_family {
                ProtocolFamily::Http => {
                    proxy_entry.by_status.insert(v.status_code, (calls, charge));
                }
                ProtocolFamily::Stream => {
                    proxy_entry.stream_connections = calls;
                    proxy_entry.stream_charges = charge;
                }
            }
        }

        let mut consumer_objects = serde_json::Map::new();
        for (consumer, proxies) in &consumers {
            let mut total_calls = 0u64;
            let mut total_per_call_charges = 0.0f64;
            let mut total_bandwidth_charges = 0.0f64;
            let mut total_stream_charges = 0.0f64;
            let mut proxy_objects = serde_json::Map::new();

            for (proxy_id, agg) in proxies {
                let mut proxy_per_call_charges = 0.0f64;
                let mut proxy_calls = 0u64;
                let mut status_objects = serde_json::Map::new();

                for (status_code, (calls, charge)) in &agg.by_status {
                    proxy_per_call_charges += charge;
                    proxy_calls += calls;
                    status_objects.insert(
                        status_code.to_string(),
                        serde_json::json!({
                            "calls": calls,
                            "charges": charge,
                        }),
                    );
                }

                // Stream connections also count toward total_calls for headline numbers.
                let proxy_total_calls = proxy_calls + agg.stream_connections;
                let proxy_total_charges = proxy_per_call_charges
                    + agg.stream_charges
                    + agg.bandwidth_charge_sent
                    + agg.bandwidth_charge_received;

                total_calls += proxy_total_calls;
                total_per_call_charges += proxy_per_call_charges;
                total_stream_charges += agg.stream_charges;
                total_bandwidth_charges +=
                    agg.bandwidth_charge_sent + agg.bandwidth_charge_received;

                let mut proxy_obj = serde_json::json!({
                    "proxy_name": agg.proxy_name,
                    "protocol_family":
                        agg.protocol_family.unwrap_or(ProtocolFamily::Http).label(),
                    "total_calls": proxy_total_calls,
                    "total_charges": proxy_total_charges,
                    "by_status": serde_json::Value::Object(status_objects),
                    "bandwidth": {
                        "bytes_sent": agg.bytes_sent,
                        "bytes_received": agg.bytes_received,
                        "charge_sent": agg.bandwidth_charge_sent,
                        "charge_received": agg.bandwidth_charge_received,
                    },
                });
                if let Some(ProtocolFamily::Stream) = agg.protocol_family {
                    proxy_obj["stream"] = serde_json::json!({
                        "connections": agg.stream_connections,
                        "connection_charges": agg.stream_charges,
                    });
                }

                proxy_objects.insert(proxy_id.clone(), proxy_obj);
            }

            consumer_objects.insert(
                consumer.clone(),
                serde_json::json!({
                    "total_calls": total_calls,
                    "total_charges":
                        total_per_call_charges + total_stream_charges + total_bandwidth_charges,
                    "per_call_charges": total_per_call_charges,
                    "stream_connection_charges": total_stream_charges,
                    "bandwidth_charges": total_bandwidth_charges,
                    "proxies": serde_json::Value::Object(proxy_objects),
                }),
            );
        }

        let result = serde_json::json!({
            "currency": currency.as_str(),
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "consumers": serde_json::Value::Object(consumer_objects),
        });

        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
    }
}

pub struct ApiChargeback {
    registry: Arc<ChargebackRegistry>,
    pricing: PricingConfig,
}

fn optional_u64(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("api_chargeback: '{key}' must be an unsigned integer")),
        None => Ok(default),
    }
}

impl ApiChargeback {
    pub fn new(config: &Value, namespace: &str) -> Result<Self, String> {
        if !config.is_object() {
            return Err("api_chargeback: config must be an object".to_string());
        }
        if config.get("schema").is_some() || config.get("schema_ref").is_some() {
            return Err("api_chargeback: 'schema' / 'schema_ref' is not supported \
                 (transaction-log schema customization applies only to log-shipping plugins; \
                 see docs/plugins.md)"
                .to_string());
        }

        let registry = global_registry();

        let currency = match config.get("currency") {
            Some(value) => {
                let currency = value
                    .as_str()
                    .ok_or_else(|| "api_chargeback: 'currency' must be a string".to_string())?
                    .trim();
                if currency.is_empty() {
                    return Err("api_chargeback: 'currency' must not be empty".to_string());
                }
                currency
            }
            None => "USD",
        };

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

        // Validate ALL pricing dimensions before touching the global registry,
        // so a config error never leaves shared state half-mutated.
        let pricing = PricingConfig::from_config(config, "api_chargeback")?;

        if !pricing.has_any_pricing() {
            return Err(
                "api_chargeback: at least one of 'pricing_tiers', 'bandwidth_pricing', or \
                 'stream_connection_pricing' must be configured — the plugin would otherwise \
                 record nothing"
                    .to_string(),
            );
        }

        // Validation passed — now safe to mutate the global registry.
        registry.configure(
            currency,
            render_cache_ttl_secs,
            stale_entry_ttl_secs,
            cache_invalidation_min_age_ms,
            namespace,
        );

        let cleanup_interval_seconds = optional_u64(config, "cleanup_interval_seconds", 300)?;
        registry.start_cleanup_task(cleanup_interval_seconds);

        Ok(Self { registry, pricing })
    }
}

#[async_trait]
impl Plugin for ApiChargeback {
    fn name(&self) -> &str {
        "api_chargeback"
    }

    fn priority(&self) -> u16 {
        super::priority::API_CHARGEBACK
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // Stream protocols (TCP/UDP/DTLS) are now supported via on_stream_disconnect.
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        let Some(charge) = self.pricing.compute_http(
            summary.response_status_code,
            summary.bytes_sent,
            summary.bytes_received,
        ) else {
            return;
        };

        let proxy_id = summary.proxy_id.as_deref().unwrap_or("unknown");
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");

        self.registry.record_http(
            consumer,
            proxy_id,
            proxy_name,
            summary.response_status_code,
            charge.charge_call,
            summary.bytes_sent,
            summary.bytes_received,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        let Some(charge) = self
            .pricing
            .compute_stream(summary.bytes_sent, summary.bytes_received)
        else {
            return;
        };

        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");

        self.registry.record_stream(
            consumer,
            &summary.proxy_id,
            proxy_name,
            charge.charge_call,
            summary.bytes_sent,
            summary.bytes_received,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };
        if self
            .pricing
            .compute_websocket_bandwidth(
                summary.bytes_client_to_backend,
                summary.bytes_backend_to_client,
            )
            .is_none()
        {
            return;
        }
        let proxy_name = summary.proxy_name.as_deref().unwrap_or("unknown");
        self.registry.record_websocket_bandwidth(
            consumer,
            &summary.proxy_id,
            proxy_name,
            summary.bytes_client_to_backend,
            summary.bytes_backend_to_client,
            self.pricing.bandwidth_price_sent,
            self.pricing.bandwidth_price_received,
        );
    }
}
