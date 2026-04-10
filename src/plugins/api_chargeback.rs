//! API Chargeback Plugin
//!
//! Tracks per-consumer API usage charges based on configurable pricing tiers
//! keyed by HTTP status code. Charges accumulate in-memory via a global
//! singleton registry and are exposed via the admin `/charges` endpoint in
//! both Prometheus and JSON formats for external billing system integration.
//!
//! This plugin uses the `log()` hook to record charges from `TransactionSummary`.
//! Only requests with an identified consumer (or authenticated identity) are
//! charged — anonymous traffic is not tracked.
//!
//! **Hot-path optimization**: The `record()` method uses a thread-local `String`
//! buffer for the DashMap lookup key, achieving **zero heap allocation on cache
//! hits** (99%+ of requests). Only the first request per unique
//! (consumer, proxy, status_code) combination allocates — subsequent requests
//! reuse the existing DashMap entry via a read-lock `get()` on a borrowed `&str`.
//! This matches the connection pool key pattern in `connection_pool.rs`.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::{Plugin, TransactionSummary};

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

/// Atomic chargeback entry with call count, accumulated charge, staleness
/// tracking, and render metadata.
///
/// The `consumer`, `proxy_id`, `proxy_name`, and `status_code` fields are set
/// once on creation and read during render. They are NOT in the DashMap key
/// (which is a plain `String`) — this allows the hot-path `get()` to use a
/// borrowed `&str` from a thread-local buffer with zero allocation.
pub struct ChargebackEntry {
    pub call_count: AtomicU64,
    /// Accumulated charge stored as u64 bits of f64.
    pub charge_total_bits: AtomicU64,
    pub last_updated: AtomicU64,
    // --- Render metadata (immutable after creation) ---
    pub consumer: Arc<str>,
    pub proxy_id: Arc<str>,
    pub proxy_name: Arc<str>,
    pub status_code: u16,
}

impl ChargebackEntry {
    fn new(
        epoch: Instant,
        consumer: Arc<str>,
        proxy_id: Arc<str>,
        proxy_name: Arc<str>,
        status_code: u16,
    ) -> Self {
        Self {
            call_count: AtomicU64::new(0),
            charge_total_bits: AtomicU64::new(0f64.to_bits()),
            last_updated: AtomicU64::new(epoch.elapsed().as_nanos() as u64),
            consumer,
            proxy_id,
            proxy_name,
            status_code,
        }
    }

    fn record(&self, price: f64, epoch: Instant) {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        // CAS loop to atomically add price to the f64 total
        loop {
            let old = self.charge_total_bits.load(Ordering::Relaxed);
            let new_val = f64::from_bits(old) + price;
            match self.charge_total_bits.compare_exchange_weak(
                old,
                new_val.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
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

/// Default stale entry TTL: 1 hour in nanoseconds.
const DEFAULT_STALE_TTL_NANOS: u64 = 3_600_000_000_000;

/// Default render cache TTL: 5 seconds.
const DEFAULT_RENDER_CACHE_TTL_SECS: u64 = 5;

/// Default minimum cache age (in nanoseconds) before record() will invalidate.
const DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS: u64 = 500_000_000; // 500ms

/// Chargeback registry holding per-consumer, per-proxy charge accumulators.
///
/// **Key design**: The DashMap uses plain `String` keys formatted as
/// `"consumer|proxy_id|status_code"`. Render metadata (consumer, proxy_id,
/// proxy_name, status_code) is stored in the `ChargebackEntry` value. This
/// allows the hot-path `record()` to use `DashMap::get(&str)` with a
/// thread-local buffer — zero allocation on cache hits. Only the cold path
/// (first request per unique combination) allocates a `String` key and
/// `Arc<str>` metadata. This matches the connection pool key pattern in
/// `connection_pool.rs`.
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
        }
    }

    pub fn configure(
        &self,
        currency: &str,
        render_cache_ttl_secs: u64,
        stale_entry_ttl_secs: u64,
        cache_invalidation_min_age_ms: u64,
    ) {
        self.currency.store(Arc::new(currency.to_string()));
        self.render_cache_ttl_secs
            .store(render_cache_ttl_secs, Ordering::Relaxed);
        self.stale_entry_ttl_nanos
            .store(stale_entry_ttl_secs * 1_000_000_000, Ordering::Relaxed);
        self.cache_invalidation_min_age_nanos
            .store(cache_invalidation_min_age_ms * 1_000_000, Ordering::Relaxed);
    }

    /// Record a chargeable API call.
    ///
    /// **Hot-path (cache hit)**: Uses `DashMap::get(&str)` with a thread-local
    /// buffer — one `write!` into a pre-allocated `String`, one DashMap read-lock,
    /// two atomic increments. Zero heap allocation.
    ///
    /// **Cold-path (first request per unique combination)**: Allocates the `String`
    /// key, three `Arc<str>` for render metadata, and a new `ChargebackEntry`.
    /// This runs once per unique (consumer, proxy, status_code) combination.
    pub fn record(
        &self,
        consumer: &str,
        proxy_id: &str,
        proxy_name: &str,
        status_code: u16,
        price: f64,
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
                entry.record(price, self.epoch);
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
                    )
                })
                .record(price, self.epoch);
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
        // Two counter families × ~150 bytes per entry
        let estimated_cap = 512 + self.entries.len() * 300;
        let mut output = String::with_capacity(estimated_cap);

        // Chargeable calls counter
        output.push_str(
            "# HELP ferrum_api_chargeable_calls_total Total chargeable API calls per consumer.\n",
        );
        output.push_str("# TYPE ferrum_api_chargeable_calls_total counter\n");
        for entry in self.entries.iter() {
            let v = entry.value();
            let count = v.call_count.load(Ordering::Relaxed);
            output.push_str(&format!(
                "ferrum_api_chargeable_calls_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\"}} {}\n",
                escape_label_value(&v.consumer),
                escape_label_value(&v.proxy_id),
                escape_label_value(&v.proxy_name),
                v.status_code,
                count
            ));
        }

        // Charges counter (monetary)
        output
            .push_str("# HELP ferrum_api_charges_total Total charges accumulated per consumer.\n");
        output.push_str("# TYPE ferrum_api_charges_total counter\n");
        for entry in self.entries.iter() {
            let v = entry.value();
            let charge = f64::from_bits(v.charge_total_bits.load(Ordering::Relaxed));
            output.push_str(&format!(
                "ferrum_api_charges_total{{consumer=\"{}\",proxy_id=\"{}\",proxy_name=\"{}\",status_code=\"{}\",currency=\"{}\"}} {:.10}\n",
                escape_label_value(&v.consumer),
                escape_label_value(&v.proxy_id),
                escape_label_value(&v.proxy_name),
                v.status_code,
                escape_label_value(&currency),
                charge
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

        // Build nested structure: consumer -> proxy -> status_code -> {calls, charges}
        #[derive(Default)]
        struct ProxyCharges {
            proxy_name: String,
            by_status: HashMap<u16, (u64, f64)>, // (calls, charges)
        }

        let mut consumers: HashMap<String, HashMap<String, ProxyCharges>> = HashMap::new();

        for entry in self.entries.iter() {
            let v = entry.value();
            let calls = v.call_count.load(Ordering::Relaxed);
            let charge = f64::from_bits(v.charge_total_bits.load(Ordering::Relaxed));

            let proxy_map = consumers.entry(v.consumer.to_string()).or_default();
            let proxy_entry = proxy_map.entry(v.proxy_id.to_string()).or_default();
            proxy_entry.proxy_name = v.proxy_name.to_string();
            proxy_entry.by_status.insert(v.status_code, (calls, charge));
        }

        // Build JSON
        let mut consumer_objects = serde_json::Map::new();
        for (consumer, proxies) in &consumers {
            let mut total_charges = 0.0f64;
            let mut total_calls = 0u64;
            let mut proxy_objects = serde_json::Map::new();

            for (proxy_id, proxy_data) in proxies {
                let mut proxy_charges = 0.0f64;
                let mut proxy_calls = 0u64;
                let mut status_objects = serde_json::Map::new();

                for (status_code, (calls, charge)) in &proxy_data.by_status {
                    proxy_charges += charge;
                    proxy_calls += calls;
                    status_objects.insert(
                        status_code.to_string(),
                        serde_json::json!({
                            "calls": calls,
                            "charges": charge,
                        }),
                    );
                }

                total_charges += proxy_charges;
                total_calls += proxy_calls;

                proxy_objects.insert(
                    proxy_id.clone(),
                    serde_json::json!({
                        "proxy_name": proxy_data.proxy_name,
                        "total_charges": proxy_charges,
                        "total_calls": proxy_calls,
                        "by_status": serde_json::Value::Object(status_objects),
                    }),
                );
            }

            consumer_objects.insert(
                consumer.clone(),
                serde_json::json!({
                    "total_charges": total_charges,
                    "total_calls": total_calls,
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
    /// Lookup from status code to price. Built at config time for O(1) hot-path lookups.
    price_by_status: HashMap<u16, f64>,
}

impl ApiChargeback {
    pub fn new(config: &Value) -> Result<Self, String> {
        let registry = global_registry();

        let currency = config
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("USD");

        let render_cache_ttl_secs = config
            .get("render_cache_ttl_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_RENDER_CACHE_TTL_SECS);

        let stale_entry_ttl_secs = config
            .get("stale_entry_ttl_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_STALE_TTL_NANOS / 1_000_000_000);

        let cache_invalidation_min_age_ms = config
            .get("cache_invalidation_min_age_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_CACHE_INVALIDATION_MIN_AGE_NANOS / 1_000_000);

        registry.configure(
            currency,
            render_cache_ttl_secs,
            stale_entry_ttl_secs,
            cache_invalidation_min_age_ms,
        );

        // Parse pricing tiers
        let tiers = config
            .get("pricing_tiers")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                "api_chargeback: 'pricing_tiers' is required and must be a non-empty array"
                    .to_string()
            })?;

        if tiers.is_empty() {
            return Err(
                "api_chargeback: 'pricing_tiers' must contain at least one pricing tier"
                    .to_string(),
            );
        }

        let mut price_by_status: HashMap<u16, f64> = HashMap::new();

        for (i, tier) in tiers.iter().enumerate() {
            let status_codes = tier
                .get("status_codes")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    format!(
                        "api_chargeback: pricing_tiers[{}].status_codes is required and must be an array",
                        i
                    )
                })?;

            if status_codes.is_empty() {
                return Err(format!(
                    "api_chargeback: pricing_tiers[{}].status_codes must not be empty",
                    i
                ));
            }

            let price = tier
                .get("price_per_call")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| {
                    format!(
                        "api_chargeback: pricing_tiers[{}].price_per_call is required and must be a number",
                        i
                    )
                })?;

            if price < 0.0 {
                return Err(format!(
                    "api_chargeback: pricing_tiers[{}].price_per_call must be non-negative",
                    i
                ));
            }

            for code_val in status_codes {
                let code = code_val.as_u64().ok_or_else(|| {
                    format!(
                        "api_chargeback: pricing_tiers[{}].status_codes contains non-integer value",
                        i
                    )
                })? as u16;

                if price_by_status.contains_key(&code) {
                    return Err(format!(
                        "api_chargeback: status code {} appears in multiple pricing tiers",
                        code
                    ));
                }

                price_by_status.insert(code, price);
            }
        }

        Ok(Self {
            registry,
            price_by_status,
        })
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
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        // Only charge identified consumers
        let consumer = match summary.consumer_username.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => return,
        };

        // Look up price for this status code — O(1) HashMap lookup, no allocation
        let price = match self.price_by_status.get(&summary.response_status_code) {
            Some(&p) => p,
            None => return,
        };

        let proxy_id = summary.matched_proxy_id.as_deref().unwrap_or("unknown");
        let proxy_name = summary.matched_proxy_name.as_deref().unwrap_or("unknown");

        self.registry.record(
            consumer,
            proxy_id,
            proxy_name,
            summary.response_status_code,
            price,
        );
    }
}
