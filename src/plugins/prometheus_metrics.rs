//! Prometheus Metrics Plugin
//!
//! Records request metrics in Prometheus format. The actual `/metrics`
//! endpoint is served by the admin API (unauthenticated).
//! This plugin uses the `log()` hook to record metrics from TransactionSummary.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Global metrics registry (singleton per process).
static METRICS_REGISTRY: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();

pub fn global_registry() -> Arc<MetricsRegistry> {
    METRICS_REGISTRY
        .get_or_init(|| Arc::new(MetricsRegistry::new()))
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

/// Composite key for request counter: (proxy_id, method, status_code).
/// Uses Arc<str> to avoid heap-allocating cloned strings on every request —
/// DashMap entry() lookups on existing keys only bump a refcount.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterKey {
    pub proxy_id: Arc<str>,
    pub method: Arc<str>,
    pub status_code: u16,
}

/// Composite key for stream connection counter: (proxy_id, protocol).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamCounterKey {
    pub proxy_id: Arc<str>,
    pub protocol: Arc<str>,
}

/// Atomic counter paired with a last-updated timestamp for stale entry eviction.
pub struct TimestampedCounter {
    pub value: AtomicU64,
    pub last_updated: AtomicU64, // Instant encoded as nanos since registry creation
}

impl TimestampedCounter {
    fn new(epoch: Instant) -> Self {
        Self {
            value: AtomicU64::new(0),
            last_updated: AtomicU64::new(epoch.elapsed().as_nanos() as u64),
        }
    }

    fn increment(&self, epoch: Instant) {
        self.value.fetch_add(1, Ordering::Relaxed);
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn nanos_since_update(&self, epoch: Instant) -> u64 {
        let now = epoch.elapsed().as_nanos() as u64;
        let last = self.last_updated.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// Histogram with predefined buckets and a last-updated timestamp.
pub struct HistogramBuckets {
    /// Bucket boundaries in milliseconds
    pub boundaries: Vec<f64>,
    /// Count of observations <= each boundary
    pub counts: Vec<AtomicU64>,
    /// Sum of all observations
    pub sum: std::sync::atomic::AtomicU64, // stored as bits of f64
    /// Total count
    pub count: AtomicU64,
    /// Last-updated timestamp (nanos since registry epoch)
    last_updated: AtomicU64,
}

impl HistogramBuckets {
    fn new(epoch: Instant) -> Self {
        let boundaries = vec![
            5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
        ];
        let counts = boundaries.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            boundaries,
            counts,
            sum: std::sync::atomic::AtomicU64::new(0),
            count: AtomicU64::new(0),
            last_updated: AtomicU64::new(epoch.elapsed().as_nanos() as u64),
        }
    }

    fn observe(&self, value_ms: f64, epoch: Instant) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_updated
            .store(epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
        // Add to sum (using u64 bit representation of f64)
        loop {
            let old = self.sum.load(Ordering::Relaxed);
            let old_f = f64::from_bits(old);
            let new_f = old_f + value_ms;
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
            if value_ms <= *boundary {
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
const RENDER_CACHE_TTL_SECS: u64 = 5;

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
    /// Rate limit exceeded counter
    pub rate_limit_exceeded: AtomicU64,
    /// Stream connections by (proxy_id, protocol)
    pub stream_connection_counter: DashMap<StreamCounterKey, TimestampedCounter>,
    /// Stream connection duration histogram by proxy_id
    pub stream_duration_buckets: DashMap<Arc<str>, HistogramBuckets>,
    /// Cached render output with generation timestamp
    render_cache: ArcSwap<Option<(Instant, String)>>,
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
            rate_limit_exceeded: AtomicU64::new(0),
            stream_connection_counter: DashMap::new(),
            stream_duration_buckets: DashMap::new(),
            render_cache: ArcSwap::from_pointee(None),
        }
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
            .entry(proxy_id)
            .or_insert_with(|| HistogramBuckets::new(self.epoch))
            .observe(summary.duration_ms, self.epoch);

        // Invalidate render cache on new data
        self.render_cache.store(Arc::new(None));
    }

    pub fn record(&self, summary: &TransactionSummary) {
        let proxy_id: Arc<str> =
            Arc::from(summary.matched_proxy_id.as_deref().unwrap_or("unknown"));

        // Increment request counter (composite key — no format!() allocation)
        let counter_key = CounterKey {
            proxy_id: Arc::clone(&proxy_id),
            method: Arc::from(summary.http_method.as_str()),
            status_code: summary.response_status_code,
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

        self.gateway_overhead_buckets
            .entry(proxy_id)
            .or_insert_with(|| HistogramBuckets::new(self.epoch))
            .observe(summary.latency_gateway_overhead_ms, self.epoch);

        // Invalidate render cache on new data
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

        if evicted > 0 {
            // Invalidate render cache after eviction
            self.render_cache.store(Arc::new(None));
        }

        evicted
    }

    /// Render metrics in Prometheus exposition format.
    /// Returns a cached result if the cache is still fresh (within RENDER_CACHE_TTL_SECS).
    /// Also runs lazy stale-entry eviction on each cache miss to bound memory growth.
    pub fn render(&self) -> String {
        // Check cache
        let cached = self.render_cache.load();
        if let Some((generated_at, ref output)) = **cached
            && generated_at.elapsed().as_secs() < RENDER_CACHE_TTL_SECS
        {
            return output.clone();
        }

        // Lazy eviction: piggyback on cache-miss (at most once per RENDER_CACHE_TTL_SECS)
        self.evict_stale(DEFAULT_STALE_TTL_NANOS);

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
            + self.stream_connection_counter.len() * 200
            + self.stream_duration_buckets.len() * 800;
        let mut output = String::with_capacity(estimated_cap);

        // Request counter
        output.push_str("# HELP ferrum_requests_total Total number of requests processed.\n");
        output.push_str("# TYPE ferrum_requests_total counter\n");
        for entry in self.request_counter.iter() {
            let key = entry.key();
            let count = entry.value().value.load(Ordering::Relaxed);
            let proxy_id = escape_label_value(&key.proxy_id);
            let method = escape_label_value(&key.method);
            output.push_str(&format!(
                "ferrum_requests_total{{proxy_id=\"{}\",method=\"{}\",status_code=\"{}\"}} {}\n",
                proxy_id, method, key.status_code, count
            ));
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
            );
        }

        // Rate limit exceeded
        output.push_str("# HELP ferrum_rate_limit_exceeded_total Total rate limit rejections.\n");
        output.push_str("# TYPE ferrum_rate_limit_exceeded_total counter\n");
        output.push_str(&format!(
            "ferrum_rate_limit_exceeded_total {}\n",
            self.rate_limit_exceeded.load(Ordering::Relaxed)
        ));

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
                    "ferrum_stream_connections_total{{proxy_id=\"{}\",protocol=\"{}\"}} {}\n",
                    proxy_id, protocol, count
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
                );
            }
        }

        output
    }
}

/// Render a single histogram's buckets, sum, and count into the output buffer.
fn render_histogram(
    output: &mut String,
    metric_name: &str,
    proxy_id: &str,
    histogram: &HistogramBuckets,
) {
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let count = histogram.counts[i].load(Ordering::Relaxed);
        output.push_str(&format!(
            "{}_bucket{{proxy_id=\"{}\",le=\"{}\"}} {}\n",
            metric_name, proxy_id, boundary, count
        ));
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    output.push_str(&format!(
        "{}_bucket{{proxy_id=\"{}\",le=\"+Inf\"}} {}\n",
        metric_name, proxy_id, total_count
    ));
    output.push_str(&format!(
        "{}_sum{{proxy_id=\"{}\"}} {:.2}\n",
        metric_name, proxy_id, sum
    ));
    output.push_str(&format!(
        "{}_count{{proxy_id=\"{}\"}} {}\n",
        metric_name, proxy_id, total_count
    ));
}

pub struct PrometheusMetrics {
    registry: Arc<MetricsRegistry>,
}

impl PrometheusMetrics {
    pub fn new(_config: &Value) -> Result<Self, String> {
        Ok(Self {
            registry: global_registry(),
        })
    }
}

pub const PROMETHEUS_METRICS_PRIORITY: u16 = 9300;

#[async_trait]
impl Plugin for PrometheusMetrics {
    fn name(&self) -> &str {
        "prometheus_metrics"
    }

    fn priority(&self) -> u16 {
        PROMETHEUS_METRICS_PRIORITY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.registry.record_stream(summary);
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.registry.record(summary);
    }
}
