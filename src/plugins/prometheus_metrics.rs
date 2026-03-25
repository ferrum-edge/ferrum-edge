//! Prometheus Metrics Plugin
//!
//! Records request metrics in Prometheus format. The actual `/metrics`
//! endpoint is served by the admin API (unauthenticated).
//! This plugin uses the `log()` hook to record metrics from TransactionSummary.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::{Plugin, TransactionSummary};

/// Global metrics registry (singleton per process).
static METRICS_REGISTRY: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();

pub fn global_registry() -> Arc<MetricsRegistry> {
    METRICS_REGISTRY
        .get_or_init(|| Arc::new(MetricsRegistry::new()))
        .clone()
}

/// Composite key for request counter: (proxy_id, method, status_code).
/// Avoids `format!()` string allocation on every request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterKey {
    pub proxy_id: String,
    pub method: String,
    pub status_code: u16,
}

/// Metrics registry holding all Prometheus-compatible counters and histograms.
pub struct MetricsRegistry {
    /// Total requests by (proxy_id, method, status_code)
    pub request_counter: DashMap<CounterKey, AtomicU64>,
    /// Request duration histogram buckets by proxy_id
    pub request_duration_buckets: DashMap<String, HistogramBuckets>,
    /// Backend duration histogram buckets by proxy_id
    pub backend_duration_buckets: DashMap<String, HistogramBuckets>,
    /// Rate limit exceeded counter
    pub rate_limit_exceeded: AtomicU64,
}

/// Histogram with predefined buckets.
pub struct HistogramBuckets {
    /// Bucket boundaries in milliseconds
    pub boundaries: Vec<f64>,
    /// Count of observations <= each boundary
    pub counts: Vec<AtomicU64>,
    /// Sum of all observations
    pub sum: std::sync::atomic::AtomicU64, // stored as bits of f64
    /// Total count
    pub count: AtomicU64,
}

impl HistogramBuckets {
    fn new() -> Self {
        let boundaries = vec![
            5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
        ];
        let counts = boundaries.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            boundaries,
            counts,
            sum: std::sync::atomic::AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, value_ms: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
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
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            request_counter: DashMap::new(),
            request_duration_buckets: DashMap::new(),
            backend_duration_buckets: DashMap::new(),
            rate_limit_exceeded: AtomicU64::new(0),
        }
    }

    pub fn record(&self, summary: &TransactionSummary) {
        let proxy_id = summary
            .matched_proxy_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        // Increment request counter (composite key — no format!() allocation)
        let counter_key = CounterKey {
            proxy_id: proxy_id.clone(),
            method: summary.http_method.clone(),
            status_code: summary.response_status_code,
        };
        self.request_counter
            .entry(counter_key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        self.request_duration_buckets
            .entry(proxy_id.clone())
            .or_insert_with(HistogramBuckets::new)
            .observe(summary.latency_total_ms);

        // Guard against sentinel value (-1.0) used for streaming responses
        // where total backend latency is unknown at log time.
        if summary.latency_backend_total_ms >= 0.0 {
            self.backend_duration_buckets
                .entry(proxy_id)
                .or_insert_with(HistogramBuckets::new)
                .observe(summary.latency_backend_total_ms);
        }
    }

    /// Render metrics in Prometheus exposition format.
    pub fn render(&self) -> String {
        let mut output = String::new();

        // Request counter
        output.push_str("# HELP ferrum_requests_total Total number of requests processed.\n");
        output.push_str("# TYPE ferrum_requests_total counter\n");
        for entry in self.request_counter.iter() {
            let key = entry.key();
            let count = entry.value().load(Ordering::Relaxed);
            output.push_str(&format!(
                "ferrum_requests_total{{proxy_id=\"{}\",method=\"{}\",status_code=\"{}\"}} {}\n",
                key.proxy_id, key.method, key.status_code, count
            ));
        }

        // Request duration histogram
        output.push_str("# HELP ferrum_request_duration_ms Request duration in milliseconds.\n");
        output.push_str("# TYPE ferrum_request_duration_ms histogram\n");
        for entry in self.request_duration_buckets.iter() {
            let proxy_id = entry.key();
            let histogram = entry.value();
            for (i, boundary) in histogram.boundaries.iter().enumerate() {
                let count = histogram.counts[i].load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_request_duration_ms_bucket{{proxy_id=\"{}\",le=\"{}\"}} {}\n",
                    proxy_id, boundary, count
                ));
            }
            let total_count = histogram.count.load(Ordering::Relaxed);
            let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
            output.push_str(&format!(
                "ferrum_request_duration_ms_bucket{{proxy_id=\"{}\",le=\"+Inf\"}} {}\n",
                proxy_id, total_count
            ));
            output.push_str(&format!(
                "ferrum_request_duration_ms_sum{{proxy_id=\"{}\"}} {:.2}\n",
                proxy_id, sum
            ));
            output.push_str(&format!(
                "ferrum_request_duration_ms_count{{proxy_id=\"{}\"}} {}\n",
                proxy_id, total_count
            ));
        }

        // Backend duration histogram
        output
            .push_str("# HELP ferrum_backend_duration_ms Backend response time in milliseconds.\n");
        output.push_str("# TYPE ferrum_backend_duration_ms histogram\n");
        for entry in self.backend_duration_buckets.iter() {
            let proxy_id = entry.key();
            let histogram = entry.value();
            for (i, boundary) in histogram.boundaries.iter().enumerate() {
                let count = histogram.counts[i].load(Ordering::Relaxed);
                output.push_str(&format!(
                    "ferrum_backend_duration_ms_bucket{{proxy_id=\"{}\",le=\"{}\"}} {}\n",
                    proxy_id, boundary, count
                ));
            }
            let total_count = histogram.count.load(Ordering::Relaxed);
            let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
            output.push_str(&format!(
                "ferrum_backend_duration_ms_bucket{{proxy_id=\"{}\",le=\"+Inf\"}} {}\n",
                proxy_id, total_count
            ));
            output.push_str(&format!(
                "ferrum_backend_duration_ms_sum{{proxy_id=\"{}\"}} {:.2}\n",
                proxy_id, sum
            ));
            output.push_str(&format!(
                "ferrum_backend_duration_ms_count{{proxy_id=\"{}\"}} {}\n",
                proxy_id, total_count
            ));
        }

        // Rate limit exceeded
        output.push_str("# HELP ferrum_rate_limit_exceeded_total Total rate limit rejections.\n");
        output.push_str("# TYPE ferrum_rate_limit_exceeded_total counter\n");
        output.push_str(&format!(
            "ferrum_rate_limit_exceeded_total {}\n",
            self.rate_limit_exceeded.load(Ordering::Relaxed)
        ));

        output
    }
}

pub struct PrometheusMetrics {
    registry: Arc<MetricsRegistry>,
}

impl PrometheusMetrics {
    pub fn new(_config: &Value) -> Self {
        Self {
            registry: global_registry(),
        }
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

    fn supports_stream_proxy(&self) -> bool {
        true
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.registry.record(summary);
    }
}
