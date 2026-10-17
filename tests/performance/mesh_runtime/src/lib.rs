//! Shared latency/throughput accounting for the mesh-runtime benchmark.
//!
//! The report shape mirrors the per-cell JSON written by
//! `tests/performance/multi_protocol/run_gateway_protocol_bench.sh`
//! (`gateway`, `protocol`, `payload_size`, `rps`, `latency_avg_us`,
//! `p50_us`, `p99_us`, `total_errors`) so the same summarizer conventions
//! apply. `mesh` duplicates `gateway` under the mesh-runtime name.

use hdrhistogram::Histogram;
use serde::Serialize;

pub struct BenchMetrics {
    histogram: Histogram<u64>,
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_bytes: u64,
}

impl Default for BenchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchMetrics {
    pub fn new() -> Self {
        Self {
            histogram: Histogram::new_with_max(60_000_000, 3)
                .unwrap_or_else(|_| Histogram::new(3).unwrap()),
            total_requests: 0,
            total_errors: 0,
            total_bytes: 0,
        }
    }

    pub fn record(&mut self, latency_us: u64, bytes: usize) {
        let _ = self.histogram.record(latency_us);
        self.total_requests += 1;
        self.total_bytes += bytes as u64;
    }

    pub fn record_error(&mut self) {
        self.total_errors += 1;
    }

    pub fn merge(&mut self, other: &BenchMetrics) {
        let _ = self.histogram.add(&other.histogram);
        self.total_requests += other.total_requests;
        self.total_errors += other.total_errors;
        self.total_bytes += other.total_bytes;
    }

    pub fn json(
        &self,
        mesh: &str,
        target: &str,
        concurrency: u64,
        duration_secs: u64,
        payload_size: usize,
    ) -> BenchReport {
        let rps = if duration_secs > 0 {
            self.total_requests as f64 / duration_secs as f64
        } else {
            0.0
        };
        BenchReport {
            gateway: mesh.to_string(),
            mesh: mesh.to_string(),
            protocol: "http1".to_string(),
            target: target.to_string(),
            concurrency,
            duration_secs,
            payload_size,
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            rps,
            latency_avg_us: self.histogram.mean() as u64,
            p50_us: self.histogram.value_at_quantile(0.50),
            p95_us: self.histogram.value_at_quantile(0.95),
            p99_us: self.histogram.value_at_quantile(0.99),
            latency_max_us: self.histogram.max(),
            total_bytes: self.total_bytes,
        }
    }
}

#[derive(Serialize)]
pub struct BenchReport {
    pub gateway: String,
    pub mesh: String,
    pub protocol: String,
    pub target: String,
    pub concurrency: u64,
    pub duration_secs: u64,
    pub payload_size: usize,
    pub total_requests: u64,
    pub total_errors: u64,
    pub rps: f64,
    pub latency_avg_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub latency_max_us: u64,
    pub total_bytes: u64,
}
