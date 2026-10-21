//! Shared latency/throughput accounting for the mesh-runtime benchmark.
//!
//! The report shape mirrors the per-cell JSON written by
//! `tests/performance/multi_protocol/run_gateway_protocol_bench.sh`
//! (`gateway`, `protocol`, `payload_size`, `rps`, `latency_avg_us`,
//! `p50_us`, `p99_us`, `total_errors`) so the same summarizer conventions
//! apply. `mesh` duplicates `gateway` under the mesh-runtime name.
//! Existing latency fields describe successful completions inside the common
//! measurement window. `cohort_*` latency fields also include successful
//! drains from requests admitted inside that window, exposing their tail.

use hdrhistogram::Histogram;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The coordinator publishes one window to every worker after connection
/// setup and warmup. Both request admission and useful completion accounting
/// use this exact interval; worker scheduling never extends it.
#[derive(Clone, Copy)]
pub struct MeasurementWindow {
    start: Instant,
    deadline: Instant,
}

impl MeasurementWindow {
    pub fn new(start: Instant, duration: Duration) -> Self {
        Self {
            start,
            deadline: start + duration,
        }
    }

    pub fn contains(self, instant: Instant) -> bool {
        self.start <= instant && instant < self.deadline
    }

    pub fn start(self) -> Instant {
        self.start
    }

    pub fn deadline(self) -> Instant {
        self.deadline
    }
}

/// One aggregate, absolute schedule shared by all workers. Claiming a slot
/// never moves its due time, even when previous exchanges were slow. There
/// is no allocated backlog: each worker holds at most one future slot, and
/// all unstarted slots are accounted for at the common admission deadline.
pub struct FixedRateSchedule {
    rate: u64,
    offered_requests: u64,
    next: AtomicU64,
}

impl FixedRateSchedule {
    pub fn new(rate: u64, duration_secs: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=1_000_000_000).contains(&rate),
            "fixed rate must be between 1 and 1000000000 requests/sec"
        );
        let offered_requests = rate
            .checked_mul(duration_secs)
            .ok_or_else(|| anyhow::anyhow!("rate times duration exceeds the request counter"))?;
        Ok(Self {
            rate,
            offered_requests,
            next: AtomicU64::new(0),
        })
    }

    pub fn rate(&self) -> u64 {
        self.rate
    }

    pub fn offered_requests(&self) -> u64 {
        self.offered_requests
    }

    /// Offset from the coordinator's epoch. Integer quotient/remainder
    /// arithmetic avoids accumulating per-request interval rounding drift.
    pub fn claim(&self) -> Option<Duration> {
        let index = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next < self.offered_requests {
                    Some(next + 1)
                } else {
                    None
                }
            })
            .ok()?;
        Some(Duration::new(
            index / self.rate,
            ((index % self.rate) * 1_000_000_000 / self.rate) as u32,
        ))
    }
}

pub struct BenchMetrics {
    histogram: Histogram<u64>,
    cohort_histogram: Histogram<u64>,
    scheduled_histogram: Histogram<u64>,
    cohort_scheduled_histogram: Histogram<u64>,
    admission_delay_histogram: Histogram<u64>,
    rate: u64,
    offered_requests: u64,
    pub admitted_requests: u64,
    pub admitted_errors: u64,
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_bytes: u64,
    pub drained_requests: u64,
    pub drained_bytes: u64,
    pub warmup_requests: u64,
    pub warmup_errors: u64,
}

impl Default for BenchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchMetrics {
    pub fn new() -> Self {
        let mut histogram =
            Histogram::new_with_max(60_000_000, 3).unwrap_or_else(|_| Histogram::new(3).unwrap());
        // The exchange timeout is configurable above 60s. Do not silently
        // lose a long successful exchange from either latency population.
        histogram.auto(true);
        Self {
            cohort_histogram: histogram.clone(),
            scheduled_histogram: histogram.clone(),
            cohort_scheduled_histogram: histogram.clone(),
            admission_delay_histogram: histogram.clone(),
            histogram,
            rate: 0,
            offered_requests: 0,
            admitted_requests: 0,
            admitted_errors: 0,
            total_requests: 0,
            total_errors: 0,
            total_bytes: 0,
            drained_requests: 0,
            drained_bytes: 0,
            warmup_requests: 0,
            warmup_errors: 0,
        }
    }

    pub fn record(&mut self, latency_us: u64, bytes: usize) {
        let _ = self.histogram.record(latency_us);
        let _ = self.cohort_histogram.record(latency_us);
        self.total_requests += 1;
        self.total_bytes += bytes as u64;
    }

    pub fn record_error(&mut self) {
        self.total_errors += 1;
    }

    /// Set once on the combined report; the offered schedule is global,
    /// rather than one offered population per worker.
    pub fn configure_fixed_rate(&mut self, schedule: &FixedRateSchedule) {
        self.rate = schedule.rate();
        self.offered_requests = schedule.offered_requests();
    }

    pub fn record_admission(&mut self) {
        self.admitted_requests += 1;
    }

    pub fn record_admitted_error(&mut self) {
        self.admitted_errors += 1;
        self.record_error();
    }

    pub fn record_scheduled_admission(&mut self, due: Instant, admitted_at: Instant) {
        self.record_admission();
        let _ = self
            .admission_delay_histogram
            .record(admitted_at.saturating_duration_since(due).as_micros() as u64);
    }

    /// Preserve both service time and scheduled response time. Scheduled
    /// latency includes time waiting for a worker/connection, so a slow
    /// target cannot hide admission delay through coordinated omission.
    pub fn record_scheduled_completion(
        &mut self,
        window: MeasurementWindow,
        due: Instant,
        admitted_at: Instant,
        completed_at: Instant,
        bytes: usize,
    ) {
        self.record_completion(
            window,
            completed_at,
            completed_at.duration_since(admitted_at).as_micros() as u64,
            bytes,
        );
        let latency_us = completed_at.duration_since(due).as_micros() as u64;
        let _ = self.cohort_scheduled_histogram.record(latency_us);
        if window.contains(completed_at) {
            let _ = self.scheduled_histogram.record(latency_us);
        }
    }

    /// Only complete, validated echoes inside the shared window contribute
    /// to useful throughput, bytes, and the existing latency fields. Every
    /// successful exchange admitted in the window, including a later drain,
    /// contributes to the separate successful-cohort latency distribution.
    pub fn record_completion(
        &mut self,
        window: MeasurementWindow,
        completed_at: Instant,
        latency_us: u64,
        bytes: usize,
    ) {
        if window.contains(completed_at) {
            self.record(latency_us, bytes);
        } else {
            let _ = self.cohort_histogram.record(latency_us);
            self.drained_requests += 1;
            self.drained_bytes += bytes as u64;
        }
    }

    pub fn record_warmup_success(&mut self) {
        self.warmup_requests += 1;
    }

    pub fn record_warmup_error(&mut self) {
        self.warmup_errors += 1;
        // Failed setup/warmup must still invalidate the cell's zero-error gate.
        self.record_error();
    }

    pub fn merge(&mut self, other: &BenchMetrics) {
        let _ = self.histogram.add(&other.histogram);
        let _ = self.cohort_histogram.add(&other.cohort_histogram);
        let _ = self.scheduled_histogram.add(&other.scheduled_histogram);
        let _ = self
            .cohort_scheduled_histogram
            .add(&other.cohort_scheduled_histogram);
        let _ = self
            .admission_delay_histogram
            .add(&other.admission_delay_histogram);
        self.admitted_requests += other.admitted_requests;
        self.admitted_errors += other.admitted_errors;
        self.total_requests += other.total_requests;
        self.total_errors += other.total_errors;
        self.total_bytes += other.total_bytes;
        self.drained_requests += other.drained_requests;
        self.drained_bytes += other.drained_bytes;
        self.warmup_requests += other.warmup_requests;
        self.warmup_errors += other.warmup_errors;
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
            rate: self.rate,
            offered_requests: self.offered_requests,
            admitted_requests: self.admitted_requests,
            admitted_errors: self.admitted_errors,
            missed_requests: if self.rate == 0 {
                0
            } else {
                self.offered_requests.saturating_sub(self.admitted_requests)
            },
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            rps,
            latency_avg_us: self.histogram.mean() as u64,
            p50_us: self.histogram.value_at_quantile(0.50),
            p95_us: self.histogram.value_at_quantile(0.95),
            p99_us: self.histogram.value_at_quantile(0.99),
            latency_max_us: self.histogram.max(),
            cohort_requests: self.cohort_histogram.len(),
            cohort_p50_us: self.cohort_histogram.value_at_quantile(0.50),
            cohort_p95_us: self.cohort_histogram.value_at_quantile(0.95),
            cohort_p99_us: self.cohort_histogram.value_at_quantile(0.99),
            cohort_latency_max_us: self.cohort_histogram.max(),
            scheduled_requests: self.scheduled_histogram.len(),
            scheduled_latency_avg_us: self.scheduled_histogram.mean() as u64,
            scheduled_p50_us: self.scheduled_histogram.value_at_quantile(0.50),
            scheduled_p95_us: self.scheduled_histogram.value_at_quantile(0.95),
            scheduled_p99_us: self.scheduled_histogram.value_at_quantile(0.99),
            scheduled_latency_max_us: self.scheduled_histogram.max(),
            cohort_scheduled_requests: self.cohort_scheduled_histogram.len(),
            cohort_scheduled_latency_avg_us: self.cohort_scheduled_histogram.mean() as u64,
            cohort_scheduled_p50_us: self.cohort_scheduled_histogram.value_at_quantile(0.50),
            cohort_scheduled_p95_us: self.cohort_scheduled_histogram.value_at_quantile(0.95),
            cohort_scheduled_p99_us: self.cohort_scheduled_histogram.value_at_quantile(0.99),
            cohort_scheduled_latency_max_us: self.cohort_scheduled_histogram.max(),
            admission_delay_avg_us: self.admission_delay_histogram.mean() as u64,
            admission_delay_p99_us: self.admission_delay_histogram.value_at_quantile(0.99),
            admission_delay_max_us: self.admission_delay_histogram.max(),
            total_bytes: self.total_bytes,
            drained_requests: self.drained_requests,
            drained_bytes: self.drained_bytes,
            warmup_requests: self.warmup_requests,
            warmup_errors: self.warmup_errors,
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
    /// Aggregate target requests/sec; zero selects saturated closed-loop load.
    pub rate: u64,
    /// Absolute scheduled slots before the deadline, independent of progress.
    /// Zero in saturated mode, which has no offered-rate schedule.
    pub offered_requests: u64,
    /// Exchanges started in the measurement window, including failed ones.
    pub admitted_requests: u64,
    /// Failed admitted exchanges; setup/warmup failures only affect total_errors.
    pub admitted_errors: u64,
    /// Scheduled slots never admitted, including reserved-but-unstarted slots.
    pub missed_requests: u64,
    pub total_requests: u64,
    pub total_errors: u64,
    pub rps: f64,
    /// Successful completions inside the common measurement window only.
    pub latency_avg_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub latency_max_us: u64,
    /// Successful exchanges admitted inside the measurement window,
    /// including successful postdeadline drains; errors are counted separately.
    pub cohort_requests: u64,
    pub cohort_p50_us: u64,
    pub cohort_p95_us: u64,
    pub cohort_p99_us: u64,
    pub cohort_latency_max_us: u64,
    /// Completion minus scheduled due time, including worker/connection delay.
    /// Existing latency/cohort fields above retain service-time semantics.
    pub scheduled_requests: u64,
    pub scheduled_latency_avg_us: u64,
    pub scheduled_p50_us: u64,
    pub scheduled_p95_us: u64,
    pub scheduled_p99_us: u64,
    pub scheduled_latency_max_us: u64,
    /// All successful scheduled exchanges, including postdeadline drains.
    pub cohort_scheduled_requests: u64,
    pub cohort_scheduled_latency_avg_us: u64,
    pub cohort_scheduled_p50_us: u64,
    pub cohort_scheduled_p95_us: u64,
    pub cohort_scheduled_p99_us: u64,
    pub cohort_scheduled_latency_max_us: u64,
    /// Admission minus scheduled due time, including failed admitted exchanges.
    pub admission_delay_avg_us: u64,
    pub admission_delay_p99_us: u64,
    pub admission_delay_max_us: u64,
    pub total_bytes: u64,
    pub drained_requests: u64,
    pub drained_bytes: u64,
    pub warmup_requests: u64,
    pub warmup_errors: u64,
}
