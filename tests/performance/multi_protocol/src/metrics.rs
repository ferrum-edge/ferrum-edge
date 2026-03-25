use hdrhistogram::Histogram;
use serde::Serialize;

/// Performance metrics collector with wrk-like reporting.
pub struct BenchMetrics {
    histogram: Histogram<u64>,
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_bytes: u64,
}

impl BenchMetrics {
    pub fn new() -> Self {
        Self {
            // Latency in microseconds, max 60s, 3 significant figures
            histogram: Histogram::new_with_max(60_000_000, 3)
                .unwrap_or_else(|_| Histogram::new(3).unwrap()),
            total_requests: 0,
            total_errors: 0,
            total_bytes: 0,
        }
    }

    /// Record a successful request with latency in microseconds and response bytes.
    pub fn record(&mut self, latency_us: u64, bytes: usize) {
        let _ = self.histogram.record(latency_us);
        self.total_requests += 1;
        self.total_bytes += bytes as u64;
    }

    /// Record an error (no latency sample).
    pub fn record_error(&mut self) {
        self.total_errors += 1;
    }

    /// Merge another metrics instance into this one.
    pub fn merge(&mut self, other: &BenchMetrics) {
        let _ = self.histogram.add(&other.histogram);
        self.total_requests += other.total_requests;
        self.total_errors += other.total_errors;
        self.total_bytes += other.total_bytes;
    }

    /// Generate a wrk-like text report.
    pub fn report(&self, protocol: &str, target: &str, concurrency: u64, duration_secs: u64) -> String {
        let rps = if duration_secs > 0 {
            self.total_requests as f64 / duration_secs as f64
        } else {
            0.0
        };
        let throughput_mb = self.total_bytes as f64 / (1024.0 * 1024.0);
        let throughput_per_sec = if duration_secs > 0 {
            throughput_mb / duration_secs as f64
        } else {
            0.0
        };

        let avg = self.histogram.mean() as u64;
        let stdev = self.histogram.stdev() as u64;
        let max = self.histogram.max();
        let p50 = self.histogram.value_at_quantile(0.50);
        let p75 = self.histogram.value_at_quantile(0.75);
        let p90 = self.histogram.value_at_quantile(0.90);
        let p99 = self.histogram.value_at_quantile(0.99);

        // Calculate +/- Stdev percentage
        let within_stdev = if self.histogram.len() > 0 {
            let lo = avg.saturating_sub(stdev);
            let hi = avg.saturating_add(stdev);
            let count_within: u64 = self.histogram.iter_recorded()
                .filter(|v| v.value_iterated_to() >= lo && v.value_iterated_to() <= hi)
                .map(|v| v.count_at_value())
                .sum();
            (count_within as f64 / self.histogram.len() as f64) * 100.0
        } else {
            0.0
        };

        format!(
            "Running {duration_secs}s test @ {target}\n\
             \x20 Protocol: {protocol}\n\
             \x20 {concurrency} concurrent connections\n\
             \n\
             \x20 Latency     Avg         Stdev       Max         +/- Stdev\n\
             \x20             {:<12}{:<12}{:<12}{:.2}%\n\
             \n\
             \x20 Latency Distribution\n\
             \x20    50%    {}\n\
             \x20    75%    {}\n\
             \x20    90%    {}\n\
             \x20    99%    {}\n\
             \n\
             \x20 {} requests in {:.2}s, {:.2}MB read\n\
             \x20 Errors: {}\n\
             \n\
             Requests/sec:  {:.2}\n\
             Transfer/sec:      {:.2}MB",
            format_duration_us(avg),
            format_duration_us(stdev),
            format_duration_us(max),
            within_stdev,
            format_duration_us(p50),
            format_duration_us(p75),
            format_duration_us(p90),
            format_duration_us(p99),
            self.total_requests,
            duration_secs as f64,
            throughput_mb,
            self.total_errors,
            rps,
            throughput_per_sec,
        )
    }

    /// Generate a machine-readable JSON report.
    pub fn to_json_report(
        &self,
        protocol: &str,
        target: &str,
        concurrency: u64,
        duration_secs: u64,
    ) -> BenchReport {
        let rps = if duration_secs > 0 {
            self.total_requests as f64 / duration_secs as f64
        } else {
            0.0
        };
        let throughput_mbps = if duration_secs > 0 {
            (self.total_bytes as f64 * 8.0) / (1_000_000.0 * duration_secs as f64)
        } else {
            0.0
        };

        BenchReport {
            protocol: protocol.to_string(),
            target: target.to_string(),
            duration_secs,
            concurrency,
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            rps,
            latency_avg_us: self.histogram.mean() as u64,
            latency_stdev_us: self.histogram.stdev() as u64,
            latency_max_us: self.histogram.max(),
            p50_us: self.histogram.value_at_quantile(0.50),
            p75_us: self.histogram.value_at_quantile(0.75),
            p90_us: self.histogram.value_at_quantile(0.90),
            p99_us: self.histogram.value_at_quantile(0.99),
            total_bytes: self.total_bytes,
            throughput_mbps,
        }
    }
}

/// Machine-readable benchmark report.
#[derive(Debug, Serialize)]
pub struct BenchReport {
    pub protocol: String,
    pub target: String,
    pub duration_secs: u64,
    pub concurrency: u64,
    pub total_requests: u64,
    pub total_errors: u64,
    pub rps: f64,
    pub latency_avg_us: u64,
    pub latency_stdev_us: u64,
    pub latency_max_us: u64,
    pub p50_us: u64,
    pub p75_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    pub total_bytes: u64,
    pub throughput_mbps: f64,
}

/// Format microseconds into a human-readable duration string.
pub fn format_duration_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}us")
    }
}
