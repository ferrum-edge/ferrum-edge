//! Per-name-class latency histograms and reporting.

use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameClass {
    MeshInternal,
    MeshWildcard,
    UpstreamForward,
}

impl NameClass {
    pub const ALL: &'static [NameClass] = &[
        NameClass::MeshInternal,
        NameClass::MeshWildcard,
        NameClass::UpstreamForward,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            NameClass::MeshInternal => "mesh-internal",
            NameClass::MeshWildcard => "mesh-wildcard",
            NameClass::UpstreamForward => "upstream-forward",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

pub struct ClassMetrics {
    histogram: Histogram<u64>,
    pub total_queries: u64,
    pub total_errors: u64,
    pub total_nxdomain: u64,
    pub total_bytes: u64,
}

impl Default for ClassMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassMetrics {
    pub fn new() -> Self {
        Self {
            // Latency in microseconds, max 60s, 3 significant figures.
            histogram: Histogram::new_with_max(60_000_000, 3)
                .unwrap_or_else(|_| Histogram::new(3).unwrap()),
            total_queries: 0,
            total_errors: 0,
            total_nxdomain: 0,
            total_bytes: 0,
        }
    }

    pub fn record(&mut self, latency_us: u64, bytes: usize) {
        let _ = self.histogram.record(latency_us);
        self.total_queries += 1;
        self.total_bytes += bytes as u64;
    }

    pub fn record_error(&mut self) {
        self.total_errors += 1;
    }

    pub fn record_nxdomain(&mut self) {
        self.total_nxdomain += 1;
    }

    pub fn merge(&mut self, other: &ClassMetrics) {
        let _ = self.histogram.add(&other.histogram);
        self.total_queries += other.total_queries;
        self.total_errors += other.total_errors;
        self.total_nxdomain += other.total_nxdomain;
        self.total_bytes += other.total_bytes;
    }

    pub fn to_report(
        &self,
        class: NameClass,
        transport: Transport,
        duration_secs: u64,
    ) -> ClassReport {
        let qps = if duration_secs > 0 {
            self.total_queries as f64 / duration_secs as f64
        } else {
            0.0
        };
        ClassReport {
            name_class: class.as_str().to_string(),
            transport: transport.as_str().to_string(),
            duration_secs,
            total_queries: self.total_queries,
            total_errors: self.total_errors,
            total_nxdomain: self.total_nxdomain,
            qps,
            latency_avg_us: self.histogram.mean() as u64,
            latency_stdev_us: self.histogram.stdev() as u64,
            latency_max_us: self.histogram.max(),
            p50_us: self.histogram.value_at_quantile(0.50),
            p90_us: self.histogram.value_at_quantile(0.90),
            p95_us: self.histogram.value_at_quantile(0.95),
            p99_us: self.histogram.value_at_quantile(0.99),
            total_bytes: self.total_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassReport {
    pub name_class: String,
    pub transport: String,
    pub duration_secs: u64,
    pub total_queries: u64,
    pub total_errors: u64,
    pub total_nxdomain: u64,
    pub qps: f64,
    pub latency_avg_us: u64,
    pub latency_stdev_us: u64,
    pub latency_max_us: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub total_bytes: u64,
}

impl ClassReport {
    /// Fail closed when a selected row recorded no successes or any query error.
    pub fn failure_reason(&self) -> Option<String> {
        if self.total_queries == 0 {
            Some(format!(
                "DNS row {}/{} recorded zero successful queries (errors={}, nxdomain={})",
                self.name_class, self.transport, self.total_errors, self.total_nxdomain
            ))
        } else if self.total_errors != 0 {
            Some(format!(
                "DNS row {}/{} recorded {} query errors (successful={}, nxdomain={})",
                self.name_class,
                self.transport,
                self.total_errors,
                self.total_queries,
                self.total_nxdomain
            ))
        } else if self.total_nxdomain != 0 {
            Some(format!(
                "DNS row {}/{} recorded {} unexpected NXDOMAIN responses (successful={})",
                self.name_class, self.transport, self.total_nxdomain, self.total_queries
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub target: String,
    pub concurrency: u64,
    pub duration_secs: u64,
    pub reports: Vec<ClassReport>,
}

/// Return a reason when any selected class/transport row is absent, duplicated,
/// unexpected, incomplete, or errorful.
pub fn selected_reports_failure(
    reports: &[ClassReport],
    expected_classes: &[NameClass],
    expected_transports: &[Transport],
) -> Option<String> {
    if expected_classes.is_empty() || expected_transports.is_empty() {
        return Some("no DNS class/transport rows were selected".to_string());
    }
    for class in expected_classes {
        for transport in expected_transports {
            let matches = reports
                .iter()
                .filter(|report| {
                    report.name_class == class.as_str() && report.transport == transport.as_str()
                })
                .count();
            if matches == 0 {
                return Some(format!(
                    "selected DNS row {}/{} was not collected",
                    class.as_str(),
                    transport.as_str()
                ));
            }
            if matches > 1 {
                return Some(format!(
                    "selected DNS row {}/{} was collected {matches} times",
                    class.as_str(),
                    transport.as_str()
                ));
            }
        }
    }
    for report in reports {
        let class_selected = expected_classes
            .iter()
            .any(|class| report.name_class == class.as_str());
        let transport_selected = expected_transports
            .iter()
            .any(|transport| report.transport == transport.as_str());
        if !class_selected || !transport_selected {
            return Some(format!(
                "unexpected DNS row {}/{} was collected",
                report.name_class, report.transport
            ));
        }
    }
    for report in reports {
        if let Some(reason) = report.failure_reason() {
            return Some(reason);
        }
    }
    None
}

pub fn format_duration_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}us")
    }
}

pub fn print_text_report(reports: &[ClassReport], target: &str, concurrency: u64) {
    println!();
    println!("Target: {target}");
    println!("Concurrency: {concurrency}");
    println!();
    println!(
        "{:<18} {:<5} {:>10} {:>8} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "Name class", "Xport", "qps", "queries", "errors", "p50", "p90", "p95", "p99"
    );
    println!("{}", "-".repeat(99));
    for r in reports {
        println!(
            "{:<18} {:<5} {:>10.0} {:>8} {:>8} {:>10} {:>10} {:>10} {:>10}",
            r.name_class,
            r.transport,
            r.qps,
            r.total_queries,
            r.total_errors,
            format_duration_us(r.p50_us),
            format_duration_us(r.p90_us),
            format_duration_us(r.p95_us),
            format_duration_us(r.p99_us),
        );
    }
    println!();
}
