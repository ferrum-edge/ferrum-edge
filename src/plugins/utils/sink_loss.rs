//! Process-persistent, fixed-cardinality record-loss accounting for the
//! per-plugin observability sinks (issue #4801).
//!
//! Every logging sink shares two discard layers: the retained-byte budgets in
//! [`crate::plugins::utils::byte_budget`] and the bounded channel plus
//! flush/retry loop in [`crate::plugins::utils::batching_logger`]. Both layers
//! logged their losses and counted them per instance, but nothing published
//! them, so an operator watching `/metrics` saw a healthy pipeline while the
//! audit trail was being truncated.
//!
//! The counters live here, in process-global storage, rather than on a sink
//! instance so a plugin-cache reload cannot reset them: a config change is not
//! evidence that the records came back. This mirrors the process-total
//! accounting the chargeback sink adopted in #4872.
//!
//! Cardinality is closed by construction. Both label values are chosen from
//! fixed compile-time arrays — never a policy id, endpoint, namespace, or any
//! other config-derived string — because these paths fire hardest under
//! exactly the load where an unbounded label would be most dangerous. A
//! plugin name outside the known set is folded into [`OTHER_PLUGIN`] rather
//! than being dropped silently; invisible loss is the defect this module
//! exists to fix.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Bucket for sink identities outside [`SINK_PLUGINS`] (test budgets, or a new
/// sink whose author has not yet added it to the closed set). Loss is still
/// published; only its attribution is coarse.
pub const OTHER_PLUGIN: &str = "other";

/// Closed set of observability sink plugins that report record loss.
///
/// Sorted so the rendered exposition is stable across scrapes. Adding a sink
/// means adding it here *and* to the `docs/prometheus_metrics.md` inventory
/// note; the label set is asserted bounded by the unit tests.
pub const SINK_PLUGINS: [&str; 10] = [
    "ai_transcript_audit",
    "api_chargeback_sink",
    "http_logging",
    "kafka_logging",
    "loki_logging",
    OTHER_PLUGIN,
    "statsd_logging",
    "tcp_logging",
    "udp_logging",
    "ws_logging",
];

/// Closed reason set for a discarded observability record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkLossReason {
    /// A per-instance or process-wide retained-byte budget refused the
    /// admission, so the record was never retained.
    ByteBudget,
    /// The serialized record exceeded a per-entry ceiling (`max_entry_bytes`
    /// or its reservation) and could not be admitted.
    RecordTooLarge,
    /// The bounded in-memory queue was full and no overflow handoff accepted
    /// ownership of the record.
    QueueFull,
    /// A whole batch was discarded after its retry budget was exhausted, or a
    /// non-retryable HTTP 4xx permanently rejected it, with no durable fallback
    /// to hand it to.
    BatchDiscard,
    /// The flush worker was closed or not yet started, so the record could not
    /// be admitted.
    Shutdown,
    /// The sink rejected an individual record on a delivery or serialization
    /// error that retrying could not fix.
    SinkError,
}

impl SinkLossReason {
    /// Every reason, ordered by label so the exposition is stable.
    pub const ALL: [Self; 6] = [
        Self::BatchDiscard,
        Self::ByteBudget,
        Self::QueueFull,
        Self::RecordTooLarge,
        Self::Shutdown,
        Self::SinkError,
    ];

    /// Fixed label value. Never derived from configuration or request data.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ByteBudget => "byte_budget",
            Self::RecordTooLarge => "record_too_large",
            Self::QueueFull => "queue_full",
            Self::BatchDiscard => "batch_discard",
            Self::Shutdown => "shutdown",
            Self::SinkError => "sink_error",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::BatchDiscard => 0,
            Self::ByteBudget => 1,
            Self::QueueFull => 2,
            Self::RecordTooLarge => 3,
            Self::Shutdown => 4,
            Self::SinkError => 5,
        }
    }
}

const PLUGIN_COUNT: usize = SINK_PLUGINS.len();
const REASON_COUNT: usize = SinkLossReason::ALL.len();

static DROPPED: [[AtomicU64; REASON_COUNT]; PLUGIN_COUNT] =
    [const { [const { AtomicU64::new(0) }; REASON_COUNT] }; PLUGIN_COUNT];
static ACCEPTED: [AtomicU64; PLUGIN_COUNT] = [const { AtomicU64::new(0) }; PLUGIN_COUNT];

fn plugin_index(plugin: &str) -> usize {
    SinkLossSlot::for_plugin(plugin).0
}

/// Pre-resolved index into the process-global counters.
///
/// Sinks resolve this once at construction so the accepted-record increment on
/// the proxy path is a single relaxed `fetch_add` rather than a name lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkLossSlot(usize);

impl SinkLossSlot {
    /// Resolve `plugin` against the closed set, falling back to
    /// [`OTHER_PLUGIN`].
    pub fn for_plugin(plugin: &str) -> Self {
        match SINK_PLUGINS.iter().position(|name| *name == plugin) {
            Some(index) => Self(index),
            None => Self(
                SINK_PLUGINS
                    .iter()
                    .position(|name| *name == OTHER_PLUGIN)
                    .unwrap_or(0),
            ),
        }
    }

    /// Count `records` lost for `reason`. Zero-record calls are ignored so a
    /// caller cannot manufacture a loss event without a lost record.
    pub fn record_dropped(self, reason: SinkLossReason, records: u64) {
        if records == 0 {
            return;
        }
        DROPPED[self.0][reason.index()].fetch_add(records, Ordering::Relaxed);
    }

    /// Count `records` admitted to the sink's bounded queue.
    pub fn record_accepted(self, records: u64) {
        if records == 0 {
            return;
        }
        ACCEPTED[self.0].fetch_add(records, Ordering::Relaxed);
    }
}

impl Default for SinkLossSlot {
    fn default() -> Self {
        Self::for_plugin(OTHER_PLUGIN)
    }
}

/// Count `records` lost by `plugin` for `reason`.
///
/// Cold-path convenience for call sites that do not hold a [`SinkLossSlot`].
pub fn record_dropped(plugin: &str, reason: SinkLossReason, records: u64) {
    SinkLossSlot::for_plugin(plugin).record_dropped(reason, records);
}

/// Count `records` admitted by `plugin`.
pub fn record_accepted(plugin: &str, records: u64) {
    SinkLossSlot::for_plugin(plugin).record_accepted(records);
}

/// Cumulative records lost by `plugin` for `reason` since process start.
// Read by the external unit-test crate; the binary target compiles this module
// separately and cannot observe those callers.
#[allow(dead_code)]
pub fn dropped_total(plugin: &str, reason: SinkLossReason) -> u64 {
    DROPPED[plugin_index(plugin)][reason.index()].load(Ordering::Relaxed)
}

/// Cumulative records lost by `plugin` across every reason.
#[allow(dead_code)] // See `dropped_total`.
pub fn dropped_total_all_reasons(plugin: &str) -> u64 {
    let index = plugin_index(plugin);
    SinkLossReason::ALL
        .iter()
        .map(|reason| DROPPED[index][reason.index()].load(Ordering::Relaxed))
        .fold(0u64, u64::saturating_add)
}

/// Cumulative records admitted by `plugin` since process start.
#[allow(dead_code)] // See `dropped_total`.
pub fn accepted_total(plugin: &str) -> u64 {
    ACCEPTED[plugin_index(plugin)].load(Ordering::Relaxed)
}

/// Authenticated `/status` projection.
///
/// Closed-set labels and counts only: no endpoint, topic, policy id, or record
/// content ever reaches this structure.
#[derive(Debug, Clone, Serialize)]
pub struct SinkLossSnapshot {
    /// Records lost across every sink and reason since process start.
    pub dropped_total: u64,
    /// Records admitted across every sink since process start.
    pub accepted_total: u64,
    /// Per-plugin totals, present only for sinks that have lost a record.
    pub dropped_by_plugin: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
}

/// Project the process counters for the authenticated `/status` payload.
///
/// Only non-zero reasons are listed so a healthy gateway reports an empty map
/// rather than a wall of zeros; the Prometheus family still emits every series.
pub fn snapshot() -> SinkLossSnapshot {
    let mut dropped_by_plugin: BTreeMap<&'static str, BTreeMap<&'static str, u64>> =
        BTreeMap::new();
    let mut dropped_total = 0u64;
    let mut accepted_total = 0u64;
    for (index, plugin) in SINK_PLUGINS.iter().enumerate() {
        accepted_total = accepted_total.saturating_add(ACCEPTED[index].load(Ordering::Relaxed));
        let mut reasons: BTreeMap<&'static str, u64> = BTreeMap::new();
        for reason in SinkLossReason::ALL {
            let value = DROPPED[index][reason.index()].load(Ordering::Relaxed);
            if value > 0 {
                reasons.insert(reason.as_str(), value);
                dropped_total = dropped_total.saturating_add(value);
            }
        }
        if !reasons.is_empty() {
            dropped_by_plugin.insert(*plugin, reasons);
        }
    }
    SinkLossSnapshot {
        dropped_total,
        accepted_total,
        dropped_by_plugin,
    }
}

/// Render both families with fixed labels only.
///
/// Every series is emitted on every scrape, including zero-valued ones, so an
/// alert on `rate(...[5m]) > 0` does not depend on a sink having already lost
/// a record for the series to exist.
pub fn render_prometheus() -> String {
    // 10 plugins * 7 series, each well under 128 bytes of exposition.
    let mut output = String::with_capacity(8_192);
    output.push_str(
        "# HELP ferrum_plugin_log_sink_records_accepted_total Observability records admitted to a per-plugin logging sink's bounded queue. Process-cumulative; not reset by a plugin-cache reload.\n\
# TYPE ferrum_plugin_log_sink_records_accepted_total counter\n",
    );
    for (index, plugin) in SINK_PLUGINS.iter().enumerate() {
        output.push_str(&format!(
            "ferrum_plugin_log_sink_records_accepted_total{{plugin=\"{plugin}\"}} {}\n",
            ACCEPTED[index].load(Ordering::Relaxed)
        ));
    }
    output.push_str(
        "# HELP ferrum_plugin_log_sink_records_dropped_total Observability records discarded by a per-plugin logging sink, by bounded reason. Process-cumulative; not reset by a plugin-cache reload.\n\
# TYPE ferrum_plugin_log_sink_records_dropped_total counter\n",
    );
    for (index, plugin) in SINK_PLUGINS.iter().enumerate() {
        for reason in SinkLossReason::ALL {
            output.push_str(&format!(
                "ferrum_plugin_log_sink_records_dropped_total{{plugin=\"{plugin}\",reason=\"{}\"}} {}\n",
                reason.as_str(),
                DROPPED[index][reason.index()].load(Ordering::Relaxed)
            ));
        }
    }
    output
}
