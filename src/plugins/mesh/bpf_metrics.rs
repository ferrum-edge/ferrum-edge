//! `__mesh_bpf_metrics` — surfaces BPF TCP counters as Prometheus
//! metrics.
//!
//! GAP-SC3 uses SOCK_OPS for lifecycle/handshake timing, SK_SKB for the first
//! accepted application-data byte, and connect hooks for drop-reason hits.
//! They emit to a userspace ringbuf. The
//! [`crate::ebpf::event_consumer::SockOpsConsumer`] drains
//! that ringbuf and updates a shared [`BpfMetricsState`]. This plugin
//! exposes that state in Prometheus exposition format via the
//! authenticated production `GET /metrics` scrape (appended once from the
//! current plugin-cache generation's precomputed
//! [`MeshBpfMetricsExporter`]).
//!
//! ## Auto-injection
//!
//! The plugin is auto-injected as a global plugin only when the mesh
//! topology is `NodeWaypoint`. Other topologies (sidecar, ambient,
//! east/egress gateway) don't run the SOCK_OPS BPF program — emitting
//! always-zero counters from them would mislead operator dashboards.
//!
//! ## What the metrics answer
//!
//! - **`ferrum_mesh_bpf_tcp_events_total{event="connect"|"accept"|...}`**:
//!   per-event TCP-lifecycle counts. Operators correlate `accept` vs
//!   `connect` rates to spot stuck pods or pre-handshake drops. RST is
//!   a single non-directional `rst` label — SOCK_OPS cannot attribute
//!   sent vs received.
//! - **`ferrum_mesh_bpf_drops_total{reason="bypass_uid_hit"|...}`**:
//!   how often each BPF capture-bypass decision fired (produced by
//!   connect4/connect6).
//! - **`ferrum_mesh_bpf_ringbuf_overruns_total`**: ringbuf overruns. The
//!   `_in_overrun_regime` companion gauge stays at 1 between the warn
//!   and recovery transitions so dashboards can alert without scraping
//!   logs.
//! - **TCP-layer latency histograms** (SRTT, syn→ack, accept→first-byte) as canonical
//!   Prometheus histograms: fixed microsecond `le` buckets plus the
//!   historical `_sum`/`_count` series for mean derivation. Capture
//!   accept-to-first-application-byte is produced by a SOCK_OPS timestamp plus
//!   SK_SKB first-data hook on the same accepted socket cookie.

use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::ebpf::bpf_metrics::{
    BPF_LATENCY_BUCKET_LE_LABELS, BpfDropReason, BpfMetricsSnapshot, BpfMetricsState,
};
use crate::plugins::{ALL_PROTOCOLS, Plugin, ProxyProtocol, priority};

/// Plugin name as it appears in plugin chain configuration. The `__mesh_`
/// prefix marks it as a reserved auto-injected mesh plugin.
pub const PLUGIN_NAME: &str = "__mesh_bpf_metrics";

/// Default Prometheus metric-name prefix when the operator does not override
/// `prefix` in the plugin config.
pub const DEFAULT_METRIC_PREFIX: &str = "ferrum_mesh_bpf";

/// Operator-facing config knobs.
#[derive(Debug, Clone)]
struct BpfMetricsConfig {
    /// Optional metric prefix override. Defaults to [`DEFAULT_METRIC_PREFIX`].
    /// Operators with multiple gateway instances on a node can use this
    /// to disambiguate the time series, mirroring the existing
    /// `prometheus_metrics` plugin's namespace_label pattern.
    prefix: String,
}

impl Default for BpfMetricsConfig {
    fn default() -> Self {
        Self {
            prefix: DEFAULT_METRIC_PREFIX.to_string(),
        }
    }
}

/// Precomputed scrape handle for the active `__mesh_bpf_metrics` instance.
///
/// Plugin-cache generations extract this once from the constructed plugin so
/// authenticated `GET /metrics` can append the surface with a single
/// `ArcSwap` load — no plugin-list scan and no new plugin allocation on the
/// scrape path. When the plugin is absent from the published configuration
/// the cache stores `None` and `/metrics` emits nothing from this renderer.
#[derive(Clone)]
pub struct MeshBpfMetricsExporter {
    prefix: Arc<str>,
    state: Arc<BpfMetricsState>,
}

impl MeshBpfMetricsExporter {
    /// Metric-name prefix preserved from the active plugin config.
    pub fn prefix(&self) -> &str {
        self.prefix.as_ref()
    }

    /// Shared counter store read on each scrape.
    pub fn metrics_state(&self) -> Arc<BpfMetricsState> {
        self.state.clone()
    }

    /// Render the BPF metrics in Prometheus text exposition format.
    ///
    /// Cold path — called once per authenticated `/metrics` scrape. Emits
    /// TYPE and HELP comments for each metric so the output is
    /// self-describing. When the attached state has never received events
    /// (plugin active without a live BPF consumer), this still emits the
    /// documented stable zero-valued surface.
    pub fn render_prometheus(&self) -> String {
        render_prometheus_snapshot(self.prefix.as_ref(), &self.state.snapshot())
    }
}

/// `__mesh_bpf_metrics` plugin.
///
/// Holds an `Arc<BpfMetricsState>` populated by
/// [`crate::ebpf::event_consumer::SockOpsConsumer`]. The Plugin trait
/// hooks are intentionally no-ops — this plugin's role is to register
/// itself in the plugin chain (so its presence is operator-visible via
/// `available_plugins()` / `/admin/plugins`) and to expose a
/// [`MeshBpfMetricsExporter`] that the plugin cache publishes into the
/// authenticated `/metrics` scrape.
pub struct MeshBpfMetrics {
    config: BpfMetricsConfig,
    state: Arc<BpfMetricsState>,
}

// Manual Debug impl: BpfMetricsState contains atomics, which Debug only
// via `Relaxed` loads of their values. We don't need that granularity for
// plugin Debug output; the prefix and a static "state=..." marker is
// enough for panic messages in tests and for `Result::unwrap` formatting.
impl std::fmt::Debug for MeshBpfMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshBpfMetrics")
            .field("config", &self.config)
            .field("state", &"<BpfMetricsState>")
            .finish()
    }
}

impl MeshBpfMetrics {
    /// Construct from operator config + the consumer's metrics state.
    ///
    /// In production the state is the same Arc the SockOpsConsumer is
    /// updating — see `inject_mesh_global_plugins()` in
    /// `src/modes/mesh/mod.rs` for the wiring point.
    pub fn with_state(config: &Value, state: Arc<BpfMetricsState>) -> Result<Self, String> {
        let parsed = parse_config(config)?;
        Ok(Self {
            config: parsed,
            state,
        })
    }

    /// Test/operator constructor: builds a plugin owning a fresh empty
    /// metrics state. Useful in plugin-validation paths and in unit
    /// tests that just check the plugin lifecycle hooks.
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::with_state(config, BpfMetricsState::new())
    }

    /// Cheap scrape handle sharing this instance's prefix and state Arc.
    pub fn exporter(&self) -> MeshBpfMetricsExporter {
        MeshBpfMetricsExporter {
            prefix: Arc::from(self.config.prefix.as_str()),
            state: self.state.clone(),
        }
    }

    /// Render the BPF metrics in Prometheus text exposition format.
    ///
    /// Cold path — used by unit tests and by
    /// [`MeshBpfMetricsExporter::render_prometheus`] on each authenticated
    /// `/metrics` scrape.
    #[cfg(test)]
    fn render_prometheus(&self) -> String {
        self.exporter().render_prometheus()
    }
}

fn render_prometheus_snapshot(prefix: &str, snap: &BpfMetricsSnapshot) -> String {
    let mut out = String::with_capacity(8192);
    let p = prefix;

    // TCP-layer event counters.
    let _ = writeln!(
        out,
        "# HELP {p}_tcp_events_total TCP-layer events captured by the BPF SOCK_OPS program. \
            event=\"rst\" counts abnormal ESTABLISHED→CLOSE transitions without sent/received \
            attribution (SOCK_OPS state callbacks cannot distinguish direction)."
    );
    let _ = writeln!(out, "# TYPE {p}_tcp_events_total counter");
    let _ = writeln!(
        out,
        "{p}_tcp_events_total{{event=\"connect\"}} {}",
        snap.connect
    );
    let _ = writeln!(
        out,
        "{p}_tcp_events_total{{event=\"accept_established\"}} {}",
        snap.accept_established
    );
    let _ = writeln!(out, "{p}_tcp_events_total{{event=\"rst\"}} {}", snap.rst);
    let _ = writeln!(
        out,
        "{p}_tcp_events_total{{event=\"fin_sent\"}} {}",
        snap.fin_sent
    );
    let _ = writeln!(
        out,
        "{p}_tcp_events_total{{event=\"fin_received\"}} {}",
        snap.fin_received
    );

    // Drop-reason counters.
    let _ = writeln!(
        out,
        "# HELP {p}_drops_total Connection-bypass decisions by reason, \
            produced by the connect4/connect6 capture hooks."
    );
    let _ = writeln!(out, "# TYPE {p}_drops_total counter");
    for (reason, count) in snap.drop_reasons() {
        let _ = writeln!(
            out,
            "{p}_drops_total{{reason=\"{}\"}} {count}",
            reason.label()
        );
    }
    // Mention the well-known reasons we know about, even at 0, so
    // dashboards stay informative on fresh installs.
    let _ = writeln!(
        out,
        "# HELP {p}_drop_reasons Well-known BPF drop reason labels (gauge=1 to make the label set self-documenting)."
    );
    let _ = writeln!(out, "# TYPE {p}_drop_reasons gauge");
    for reason in [
        BpfDropReason::BypassUidHit,
        BpfDropReason::ExcludeCidrHit,
        BpfDropReason::NotInIncludeCidr,
        BpfDropReason::ExcludePortHit,
    ] {
        let _ = writeln!(out, "{p}_drop_reasons{{reason=\"{}\"}} 1", reason.label());
    }

    // Latency histograms (TCP-layer only; app-layer stays in workload_metrics).
    // Fixed low-cardinality µs buckets; `_sum`/`_count` preserved for means.
    render_latency_histogram(
        &mut out,
        p,
        "srtt_microseconds",
        "TCP smoothed RTT samples in microseconds. Fixed le buckets plus sum/count; \
         zero samples are ignored and sum overflow or counter saturation drops the sample.",
        &snap.srtt_cumulative_buckets(),
        snap.srtt_sample_us_sum,
        snap.srtt_count,
    );
    render_latency_histogram(
        &mut out,
        p,
        "syn_to_ack_microseconds",
        "Time between SYN send and ACK observation in microseconds. Fixed le buckets \
         plus sum/count; zero samples are ignored and sum overflow or counter saturation drops the sample.",
        &snap.syn_to_ack_cumulative_buckets(),
        snap.syn_to_ack_us_sum,
        snap.syn_to_ack_count,
    );
    render_latency_histogram(
        &mut out,
        p,
        "accept_to_first_byte_microseconds",
        "Time from captured TCP passive-established accept to the first inbound application-data byte on the same accepted socket, in microseconds. Missing, raced, stale, reversed, or corrupt correlation evidence emits no sample; fixed le buckets plus sum/count; sum overflow or counter saturation drops the sample.",
        &snap.accept_to_first_byte_cumulative_buckets(),
        snap.accept_to_first_byte_us_sum,
        snap.accept_to_first_byte_count,
    );

    // Ringbuf health.
    let _ = writeln!(
        out,
        "# HELP {p}_ringbuf_events_total Total events drained from the SOCK_OPS ringbuf."
    );
    let _ = writeln!(out, "# TYPE {p}_ringbuf_events_total counter");
    let _ = writeln!(
        out,
        "{p}_ringbuf_events_total {}",
        snap.ringbuf_events_consumed
    );
    let _ = writeln!(
        out,
        "# HELP {p}_ringbuf_overruns_total Ringbuf overrun episodes. Incremented when the \
            kernel dropped-events counter advances between polls, and once when attaching \
            (or re-attaching after pin rotation) to a map generation that already reports \
            a nonzero dropped total. Non-zero = userspace fell behind and the kernel \
            dropped events. Set FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES higher."
    );
    let _ = writeln!(out, "# TYPE {p}_ringbuf_overruns_total counter");
    let _ = writeln!(out, "{p}_ringbuf_overruns_total {}", snap.ringbuf_overruns);
    let _ = writeln!(
        out,
        "# HELP {p}_ringbuf_in_overrun_regime 1 while the consumer is in an overrun regime, 0 after recovery. Pair with `_overruns_total` for alerting."
    );
    let _ = writeln!(out, "# TYPE {p}_ringbuf_in_overrun_regime gauge");
    let _ = writeln!(
        out,
        "{p}_ringbuf_in_overrun_regime {}",
        if snap.in_overrun_regime { 1 } else { 0 }
    );

    out
}

fn render_latency_histogram(
    out: &mut String,
    prefix: &str,
    metric: &str,
    help: &str,
    cumulative: &[u64],
    sum: u64,
    count: u64,
) {
    // Bucket and count atomics are sampled independently. If an observation
    // lands between those loads, the finite buckets can be newer than count.
    // Clamp the rendered count so Prometheus always sees a valid histogram
    // whose +Inf bucket and _count cover every rendered finite bucket.
    let rendered_count = cumulative.last().copied().unwrap_or(count).max(count);
    let _ = writeln!(out, "# HELP {prefix}_{metric} {help}");
    let _ = writeln!(out, "# TYPE {prefix}_{metric} histogram");
    for (le, &bucket_count) in BPF_LATENCY_BUCKET_LE_LABELS.iter().zip(cumulative.iter()) {
        let _ = writeln!(
            out,
            "{prefix}_{metric}_bucket{{le=\"{le}\"}} {bucket_count}"
        );
    }
    let _ = writeln!(
        out,
        "{prefix}_{metric}_bucket{{le=\"+Inf\"}} {rendered_count}"
    );
    let _ = writeln!(out, "{prefix}_{metric}_sum {sum}");
    let _ = writeln!(out, "{prefix}_{metric}_count {rendered_count}");
}

/// Every root `config` key `__mesh_bpf_metrics` reads. Unknown root keys fail
/// closed at construction so a misspelled `prefix` cannot silently publish the
/// default metric namespace while operator dashboards scrape the intended one.
pub const MESH_BPF_METRICS_CONFIG_KEYS: &[&str] = &["prefix"];

fn parse_config(config: &Value) -> Result<BpfMetricsConfig, String> {
    // A non-object config keeps its existing behavior (the read below yields
    // `None`, producing the default prefix).
    if let Some(object) = config.as_object() {
        crate::util::unknown_keys::reject_unknown_keys(
            object,
            "config",
            MESH_BPF_METRICS_CONFIG_KEYS,
            "__mesh_bpf_metrics: ",
        )?;
    }
    let mut parsed = BpfMetricsConfig::default();
    if let Some(prefix) = config.get("prefix") {
        let prefix = prefix
            .as_str()
            .ok_or_else(|| "__mesh_bpf_metrics: `prefix` must be a string".to_string())?
            .trim();
        if prefix.is_empty() {
            return Err("__mesh_bpf_metrics: `prefix` must not be empty".to_string());
        }
        let mut chars = prefix.chars();
        let first = chars.next().expect("prefix is not empty");
        if !(first.is_ascii_alphabetic() || first == '_')
            || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(
                "__mesh_bpf_metrics: `prefix` must match `[A-Za-z_][A-Za-z0-9_]*` to form valid Prometheus metric names"
                    .to_string(),
            );
        }
        parsed.prefix = prefix.to_string();
    }
    Ok(parsed)
}

#[async_trait]
impl Plugin for MeshBpfMetrics {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> u16 {
        priority::MESH_BPF_METRICS
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        // Touches no per-request state; safe across every protocol the
        // chain supports so an operator config that targets this plugin
        // at a non-mesh proxy isn't silently dropped.
        ALL_PROTOCOLS
    }

    fn mesh_bpf_metrics_exporter(&self) -> Option<MeshBpfMetricsExporter> {
        Some(self.exporter())
    }

    // No hot-path hooks. The plugin is a passive metrics surface; all
    // counter updates happen on the event-consumer task that shares the
    // same `Arc<BpfMetricsState>`. The Plugin trait's default no-op
    // implementations for the request/response/stream/ws hooks are
    // exactly the right shape — we don't override any of them.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> Arc<BpfMetricsState> {
        BpfMetricsState::new()
    }

    #[test]
    fn default_config_accepted() {
        let plugin = MeshBpfMetrics::with_state(&Value::Null, metrics()).unwrap();
        assert_eq!(plugin.config.prefix, DEFAULT_METRIC_PREFIX);
    }

    #[test]
    fn empty_object_config_accepted() {
        MeshBpfMetrics::with_state(&serde_json::json!({}), metrics()).unwrap();
    }

    #[test]
    fn custom_prefix_accepted() {
        let plugin =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "tenantA_bpf" }), metrics())
                .unwrap();
        assert_eq!(plugin.config.prefix, "tenantA_bpf");
    }

    #[test]
    fn invalid_prefix_rejected() {
        let err =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "with spaces" }), metrics())
                .unwrap_err();
        assert!(err.contains("prefix"));

        let empty_err =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "  " }), metrics())
                .unwrap_err();
        assert!(empty_err.contains("must not be empty"));

        let leading_digit_err =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "1tenant_bpf" }), metrics())
                .unwrap_err();
        assert!(leading_digit_err.contains("valid Prometheus"));
    }

    #[test]
    fn render_prometheus_emits_expected_metric_families() {
        let state = metrics();
        // Seed a few counters so the render is non-zero.
        state.record_connect();
        state.record_accept_established();
        state.record_srtt_sample(250);
        state.record_drop(BpfDropReason::BypassUidHit);
        state.record_ringbuf_overrun();
        let plugin = MeshBpfMetrics::with_state(&Value::Null, state).unwrap();

        let text = plugin.render_prometheus();
        // TCP event counters
        assert!(text.contains("ferrum_mesh_bpf_tcp_events_total{event=\"connect\"} 1"));
        assert!(text.contains("ferrum_mesh_bpf_tcp_events_total{event=\"accept_established\"} 1"));
        // Drop counters (concrete count + the self-documenting gauge)
        assert!(text.contains("ferrum_mesh_bpf_drops_total{reason=\"bypass_uid_hit\"} 1"));
        assert!(text.contains("ferrum_mesh_bpf_drop_reasons{reason=\"exclude_cidr_hit\"} 1"));
        // Latency histogram (TYPE + buckets + preserved sum/count)
        assert!(text.contains("# TYPE ferrum_mesh_bpf_srtt_microseconds histogram"));
        assert!(text.contains("ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"250\"} 1"));
        assert!(text.contains("ferrum_mesh_bpf_srtt_microseconds_bucket{le=\"+Inf\"} 1"));
        assert!(text.contains("ferrum_mesh_bpf_srtt_microseconds_sum 250"));
        assert!(text.contains("ferrum_mesh_bpf_srtt_microseconds_count 1"));
        // Ringbuf health: in-regime gauge flipped to 1 after the overrun.
        assert!(text.contains("ferrum_mesh_bpf_ringbuf_overruns_total 1"));
        assert!(text.contains("ferrum_mesh_bpf_ringbuf_in_overrun_regime 1"));
    }

    #[test]
    fn render_prometheus_honors_custom_prefix() {
        let plugin =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "tenantA_bpf" }), metrics())
                .unwrap();
        let text = plugin.render_prometheus();
        assert!(text.contains("tenantA_bpf_tcp_events_total{event=\"connect\"} 0"));
        assert!(!text.contains("ferrum_mesh_bpf_tcp_events_total"));
    }

    #[test]
    fn plugin_metadata_matches_reserved_priority() {
        let plugin = MeshBpfMetrics::with_state(&Value::Null, metrics()).unwrap();
        assert_eq!(plugin.name(), PLUGIN_NAME);
        assert_eq!(plugin.priority(), priority::MESH_BPF_METRICS);
    }
}
