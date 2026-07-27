//! Rule types and per-sample evaluation logic for `proxy_alerts`.
//!
//! Each rule type carries its own threshold spec and a list of channel ids
//! to dispatch to. The plugin's `log()` / `on_stream_disconnect()` hook
//! iterates rules, calls `Rule::observe(...)`, records into the shared
//! [`WindowStore`], snapshots the current window, and decides whether to
//! dispatch via the cooldown + recovery gates.

use std::sync::Arc;

use crate::notifications::Severity;
use crate::plugins::{
    DisconnectCause, StreamTransactionSummary, TransactionSummary, WsDisconnectContext,
};
use crate::retry::ErrorClass;

use super::windows::{MAX_FINITE_LATENCY_BOUND_MS, RuleWindowSpec, WindowKind, WindowStore};

thread_local! {
    /// Reusable scratch buffer for the namespace-qualified window identity
    /// (`namespace|proxy_id`). Borrowed strictly synchronously within one
    /// `observe` call — no `.await`, no re-entry — so window keying stays
    /// allocation-free in steady state.
    static OWNER_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(64));
}

#[allow(clippy::enum_variant_names)] // All variants are millisecond metrics by intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyMetric {
    BackendTotalMs,
    BackendTtfbMs,
    TotalMs,
    StreamDurationMs,
}

impl LatencyMetric {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BackendTotalMs => "backend_total_ms",
            Self::BackendTtfbMs => "backend_ttfb_ms",
            Self::TotalMs => "total_ms",
            Self::StreamDurationMs => "stream_duration_ms",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    pub resolved_window_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RuleCommon {
    pub id: u32,
    pub name: Arc<str>,
    pub window_seconds: u32,
    pub cooldown_ms: u64,
    pub recovery: Option<RecoveryConfig>,
    pub severity: Severity,
    /// Channel ids (indexes into the plugin's channel table). Resolved at
    /// construction so the hot path does not look up channel names.
    pub channel_ids: Vec<u32>,
    /// Channel names parallel to `channel_ids`, for log/notification body
    /// fields. Sized identically to `channel_ids`.
    pub channel_names: Vec<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct ErrorRateRule {
    pub common: RuleCommon,
    pub status_codes: Vec<u16>,
    pub threshold_percent: f64,
    pub min_request_count: u64,
}

#[derive(Debug, Clone)]
pub struct StatusCodeCountRule {
    pub common: RuleCommon,
    pub status_codes: Vec<u16>,
    pub threshold_count: u64,
}

#[derive(Debug, Clone)]
pub struct LatencyPercentileRule {
    pub common: RuleCommon,
    pub metric: LatencyMetric,
    pub percentile: u8,
    pub threshold_ms: f64,
    pub min_request_count: u64,
}

#[derive(Debug, Clone)]
pub struct ErrorClassRule {
    pub common: RuleCommon,
    pub classes: Vec<ErrorClass>,
    pub threshold_count: u64,
}

#[derive(Debug, Clone)]
pub struct StreamDisconnectCauseRule {
    pub common: RuleCommon,
    pub causes: Vec<DisconnectCause>,
    pub threshold_count: u64,
}

/// Selector for the authoritative terminal gRPC application status.
///
/// Standard codes `0..=16` match exactly. [`GrpcStatusMatch::Other`] matches
/// any status outside that range (malformed `u32::MAX` sentinel and future
/// non-standard codes), mirroring the bounded StatsD/Prometheus `OTHER`
/// bucket. HTTP transport status remains a separate rule dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcStatusMatch {
    Code(u8),
    Other,
}

impl GrpcStatusMatch {
    pub fn matches(self, status: u32) -> bool {
        match self {
            Self::Code(code) => status == u32::from(code),
            Self::Other => status > 16,
        }
    }

    pub fn as_display(&self) -> String {
        match self {
            Self::Code(code) => code.to_string(),
            Self::Other => "OTHER".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GrpcStatusCountRule {
    pub common: RuleCommon,
    pub grpc_statuses: Vec<GrpcStatusMatch>,
    pub threshold_count: u64,
}

#[derive(Debug, Clone)]
pub struct GrpcStatusRateRule {
    pub common: RuleCommon,
    pub grpc_statuses: Vec<GrpcStatusMatch>,
    pub threshold_percent: f64,
    pub min_request_count: u64,
}

#[derive(Debug, Clone)]
pub enum Rule {
    ErrorRate(ErrorRateRule),
    StatusCodeCount(StatusCodeCountRule),
    LatencyPercentile(LatencyPercentileRule),
    ErrorClass(ErrorClassRule),
    StreamDisconnectCause(StreamDisconnectCauseRule),
    GrpcStatusCount(GrpcStatusCountRule),
    GrpcStatusRate(GrpcStatusRateRule),
}

impl Rule {
    pub fn common(&self) -> &RuleCommon {
        match self {
            Self::ErrorRate(r) => &r.common,
            Self::StatusCodeCount(r) => &r.common,
            Self::LatencyPercentile(r) => &r.common,
            Self::ErrorClass(r) => &r.common,
            Self::StreamDisconnectCause(r) => &r.common,
            Self::GrpcStatusCount(r) => &r.common,
            Self::GrpcStatusRate(r) => &r.common,
        }
    }

    pub fn id(&self) -> u32 {
        self.common().id
    }

    #[allow(dead_code)] // Used by external test crate.
    pub fn name(&self) -> &str {
        &self.common().name
    }

    pub fn window_spec(&self) -> RuleWindowSpec {
        let window_seconds = self.common().window_seconds;
        let kind = match self {
            Self::LatencyPercentile(_) => WindowKind::Histogram,
            _ => WindowKind::Counter,
        };
        RuleWindowSpec {
            window_seconds,
            kind,
        }
    }

    pub fn type_str(&self) -> &'static str {
        match self {
            Self::ErrorRate(_) => "error_rate",
            Self::StatusCodeCount(_) => "status_code_count",
            Self::LatencyPercentile(_) => "latency_percentile",
            Self::ErrorClass(_) => "error_class",
            Self::StreamDisconnectCause(_) => "stream_disconnect_cause",
            Self::GrpcStatusCount(_) => "grpc_status_count",
            Self::GrpcStatusRate(_) => "grpc_status_rate",
        }
    }

    pub fn observes_ws_disconnect(&self) -> bool {
        match self {
            Self::LatencyPercentile(r) => r.metric == LatencyMetric::StreamDurationMs,
            Self::ErrorClass(_) | Self::StreamDisconnectCause(_) => true,
            Self::ErrorRate(_)
            | Self::StatusCodeCount(_)
            | Self::GrpcStatusCount(_)
            | Self::GrpcStatusRate(_) => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SampleInput<'a> {
    Http(&'a TransactionSummary),
    Stream(&'a StreamTransactionSummary),
    WebSocket(&'a WsDisconnectContext),
}

impl<'a> SampleInput<'a> {
    pub fn proxy_id(&self) -> Option<&str> {
        match self {
            Self::Http(s) => s.proxy_id.as_deref(),
            Self::Stream(s) => Some(s.proxy_id.as_str()),
            Self::WebSocket(s) => Some(s.proxy_id.as_str()),
        }
    }

    pub fn proxy_lifecycle_generation(&self) -> Option<u64> {
        match self {
            Self::Http(s) => s.proxy_lifecycle_generation,
            Self::Stream(s) => s.proxy_lifecycle_generation,
            Self::WebSocket(s) => s.proxy_lifecycle_generation,
        }
    }

    pub fn proxy_name(&self) -> Option<&str> {
        match self {
            Self::Http(s) => s.proxy_name.as_deref(),
            Self::Stream(s) => s.proxy_name.as_deref(),
            Self::WebSocket(s) => s.proxy_name.as_deref(),
        }
    }

    pub fn namespace(&self) -> &str {
        match self {
            Self::Http(s) => s.namespace.as_str(),
            Self::Stream(s) => s.namespace.as_str(),
            Self::WebSocket(s) => s.namespace.as_str(),
        }
    }
}

/// Outcome of evaluating a rule against the current window state. The
/// plugin uses these to render the dispatched notification.
#[derive(Debug, Clone)]
pub struct RuleObservation {
    /// `true` when the threshold is currently exceeded (subject to
    /// `min_request_count` etc.).
    pub breach: bool,
    /// Total number of samples in the window (denominator for rates,
    /// hit count for counters, total observations for histograms).
    pub sample_count: u64,
    /// Raw observation data. Rendered only when a notification is actually
    /// dispatched so the common non-breaching hot path stays allocation-light.
    detail: RuleObservationDetail,
}

#[derive(Debug, Clone)]
enum RuleObservationDetail {
    ErrorRate {
        matched_total: u64,
        total: u64,
        percent: f64,
    },
    StatusCodeCount {
        matched_total: u64,
    },
    LatencyPercentile {
        estimate_upper_bound_ms: Option<f64>,
    },
    ErrorClass {
        matched_total: u64,
    },
    StreamDisconnectCause {
        matched_total: u64,
    },
    GrpcStatusCount {
        matched_total: u64,
    },
    GrpcStatusRate {
        matched_total: u64,
        total: u64,
        percent: f64,
    },
}

#[derive(Debug, Clone)]
pub struct RenderedRuleObservation {
    pub observed: String,
    pub threshold: String,
    pub reason: String,
}

impl RuleObservation {
    pub fn render(&self, rule: &Rule) -> RenderedRuleObservation {
        match (&self.detail, rule) {
            (
                RuleObservationDetail::ErrorRate {
                    matched_total,
                    total,
                    percent,
                },
                Rule::ErrorRate(rule),
            ) => RenderedRuleObservation {
                observed: format!("{percent:.2}%"),
                threshold: format!("{:.2}%", rule.threshold_percent),
                reason: format!(
                    "{}/{} requests matched {:?} over {}s",
                    matched_total, total, rule.status_codes, rule.common.window_seconds
                ),
            },
            (
                RuleObservationDetail::StatusCodeCount { matched_total },
                Rule::StatusCodeCount(rule),
            ) => RenderedRuleObservation {
                observed: matched_total.to_string(),
                threshold: rule.threshold_count.to_string(),
                reason: format!(
                    "{} requests with status in {:?} over {}s",
                    matched_total, rule.status_codes, rule.common.window_seconds
                ),
            },
            (
                RuleObservationDetail::LatencyPercentile {
                    estimate_upper_bound_ms,
                },
                Rule::LatencyPercentile(rule),
            ) => RenderedRuleObservation {
                observed: estimate_upper_bound_ms
                    .map(format_latency)
                    .unwrap_or_else(|| "n/a".to_string()),
                threshold: format!("{:.0}ms", rule.threshold_ms),
                reason: format!(
                    "p{} of {} over {}s ({} samples)",
                    rule.percentile,
                    rule.metric.as_str(),
                    rule.common.window_seconds,
                    self.sample_count
                ),
            },
            (RuleObservationDetail::ErrorClass { matched_total }, Rule::ErrorClass(rule)) => {
                let class_names: Vec<&'static str> =
                    rule.classes.iter().map(|c| c.as_str()).collect();
                RenderedRuleObservation {
                    observed: matched_total.to_string(),
                    threshold: rule.threshold_count.to_string(),
                    reason: format!(
                        "{} transactions classified as {:?} over {}s",
                        matched_total, class_names, rule.common.window_seconds
                    ),
                }
            }
            (
                RuleObservationDetail::StreamDisconnectCause { matched_total },
                Rule::StreamDisconnectCause(rule),
            ) => {
                let cause_names: Vec<&'static str> = rule
                    .causes
                    .iter()
                    .map(|c| disconnect_cause_str(*c))
                    .collect();
                RenderedRuleObservation {
                    observed: matched_total.to_string(),
                    threshold: rule.threshold_count.to_string(),
                    reason: format!(
                        "{} stream disconnects with cause in {:?} over {}s",
                        matched_total, cause_names, rule.common.window_seconds
                    ),
                }
            }
            (
                RuleObservationDetail::GrpcStatusCount { matched_total },
                Rule::GrpcStatusCount(rule),
            ) => {
                let statuses = format_grpc_status_matches(&rule.grpc_statuses);
                RenderedRuleObservation {
                    observed: matched_total.to_string(),
                    threshold: rule.threshold_count.to_string(),
                    reason: format!(
                        "{matched_total} gRPC transactions with status in {statuses} over {}s",
                        rule.common.window_seconds
                    ),
                }
            }
            (
                RuleObservationDetail::GrpcStatusRate {
                    matched_total,
                    total,
                    percent,
                },
                Rule::GrpcStatusRate(rule),
            ) => {
                let statuses = format_grpc_status_matches(&rule.grpc_statuses);
                RenderedRuleObservation {
                    observed: format!("{percent:.2}%"),
                    threshold: format!("{:.2}%", rule.threshold_percent),
                    reason: format!(
                        "{matched_total}/{total} gRPC transactions matched {statuses} over {}s",
                        rule.common.window_seconds
                    ),
                }
            }
            _ => RenderedRuleObservation {
                observed: "n/a".to_string(),
                threshold: "n/a".to_string(),
                reason: "rule observation mismatch".to_string(),
            },
        }
    }
}

impl Rule {
    /// Record the sample (when applicable) and return an observation if the
    /// rule is interested in this sample type. Returns `None` for rules
    /// whose sample family doesn't apply (e.g., HTTP-only rules on stream
    /// disconnects, stream-only rules on HTTP transactions).
    pub fn observe<'a>(
        &self,
        sample: SampleInput<'a>,
        store: &WindowStore,
        now_ms: u64,
    ) -> Option<RuleObservation> {
        let proxy_id = sample.proxy_id()?;
        // Offline / unarmed unit tests omit an admission token; production
        // armed paths fail closed before observe when the token is missing.
        let ownership_generation = sample
            .proxy_lifecycle_generation()
            .unwrap_or(super::UNARMED_PROXY_LIFECYCLE_GENERATION);
        // Key window rows by the namespace-qualified lifecycle identity
        // (`namespace|id`) so the same proxy id in two tenants never shares a
        // window. Zero allocation beyond the reusable thread-local buffer; the
        // returned observation owns its counts and never borrows the buffer.
        OWNER_KEY_BUF.with(|buf| {
            let mut owner = buf.borrow_mut();
            crate::config::db_backend::write_namespaced_runtime_key(
                &mut owner,
                sample.namespace(),
                proxy_id,
            );
            let owner_key = owner.as_str();
            match self {
                Rule::ErrorRate(r) => {
                    observe_error_rate(r, sample, owner_key, ownership_generation, store, now_ms)
                }
                Rule::StatusCodeCount(r) => observe_status_code_count(
                    r,
                    sample,
                    owner_key,
                    ownership_generation,
                    store,
                    now_ms,
                ),
                Rule::LatencyPercentile(r) => observe_latency_percentile(
                    r,
                    sample,
                    owner_key,
                    ownership_generation,
                    store,
                    now_ms,
                ),
                Rule::ErrorClass(r) => {
                    observe_error_class(r, sample, owner_key, ownership_generation, store, now_ms)
                }
                Rule::StreamDisconnectCause(r) => observe_stream_disconnect(
                    r,
                    sample,
                    owner_key,
                    ownership_generation,
                    store,
                    now_ms,
                ),
                Rule::GrpcStatusCount(r) => observe_grpc_status_count(
                    r,
                    sample,
                    owner_key,
                    ownership_generation,
                    store,
                    now_ms,
                ),
                Rule::GrpcStatusRate(r) => observe_grpc_status_rate(
                    r,
                    sample,
                    owner_key,
                    ownership_generation,
                    store,
                    now_ms,
                ),
            }
        })
    }
}

fn observe_error_rate(
    rule: &ErrorRateRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Http(s) = sample else {
        return None;
    };
    let matched = rule.status_codes.contains(&s.response_status_code);
    store.record_count(
        rule.common.id,
        proxy_id,
        ownership_generation,
        matched,
        now_ms,
    );
    let (matched_total, total) =
        store.snapshot_count(rule.common.id, proxy_id, ownership_generation, now_ms);
    let percent = if total == 0 {
        0.0
    } else {
        (matched_total as f64 / total as f64) * 100.0
    };
    let breach = total >= rule.min_request_count && percent >= rule.threshold_percent;
    Some(RuleObservation {
        breach,
        sample_count: total,
        detail: RuleObservationDetail::ErrorRate {
            matched_total,
            total,
            percent,
        },
    })
}

fn observe_status_code_count(
    rule: &StatusCodeCountRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Http(s) = sample else {
        return None;
    };
    let matched = rule.status_codes.contains(&s.response_status_code);
    store.record_count(
        rule.common.id,
        proxy_id,
        ownership_generation,
        matched,
        now_ms,
    );
    let (matched_total, _) =
        store.snapshot_count(rule.common.id, proxy_id, ownership_generation, now_ms);
    let breach = matched_total >= rule.threshold_count;
    Some(RuleObservation {
        breach,
        sample_count: matched_total,
        detail: RuleObservationDetail::StatusCodeCount { matched_total },
    })
}

fn observe_latency_percentile(
    rule: &LatencyPercentileRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let latency = match (rule.metric, sample) {
        (LatencyMetric::BackendTotalMs, SampleInput::Http(s)) => s.latency_backend_total_ms,
        (LatencyMetric::BackendTtfbMs, SampleInput::Http(s)) => s.latency_backend_ttfb_ms,
        (LatencyMetric::TotalMs, SampleInput::Http(s)) => s.latency_total_ms,
        (LatencyMetric::StreamDurationMs, SampleInput::Stream(s)) => s.duration_ms,
        (LatencyMetric::StreamDurationMs, SampleInput::WebSocket(s)) => s.duration_ms,
        _ => return None,
    };
    if latency < 0.0 || !latency.is_finite() {
        // Sentinel value (-1.0) or NaN — skip recording but still return
        // a snapshot-based observation. Sentinel samples must not clear an
        // already-breached latency window.
        let (estimate, total) = store.snapshot_percentile(
            rule.common.id,
            proxy_id,
            ownership_generation,
            rule.percentile,
            now_ms,
        );
        let breach = latency_estimate_breaches(estimate, total, rule);
        return Some(RuleObservation {
            breach,
            sample_count: total,
            detail: RuleObservationDetail::LatencyPercentile {
                estimate_upper_bound_ms: estimate,
            },
        });
    }
    store.record_latency(
        rule.common.id,
        proxy_id,
        ownership_generation,
        latency,
        now_ms,
    );
    let (estimate, total) = store.snapshot_percentile(
        rule.common.id,
        proxy_id,
        ownership_generation,
        rule.percentile,
        now_ms,
    );
    let breach = latency_estimate_breaches(estimate, total, rule);
    Some(RuleObservation {
        breach,
        sample_count: total,
        detail: RuleObservationDetail::LatencyPercentile {
            estimate_upper_bound_ms: estimate,
        },
    })
}

fn latency_estimate_breaches(
    estimate_upper_bound_ms: Option<f64>,
    total: u64,
    rule: &LatencyPercentileRule,
) -> bool {
    total >= rule.min_request_count
        && estimate_upper_bound_ms
            // Percentiles are fixed-bucket estimates. Use a strict comparison
            // against the bucket upper bound so thresholds that fall inside a
            // bucket can still fire, while a threshold exactly on a bucket
            // boundary does not fire for samples from the previous bucket.
            .map(|estimate| estimate > rule.threshold_ms)
            .unwrap_or(false)
}

fn observe_error_class(
    rule: &ErrorClassRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let matched = match sample {
        SampleInput::Http(s) => {
            s.error_class.is_some_and(|c| rule.classes.contains(&c))
                || s.body_error_class
                    .is_some_and(|c| rule.classes.contains(&c))
        }
        SampleInput::Stream(s) => s.error_class.is_some_and(|c| rule.classes.contains(&c)),
        SampleInput::WebSocket(s) => s.error_class.is_some_and(|c| rule.classes.contains(&c)),
    };
    store.record_count(
        rule.common.id,
        proxy_id,
        ownership_generation,
        matched,
        now_ms,
    );
    let (matched_total, _) =
        store.snapshot_count(rule.common.id, proxy_id, ownership_generation, now_ms);
    let breach = matched_total >= rule.threshold_count;
    Some(RuleObservation {
        breach,
        sample_count: matched_total,
        detail: RuleObservationDetail::ErrorClass { matched_total },
    })
}

fn observe_stream_disconnect(
    rule: &StreamDisconnectCauseRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let cause = match sample {
        SampleInput::Stream(s) => s.disconnect_cause,
        SampleInput::WebSocket(s) => Some(websocket_disconnect_cause(s)),
        SampleInput::Http(_) => return None,
    };
    let matched = match cause {
        Some(c) => rule.causes.contains(&c),
        None => false,
    };
    store.record_count(
        rule.common.id,
        proxy_id,
        ownership_generation,
        matched,
        now_ms,
    );
    let (matched_total, _) =
        store.snapshot_count(rule.common.id, proxy_id, ownership_generation, now_ms);
    let breach = matched_total >= rule.threshold_count;
    Some(RuleObservation {
        breach,
        sample_count: matched_total,
        detail: RuleObservationDetail::StreamDisconnectCause { matched_total },
    })
}

fn observe_grpc_status_count(
    rule: &GrpcStatusCountRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Http(s) = sample else {
        return None;
    };
    // Plain HTTP never enters this rule's window. Snapshotting at `now_ms`
    // still expires old buckets and lets recovery advance without an
    // avoidable write for every non-gRPC transaction.
    // Evaluation runs from `log()` after terminal completion (buffered,
    // trailers-only, streamed H2/H3, and gateway-generated rejections), so
    // trailer-borne statuses are visible before this sample is counted.
    if let Some(status) = s.grpc_status() {
        let matched = grpc_status_matches(&rule.grpc_statuses, status);
        store.record_count(
            rule.common.id,
            proxy_id,
            ownership_generation,
            matched,
            now_ms,
        );
    }
    let (matched_total, _) =
        store.snapshot_count(rule.common.id, proxy_id, ownership_generation, now_ms);
    let breach = matched_total >= rule.threshold_count;
    Some(RuleObservation {
        breach,
        sample_count: matched_total,
        detail: RuleObservationDetail::GrpcStatusCount { matched_total },
    })
}

fn observe_grpc_status_rate(
    rule: &GrpcStatusRateRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    ownership_generation: u64,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Http(s) = sample else {
        return None;
    };
    // Denominator is gRPC transactions only so plain HTTP does not dilute
    // the rate. Non-gRPC HTTP still returns a snapshot observation so
    // recovery/resolve can progress without recording into the window.
    if let Some(status) = s.grpc_status() {
        let matched = grpc_status_matches(&rule.grpc_statuses, status);
        store.record_count(
            rule.common.id,
            proxy_id,
            ownership_generation,
            matched,
            now_ms,
        );
    }
    let (matched_total, total) =
        store.snapshot_count(rule.common.id, proxy_id, ownership_generation, now_ms);
    let percent = if total == 0 {
        0.0
    } else {
        (matched_total as f64 / total as f64) * 100.0
    };
    let breach = total >= rule.min_request_count && percent >= rule.threshold_percent;
    Some(RuleObservation {
        breach,
        sample_count: total,
        detail: RuleObservationDetail::GrpcStatusRate {
            matched_total,
            total,
            percent,
        },
    })
}

fn grpc_status_matches(selectors: &[GrpcStatusMatch], status: u32) -> bool {
    selectors.iter().any(|selector| selector.matches(status))
}

fn format_grpc_status_matches(selectors: &[GrpcStatusMatch]) -> String {
    let rendered: Vec<String> = selectors.iter().map(GrpcStatusMatch::as_display).collect();
    format!("{rendered:?}")
}

fn websocket_disconnect_cause(ctx: &WsDisconnectContext) -> DisconnectCause {
    let Some(class) = ctx.error_class else {
        return DisconnectCause::GracefulShutdown;
    };
    match ctx.direction {
        Some(direction) => {
            crate::proxy::tcp_proxy::disconnect_cause_for_failure(direction, &class, ctx.io_side)
        }
        None if class == ErrorClass::ReadWriteTimeout => DisconnectCause::IdleTimeout,
        None => DisconnectCause::RecvError,
    }
}

fn disconnect_cause_str(c: DisconnectCause) -> &'static str {
    match c {
        DisconnectCause::IdleTimeout => "idle_timeout",
        DisconnectCause::RecvError => "recv_error",
        DisconnectCause::BackendError => "backend_error",
        DisconnectCause::GracefulShutdown => "graceful_shutdown",
    }
}

fn format_latency(v: f64) -> String {
    if v.is_infinite() {
        format!(">{MAX_FINITE_LATENCY_BOUND_MS}ms")
    } else {
        format!("{:.0}ms", v)
    }
}
