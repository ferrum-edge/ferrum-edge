//! Bounded-cardinality notification delivery metrics.
//!
//! Every counter/gauge is labeled by the fixed [`super::outcome::CHANNEL_TYPES`]
//! set (`slack` / `teams` / `discord` / `webhook` / `email`), and the two
//! non-outcome families additionally by a fixed `reason` drawn from
//! [`REJECT_REASONS`] / [`ABANDON_REASONS`]. Operator-chosen channel *names*,
//! endpoint URLs, and peer-supplied strings never appear as labels, so the
//! whole subsystem is bounded at 5 series per single-label family, 10 for
//! `rejected_total`, and 15 for `abandoned_total`.
//!
//! Process-wide tallies dual-write into authenticated `/metrics` via
//! [`render_prometheus`]. Per-plugin-instance snapshots are available for
//! deterministic external tests through [`DeliveryMetrics::snapshot`].

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::outcome::{ABANDON_REASONS, AbandonReason, CHANNEL_TYPES, REJECT_REASONS};

/// Index into the fixed channel-type arrays. Out-of-range maps to webhook as a
/// defensive fallback so a future discriminant cannot panic hot paths.
#[inline]
fn channel_index(channel_type: &str) -> usize {
    match channel_type {
        "slack" => 0,
        "teams" => 1,
        "discord" => 2,
        "webhook" => 3,
        "email" => 4,
        _ => 3,
    }
}

/// Process-wide delivery counters/gauges keyed by channel type.
///
/// The accounting invariant, per channel type, is:
///
/// ```text
/// attempted == succeeded + failed_transient + failed_permanent
///            + sum(abandoned[*]) + in_flight
/// ```
///
/// `attempted` advances when the registry-owned delivery **body starts**, not
/// when the first channel transport call is polled. An admit-then-cancel race
/// can therefore increment `attempted` with no bytes on the wire; that is the
/// documented contract, not a hole. Pre-body drops (`backpressure_dropped`,
/// `rejected[*]`) stay outside the identity so the success ratio is not
/// understated by admission refusals.
#[derive(Debug)]
pub struct DeliveryMetrics {
    attempted: [AtomicU64; 5],
    succeeded: [AtomicU64; 5],
    failed_transient: [AtomicU64; 5],
    failed_permanent: [AtomicU64; 5],
    backpressure_dropped: [AtomicU64; 5],
    /// `[reject_reason_index][channel_index]` — admitted past the semaphore but
    /// the registry-owned delivery body never started.
    rejected: [[AtomicU64; 5]; 2],
    /// `[abandon_reason_index][channel_index]` — the delivery body started but
    /// produced no committed outcome (transport may or may not have run).
    abandoned: [[AtomicU64; 5]; 3],
    /// The `shutdown_deadline` slice of `abandoned`, kept as its own family
    /// because #2448 requires that exact signal.
    abandoned_at_deadline: [AtomicU64; 5],
    in_flight: [AtomicI64; 5],
}

impl Default for DeliveryMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryMetrics {
    pub const fn new() -> Self {
        Self {
            attempted: [const { AtomicU64::new(0) }; 5],
            succeeded: [const { AtomicU64::new(0) }; 5],
            failed_transient: [const { AtomicU64::new(0) }; 5],
            failed_permanent: [const { AtomicU64::new(0) }; 5],
            backpressure_dropped: [const { AtomicU64::new(0) }; 5],
            rejected: [const { [const { AtomicU64::new(0) }; 5] }; 2],
            abandoned: [const { [const { AtomicU64::new(0) }; 5] }; 3],
            abandoned_at_deadline: [const { AtomicU64::new(0) }; 5],
            in_flight: [const { AtomicI64::new(0) }; 5],
        }
    }

    pub fn record_attempted(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.attempted[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_succeeded(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.succeeded[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_failed_transient(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.failed_transient[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_failed_permanent(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.failed_permanent[i].fetch_add(1, Ordering::Relaxed);
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_backpressure_dropped(&self, channel_type: &str) {
        let i = channel_index(channel_type);
        self.backpressure_dropped[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a *pre-body* rejection: admitted past the semaphore but the
    /// registry-owned delivery body never started, so neither `attempted` nor
    /// `in_flight` was ever reserved and neither is touched here.
    ///
    /// [`AbandonReason::Backpressure`] is a no-op: semaphore exhaustion keeps
    /// its own `backpressure_dropped_total` family so no drop is double
    /// counted.
    pub fn record_rejected(&self, channel_type: &str, reason: AbandonReason) {
        let Some(r) = reason.reject_index() else {
            return;
        };
        self.rejected[r][channel_index(channel_type)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a *post-body* abandonment: the delivery body started and settled
    /// without a committed success/failure, so it releases the `in_flight`
    /// reservation `record_attempted` took. Channel transport may or may not
    /// have been polled (admit-then-cancel can abandon before the first call).
    ///
    /// `abandoned_at_deadline` advances only for the true hard shutdown
    /// deadline abort; reload retirement, registry-side cancellation and task
    /// drops are visible under their own `reason` label instead.
    pub fn record_abandoned(&self, channel_type: &str, reason: AbandonReason) {
        let i = channel_index(channel_type);
        if let Some(r) = reason.abandon_index() {
            self.abandoned[r][i].fetch_add(1, Ordering::Relaxed);
        }
        if reason.is_shutdown_deadline() {
            self.abandoned_at_deadline[i].fetch_add(1, Ordering::Relaxed);
        }
        self.in_flight[i].fetch_sub(1, Ordering::Relaxed);
    }

    /// Plain snapshot for external tests. Values are process-wide unless the
    /// caller constructed an isolated [`DeliveryMetrics`].
    pub fn snapshot(&self) -> DeliveryMetricsSnapshot {
        let mut out = DeliveryMetricsSnapshot::default();
        for (i, slot) in out.by_channel.iter_mut().enumerate() {
            *slot = self.channel_snapshot_at(i);
        }
        out
    }

    pub fn channel_snapshot(&self, channel_type: &str) -> ChannelMetricsSnapshot {
        self.channel_snapshot_at(channel_index(channel_type))
    }

    fn channel_snapshot_at(&self, i: usize) -> ChannelMetricsSnapshot {
        let rejected = std::array::from_fn(|r| self.rejected[r][i].load(Ordering::Relaxed));
        let abandoned = std::array::from_fn(|r| self.abandoned[r][i].load(Ordering::Relaxed));
        ChannelMetricsSnapshot {
            channel_type: CHANNEL_TYPES[i],
            attempted: self.attempted[i].load(Ordering::Relaxed),
            succeeded: self.succeeded[i].load(Ordering::Relaxed),
            failed_transient: self.failed_transient[i].load(Ordering::Relaxed),
            failed_permanent: self.failed_permanent[i].load(Ordering::Relaxed),
            backpressure_dropped: self.backpressure_dropped[i].load(Ordering::Relaxed),
            rejected,
            abandoned,
            abandoned_at_deadline: self.abandoned_at_deadline[i].load(Ordering::Relaxed),
            in_flight: self.in_flight[i].load(Ordering::Relaxed),
        }
    }
}

/// Per-channel-type plain snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelMetricsSnapshot {
    pub channel_type: &'static str,
    pub attempted: u64,
    pub succeeded: u64,
    pub failed_transient: u64,
    pub failed_permanent: u64,
    pub backpressure_dropped: u64,
    /// Pre-body rejections, indexed by [`REJECT_REASONS`].
    pub rejected: [u64; 2],
    /// Post-body abandonment, indexed by [`ABANDON_REASONS`].
    pub abandoned: [u64; 3],
    /// The `shutdown_deadline` slice of [`Self::abandoned`].
    pub abandoned_at_deadline: u64,
    pub in_flight: i64,
}

impl ChannelMetricsSnapshot {
    /// Pre-body rejections for one fixed reason (0 for a reason that is not a
    /// rejection, including `Backpressure`).
    pub fn rejected_for(&self, reason: AbandonReason) -> u64 {
        reason.reject_index().map_or(0, |r| self.rejected[r])
    }

    /// Post-body abandonment for one fixed reason.
    pub fn abandoned_for(&self, reason: AbandonReason) -> u64 {
        reason.abandon_index().map_or(0, |r| self.abandoned[r])
    }

    pub fn total_rejected(&self) -> u64 {
        self.rejected.iter().sum()
    }

    pub fn total_abandoned(&self) -> u64 {
        self.abandoned.iter().sum()
    }
}

/// Full process (or test-isolated) snapshot across every channel type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryMetricsSnapshot {
    pub by_channel: [ChannelMetricsSnapshot; 5],
}

impl DeliveryMetricsSnapshot {
    pub fn for_channel(&self, channel_type: &str) -> ChannelMetricsSnapshot {
        self.by_channel[channel_index(channel_type)]
    }

    pub fn total_attempted(&self) -> u64 {
        self.by_channel.iter().map(|c| c.attempted).sum()
    }

    pub fn total_backpressure_dropped(&self) -> u64 {
        self.by_channel.iter().map(|c| c.backpressure_dropped).sum()
    }

    /// Every post-body abandonment, across all reasons.
    pub fn total_abandoned(&self) -> u64 {
        self.by_channel.iter().map(|c| c.total_abandoned()).sum()
    }

    /// Only the true hard shutdown-deadline aborts.
    pub fn total_abandoned_at_deadline(&self) -> u64 {
        self.by_channel
            .iter()
            .map(|c| c.abandoned_at_deadline)
            .sum()
    }

    /// Every pre-body admission/registry rejection (excluding backpressure,
    /// which has its own counter).
    pub fn total_rejected(&self) -> u64 {
        self.by_channel.iter().map(|c| c.total_rejected()).sum()
    }
}

static GLOBAL: OnceLock<Arc<DeliveryMetrics>> = OnceLock::new();

/// Process-wide metrics shared by every notification producer.
pub fn global() -> &'static Arc<DeliveryMetrics> {
    GLOBAL.get_or_init(|| Arc::new(DeliveryMetrics::new()))
}

/// Render Prometheus text for authenticated `/metrics`.
///
/// Always emits the full fixed channel-type series (including zeros) so
/// dashboards and recording rules have a stable contract from first scrape.
pub fn render_prometheus() -> String {
    let m = global();
    let mut out = String::with_capacity(4096);
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_attempted_total",
        "Notification delivery tasks whose registry-owned delivery body started executing (counted once per admitted task, not once per bounded retry; may advance before any channel transport call).",
        &m.attempted,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_succeeded_total",
        "Notification deliveries that completed successfully (after any bounded retries).",
        &m.succeeded,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_failed_transient_total",
        "Notification deliveries that exhausted retries on transient transport/HTTP failures.",
        &m.failed_transient,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_failed_permanent_total",
        "Notification deliveries that failed with a permanent (non-retryable) outcome.",
        &m.failed_permanent,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_backpressure_dropped_total",
        "Notification deliveries dropped because the bounded dispatch semaphore was exhausted.",
        &m.backpressure_dropped,
    );
    render_reason_family(
        &mut out,
        "ferrum_notification_delivery_rejected_total",
        "Notification deliveries rejected before the registry-owned delivery body started, by fixed reason (generation_closed = producer reload/Drop closed admission, registry_rejected = process delivery registry refused the task).",
        REJECT_REASONS,
        &m.rejected,
    );
    render_reason_family(
        &mut out,
        "ferrum_notification_delivery_abandoned_total",
        "Notification delivery tasks whose body started executing but settled without a committed outcome, by fixed reason (generation_retired = producer reload/Drop, shutdown_deadline = hard abort at the global drain deadline, task_dropped = dispatch task dropped without settling).",
        ABANDON_REASONS,
        &m.abandoned,
    );
    render_counter_family(
        &mut out,
        "ferrum_notification_delivery_abandoned_at_deadline_total",
        "Notification deliveries hard-aborted because the global observability shutdown drain deadline expired; the shutdown_deadline slice of ferrum_notification_delivery_abandoned_total.",
        &m.abandoned_at_deadline,
    );
    out.push_str(
        "# HELP ferrum_notification_delivery_in_flight Notification deliveries currently executing (including bounded retry backoff).\n",
    );
    out.push_str("# TYPE ferrum_notification_delivery_in_flight gauge\n");
    for (i, kind) in CHANNEL_TYPES.iter().enumerate() {
        let value = m.in_flight[i].load(Ordering::Relaxed);
        out.push_str(&format!(
            "ferrum_notification_delivery_in_flight{{channel_type=\"{kind}\"}} {value}\n"
        ));
    }
    out
}

fn render_counter_family(out: &mut String, name: &str, help: &str, values: &[AtomicU64; 5]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for (i, kind) in CHANNEL_TYPES.iter().enumerate() {
        let value = values[i].load(Ordering::Relaxed);
        out.push_str(&format!("{name}{{channel_type=\"{kind}\"}} {value}\n"));
    }
}

/// Render a `{channel_type, reason}` family over the compiled-in reason set.
///
/// Cardinality is `CHANNEL_TYPES.len() * reasons.len()` and both are fixed
/// slices of `&'static str` discriminants, so no operator- or peer-supplied
/// value can ever reach a label here.
fn render_reason_family(
    out: &mut String,
    name: &str,
    help: &str,
    reasons: &[AbandonReason],
    values: &[[AtomicU64; 5]],
) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for (r, reason) in reasons.iter().enumerate() {
        let reason = reason.as_str();
        for (i, kind) in CHANNEL_TYPES.iter().enumerate() {
            let value = values[r][i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "{name}{{channel_type=\"{kind}\",reason=\"{reason}\"}} {value}\n"
            ));
        }
    }
}
