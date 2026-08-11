//! Bounded age for the DP's last-known-good configuration (issue #3726).
//!
//! A data plane that has accepted one configuration snapshot keeps serving it
//! while every control plane is unreachable. That preserves availability, but
//! without a bound it also means an operator can never be sure a revocation, a
//! deleted route, an emergency authorization change, or a rotated credential
//! has actually taken effect: the DP stays green forever behind a load
//! balancer while its authority is gone.
//!
//! This module is the safety boundary for that window:
//!
//! * The age is measured with [`Instant`] — a monotonic clock — from the last
//!   snapshot that was **validated and successfully applied**. A wall-clock
//!   step (NTP correction, operator `date`, VM restore) can neither extend nor
//!   shorten the window.
//! * Heartbeats, reconnect attempts, CP transport success, rejected/fenced
//!   snapshots, rejected deltas, and snapshots that fail to apply all leave the
//!   age untouched. Only [`DpConfigFreshness::record_snapshot_applied`] resets
//!   it.
//! * The configured bound is the **maximum**, never a floor with a grace period
//!   bolted on top: there is no additional time window anywhere in the
//!   predicate. What distinguishes a routine failover from a real loss of
//!   authority is the [`CpAuthority`] state the outer `dp_client` loop
//!   publishes, not elapsed time. A DP that is between two CP attempts is
//!   [`CpAuthority::Reconnecting`] and does not latch; a DP whose reconnect
//!   attempt actually failed is [`CpAuthority::Lost`] and latches the instant
//!   the applied snapshot reaches the bound.
//! * Once the DP has gone stale, recovery requires an applied snapshot.
//!   Reconnecting alone does not restore readiness or traffic admission — the
//!   sticky flag clears in `record_snapshot_applied` and nowhere else.
//!
//! Two operator-visible effects at the threshold:
//!
//! 1. Readiness degrades (`/health` reports `ready: false`, status
//!    `unavailable`), so orchestrators stop steering new traffic at the pod.
//! 2. Under the default [`StaleAction::FailClosed`], new HTTP/1.1, HTTP/2,
//!    HTTP/3, TCP, UDP-session, and DTLS-session admissions are refused at the
//!    proxy boundary while already-accepted work drains normally.
//!    [`StaleAction::ReadinessOnly`] is the explicitly named compatibility mode
//!    that degrades readiness only.
//!
//! The hot path cost is one relaxed atomic load ([`new_traffic_blocked`]) on a
//! process-global word that only a data plane ever writes, so every other mode
//! reads a constant `0`.
//!
//! # Race safety
//!
//! Staleness and its published admission bit are **generation-aware**. The
//! state word packs a monotonically increasing generation with the sticky stale
//! bit (`generation << 1 | stale`), and every published value is installed with
//! a monotonic compare-and-swap. A background evaluator that started computing
//! before a valid snapshot applied therefore cannot commit its verdict after
//! the recovery: its CAS targets a word the apply already replaced. A valid
//! apply always wins over every evaluation based on an older generation, and no
//! old evaluation can re-block a recovered generation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Notify;

/// Process-global admission word read by the proxy request/connection paths.
///
/// Layout matches [`DpConfigFreshness::state`]: `generation << 1 | blocked`.
/// Publishing the *whole* decision in one word (rather than a separate bool
/// beside a state machine) is what makes publication race-safe — a monotonic
/// CAS on this single location cannot be clobbered by a stale evaluator, and
/// the hot path still reads exactly one relaxed atomic.
///
/// Deliberately a plain static rather than a field on `ProxyState`: the value
/// is process-wide, and a `static` keeps the hot-path check to one relaxed load
/// with no pointer chase. Only the installed global [`DpConfigFreshness`] (DP
/// mode) ever writes it, so unit tests that build their own instances cannot
/// perturb an unrelated process.
static ADMISSION: AtomicU64 = AtomicU64::new(0);

/// The installed DP freshness tracker, if this process is a data plane.
static GLOBAL: OnceLock<Arc<DpConfigFreshness>> = OnceLock::new();

/// Whether new traffic must be refused because the applied configuration is
/// stale beyond the configured bound.
///
/// One `Relaxed` load (~1ns, no-op on x86). `Relaxed` is sufficient: the word
/// is an advisory admission gate with no other state published alongside it,
/// and a request that observes the previous value simply lands on the other
/// side of a boundary it was already racing.
#[inline]
pub fn new_traffic_blocked() -> bool {
    ADMISSION.load(Ordering::Relaxed) & STALE_BIT != 0
}

/// The installed DP freshness tracker (`None` outside DP mode).
pub fn global() -> Option<&'static Arc<DpConfigFreshness>> {
    GLOBAL.get()
}

/// Install the process-wide DP freshness tracker.
///
/// Idempotent: a second call (a test harness starting a second DP runtime in
/// one process) returns the already-installed tracker rather than replacing it,
/// so the admission gate can never be silently re-pointed at a fresh instance
/// with a zeroed age.
pub fn install(max_stale: Duration, action: StaleAction) -> Arc<DpConfigFreshness> {
    GLOBAL
        .get_or_init(|| Arc::new(DpConfigFreshness::new_publishing(max_stale, action)))
        .clone()
}

/// What the DP does for *new* traffic once its applied configuration is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleAction {
    /// Degrade readiness **and** refuse new request/connection/session
    /// admissions. Already-accepted connections, sessions, and in-flight
    /// requests are untouched and drain normally.
    FailClosed,
    /// Compatibility mode: degrade readiness only, keep admitting new traffic.
    /// Deliberately named so choosing it is a recorded operator decision.
    ReadinessOnly,
}

impl StaleAction {
    /// Parse `FERRUM_DP_CONFIG_STALE_ACTION`.
    ///
    /// The accepted set is exactly the two documented spellings. No case
    /// folding, no dash aliases, no surrounding whitespace: this is a new
    /// build-out setting with no compatibility history, and an accepted alias
    /// that the documentation and the error message both deny is a
    /// configuration surface nobody can reason about. Unknown values fail
    /// closed with an operator-actionable message rather than defaulting to the
    /// weaker mode.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "fail_closed" => Ok(Self::FailClosed),
            "readiness_only" => Ok(Self::ReadinessOnly),
            other => Err(format!(
                "FERRUM_DP_CONFIG_STALE_ACTION must be 'fail_closed' or \
                 'readiness_only', got '{other}'"
            )),
        }
    }

    /// Stable label for metrics, logs, and admin diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::ReadinessOnly => "readiness_only",
        }
    }
}

/// Whether the DP currently has an authoritative configuration source.
///
/// This is the safety input the outer `dp_client` loop owns. It exists so the
/// boundary needs no second time window: "am I between two attempts?" and "did
/// my attempt fail?" are events the reconnect loop already knows, and only the
/// second one is a loss of authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpAuthority {
    /// A ConfigSync stream to some CP is established.
    Connected,
    /// The stream ended for a reason that is not itself evidence of authority
    /// loss — an intentional primary-retry or TLS-rotation reconnect, or a
    /// healthy session that ended after delivering config — and the next
    /// attempt has not resolved yet. The DP does not latch stale here: a
    /// successful handoff to a fallback or alternate CP must not blip traffic.
    Reconnecting,
    /// No CP is authoritative: a connect/subscribe attempt failed, or a stream
    /// ended without ever delivering usable authoritative config. This is the
    /// only state in which the bound can latch, so the detection latency is
    /// exactly one failed transport attempt and never a configured grace.
    Lost,
}

impl CpAuthority {
    fn encode(self) -> u8 {
        match self {
            Self::Connected => 0,
            Self::Reconnecting => 1,
            Self::Lost => 2,
        }
    }

    fn decode(value: u8) -> Self {
        match value {
            0 => Self::Connected,
            1 => Self::Reconnecting,
            _ => Self::Lost,
        }
    }

    /// Stable label for admin diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Lost => "lost",
        }
    }
}

/// Closed set of reason labels. Fixed cardinality: safe as a metric label and
/// as an admin diagnostic field, and it carries no CP endpoint, credential,
/// namespace, or other unbounded identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessReason {
    /// Connected to a CP with an applied snapshot inside the bound.
    Ok,
    /// No snapshot has ever been validated and applied on this process.
    AwaitingFirstSnapshot,
    /// No CP is connected, but the applied snapshot is still inside the bound.
    CpDisconnected,
    /// The applied snapshot has aged past the configured bound with no CP.
    SnapshotStale,
    /// The most recent CP payload was refused before apply (fenced snapshot or
    /// rejected delta). Last-known-good config keeps serving.
    SnapshotRejected,
    /// The most recent CP snapshot passed admission but failed to apply.
    SnapshotApplyFailed,
}

impl FreshnessReason {
    /// Stable label for metrics, logs, and admin diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::AwaitingFirstSnapshot => "awaiting_first_snapshot",
            Self::CpDisconnected => "cp_disconnected",
            Self::SnapshotStale => "snapshot_stale",
            Self::SnapshotRejected => "snapshot_rejected",
            Self::SnapshotApplyFailed => "snapshot_apply_failed",
        }
    }
}

/// Last CP config outcome, encoded for the `last_outcome` atomic.
const OUTCOME_NONE: u8 = 0;
const OUTCOME_APPLIED: u8 = 1;
const OUTCOME_REJECTED: u8 = 2;
const OUTCOME_APPLY_FAILED: u8 = 3;

/// Low bit of a state/admission word: sticky stale (state) or blocked
/// (admission). The remaining bits are the generation.
const STALE_BIT: u64 = 1;

/// Fixed-cardinality projection of the freshness state for `/health`, the
/// Prometheus render pass, and tests.
#[derive(Clone, Debug, Serialize)]
pub struct DpConfigFreshnessSnapshot {
    /// Whether the applied configuration is currently past its bound.
    pub stale: bool,
    /// Closed-set reason label (see [`FreshnessReason`]).
    pub reason: &'static str,
    /// Configured stale action (`fail_closed` / `readiness_only`).
    pub stale_action: &'static str,
    /// Whether new traffic is currently refused at the proxy boundary.
    pub new_traffic_blocked: bool,
    /// Whether a ConfigSync stream to some CP is currently established.
    pub cp_connected: bool,
    /// Closed-set CP authority state (`connected` / `reconnecting` / `lost`).
    /// Only `lost` can latch the bound.
    pub cp_authority: &'static str,
    /// How long every CP has been unreachable, in seconds. `0` while connected.
    pub cp_disconnected_seconds: u64,
    /// Configured bound in seconds. `0` means the bound is disabled.
    pub max_stale_seconds: u64,
    /// Whether any snapshot has ever been validated and applied.
    pub applied_snapshot: bool,
    /// Age of the last applied snapshot in seconds. With no applied snapshot
    /// this is the age of the tracker itself (process start), which is what the
    /// bound is measured against on a DP that never reached a CP.
    pub snapshot_age_seconds: u64,
    /// Snapshots/deltas validated and applied since process start.
    pub applied_total: u64,
    /// CP payloads refused before apply since process start.
    pub rejected_total: u64,
    /// CP snapshots that failed during apply since process start.
    pub apply_failed_total: u64,
    /// Transitions into the stale state since process start.
    pub stale_transitions_total: u64,
}

/// Monotonic freshness accounting for the DP's applied configuration.
pub struct DpConfigFreshness {
    /// Configured bound. `Duration::ZERO` disables the bound entirely.
    max_stale: Duration,
    action: StaleAction,
    /// Monotonic base. All stamps are millisecond offsets from here, so no
    /// wall-clock source participates in the age at any point.
    epoch: Instant,
    /// `generation << 1 | stale`. The generation increments on every applied
    /// snapshot; the stale bit is sticky within a generation and is cleared
    /// only by the generation bump itself.
    state: AtomicU64,
    /// Offset of the last applied snapshot, stored as `offset_ms + 1` so `0`
    /// can mean "never applied" without a separate flag. Written **before** the
    /// generation bump, so an evaluator that observed the older generation and
    /// then reads this cannot commit (its CAS fails).
    last_applied_ms: AtomicU64,
    /// Offset at which the current CP outage began, stored as `offset_ms + 1`
    /// so `0` can mean "a CP is connected". Diagnostic only — the staleness
    /// predicate does not read it, because the bound is the applied-snapshot
    /// age and nothing else. Set once per outage: repeated failover attempts
    /// against successive CP URLs must not restart it.
    disconnected_since_ms: AtomicU64,
    /// [`CpAuthority`], encoded.
    authority: AtomicU8,
    last_outcome: AtomicU8,
    applied_total: AtomicU64,
    rejected_total: AtomicU64,
    apply_failed_total: AtomicU64,
    stale_transitions_total: AtomicU64,
    /// Last published admission word (`generation << 1 | blocked`). Mirrors
    /// [`ADMISSION`] for the installed tracker and stands alone for test
    /// instances, so both are installed by the same monotonic CAS.
    admission: AtomicU64,
    /// Woken whenever the state the deadline depends on changes, so the
    /// monitor task can recompute its exact wakeup instead of polling.
    wakeup: Notify,
    /// Only the installed global publishes to [`ADMISSION`].
    publishes: bool,
}

impl DpConfigFreshness {
    /// Construct a non-publishing tracker with an explicit monotonic base, so
    /// tests can drive the whole state machine from a fixed instant.
    pub fn new_at(epoch: Instant, max_stale: Duration, action: StaleAction) -> Self {
        Self::with_epoch(epoch, max_stale, action, false)
    }

    fn new_publishing(max_stale: Duration, action: StaleAction) -> Self {
        Self::with_epoch(Instant::now(), max_stale, action, true)
    }

    fn with_epoch(
        epoch: Instant,
        max_stale: Duration,
        action: StaleAction,
        publishes: bool,
    ) -> Self {
        Self {
            max_stale,
            action,
            epoch,
            state: AtomicU64::new(0),
            last_applied_ms: AtomicU64::new(0),
            // A DP that has not yet reached a CP is already in an outage that
            // started at the epoch, so startup without any accepted snapshot is
            // bounded by exactly the same rule as a mid-life outage.
            disconnected_since_ms: AtomicU64::new(1),
            authority: AtomicU8::new(CpAuthority::Lost.encode()),
            last_outcome: AtomicU8::new(OUTCOME_NONE),
            applied_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            apply_failed_total: AtomicU64::new(0),
            stale_transitions_total: AtomicU64::new(0),
            admission: AtomicU64::new(0),
            wakeup: Notify::new(),
            publishes,
        }
    }

    /// Configured bound (`Duration::ZERO` = disabled).
    pub fn max_stale(&self) -> Duration {
        self.max_stale
    }

    /// Whether the bound is enforced at all.
    pub fn enabled(&self) -> bool {
        !self.max_stale.is_zero()
    }

    /// Current CP authority state.
    pub fn cp_authority(&self) -> CpAuthority {
        CpAuthority::decode(self.authority.load(Ordering::Relaxed))
    }

    /// Wait for the next state change that could move the staleness deadline.
    ///
    /// `Notify::notified()` stores a permit on `notify_one`, so a change that
    /// lands between two waits is never lost and the monitor never has to poll.
    pub async fn wait_for_change(&self) {
        self.wakeup.notified().await;
    }

    /// A ConfigSync stream to some CP is established. Transport success alone
    /// is **not** freshness: this records authority for the staleness predicate
    /// and never touches the age or clears the sticky stale flag.
    pub fn record_cp_connected(&self) {
        self.record_cp_connected_at(Instant::now());
    }

    /// [`Self::record_cp_connected`] with an explicit instant (tests).
    pub fn record_cp_connected_at(&self, now: Instant) {
        self.disconnected_since_ms.store(0, Ordering::Relaxed);
        self.authority
            .store(CpAuthority::Connected.encode(), Ordering::Relaxed);
        self.wake();
        self.evaluate_at(now);
    }

    /// The stream ended, but not in a way that proves the DP has lost its
    /// authority: an intentional primary-retry or TLS-rotation reconnect, or a
    /// healthy session that had already delivered config. A reconnect attempt
    /// follows immediately, so the bound must not latch during the handoff.
    ///
    /// Only a `Connected` DP can enter this state — an already-`Lost` DP does
    /// not get its boundary postponed by a reclassified stream end.
    pub fn record_cp_reconnecting(&self) {
        self.record_cp_reconnecting_at(Instant::now());
    }

    /// [`Self::record_cp_reconnecting`] with an explicit instant (tests).
    pub fn record_cp_reconnecting_at(&self, now: Instant) {
        let _ = self.authority.compare_exchange(
            CpAuthority::Connected.encode(),
            CpAuthority::Reconnecting.encode(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        self.stamp_outage_start(now);
        self.wake();
        self.evaluate_at(now);
    }

    /// The DP has no authoritative configuration source: a connect/subscribe
    /// attempt failed, or a stream ended without delivering usable config.
    /// Re-evaluates immediately so an outage that starts with an already-old
    /// snapshot degrades without waiting for anything.
    pub fn record_cp_authority_lost(&self) {
        self.record_cp_authority_lost_at(Instant::now());
    }

    /// [`Self::record_cp_authority_lost`] with an explicit instant (tests).
    ///
    /// Idempotent within one outage: the DP calls this once per failed CP
    /// attempt while cycling through `FERRUM_DP_CP_GRPC_URLS`. Because the
    /// predicate is the applied-snapshot age — not an outage duration —
    /// repeated failed cycles cannot postpone the boundary; only the
    /// `cp_disconnected_seconds` diagnostic depends on the first stamp.
    pub fn record_cp_authority_lost_at(&self, now: Instant) {
        self.authority
            .store(CpAuthority::Lost.encode(), Ordering::Relaxed);
        self.stamp_outage_start(now);
        self.wake();
        self.evaluate_at(now);
    }

    fn stamp_outage_start(&self, now: Instant) {
        if self.disconnected_since_ms.load(Ordering::Relaxed) == 0 {
            self.disconnected_since_ms
                .store(self.stamp(now), Ordering::Relaxed);
        }
    }

    fn wake(&self) {
        self.wakeup.notify_one();
    }

    /// Monotonic offset from the epoch, encoded as `offset_ms + 1`.
    fn stamp(&self, now: Instant) -> u64 {
        let offset = now.saturating_duration_since(self.epoch).as_millis();
        // Saturate rather than wrap: a u64 of milliseconds is ~584 million
        // years, so this is unreachable, and clamping keeps the stamp monotonic
        // in the impossible case instead of teleporting it back to the epoch.
        u64::try_from(offset)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// Elapsed time since a stamp of the `offset_ms + 1` encoding.
    fn since_stamp(&self, stamp: u64, now: Instant) -> Duration {
        now.saturating_duration_since(self.epoch)
            .saturating_sub(Duration::from_millis(stamp.saturating_sub(1)))
    }

    /// A snapshot or delta was validated and successfully applied. This is the
    /// only event that resets the age, and the only one that clears the sticky
    /// stale flag — a reconnect on its own must not restore admission.
    pub fn record_snapshot_applied(&self) {
        self.record_snapshot_applied_at(Instant::now());
    }

    /// [`Self::record_snapshot_applied`] with an explicit instant (tests).
    ///
    /// The write order is load-bearing: the new age lands first, then the
    /// generation bump publishes it. Any evaluator that observed the previous
    /// generation now fails its compare-and-swap, so a verdict computed against
    /// the superseded snapshot can never re-block this one.
    pub fn record_snapshot_applied_at(&self, now: Instant) {
        let stamp = self.stamp(now);
        self.last_applied_ms.store(stamp, Ordering::Release);
        self.applied_total.fetch_add(1, Ordering::Relaxed);
        self.last_outcome.store(OUTCOME_APPLIED, Ordering::Relaxed);
        // Bump the generation and clear the sticky stale bit in one step. The
        // word only ever grows, which is what makes the publication CAS below
        // safe against a late evaluator.
        let _ = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(((current >> 1) + 1) << 1)
            });
        self.wake();
        self.evaluate_at(now);
    }

    /// A CP payload was refused before apply (fenced FULL_SNAPSHOT, rejected
    /// delta, pre-snapshot delta, or a snapshot that failed
    /// validation/staging). Age is untouched.
    pub fn record_snapshot_rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
        self.last_outcome.store(OUTCOME_REJECTED, Ordering::Relaxed);
    }

    /// A CP payload passed admission but failed during apply. Age is
    /// untouched: nothing new is serving.
    pub fn record_snapshot_apply_failed(&self) {
        self.apply_failed_total.fetch_add(1, Ordering::Relaxed);
        self.last_outcome
            .store(OUTCOME_APPLY_FAILED, Ordering::Relaxed);
    }

    /// Age of the last applied snapshot, or of the tracker itself when no
    /// snapshot has ever been applied.
    pub fn age_at(&self, now: Instant) -> Duration {
        self.age_from(self.last_applied_ms.load(Ordering::Acquire), now)
    }

    fn age_from(&self, applied_stamp: u64, now: Instant) -> Duration {
        match applied_stamp {
            0 => now.saturating_duration_since(self.epoch),
            stamp => self.since_stamp(stamp, now),
        }
    }

    /// How long every CP has been unreachable. `Duration::ZERO` while a CP
    /// stream is established.
    pub fn cp_outage_at(&self, now: Instant) -> Duration {
        match self.disconnected_since_ms.load(Ordering::Relaxed) {
            0 => Duration::ZERO,
            stamp => self.since_stamp(stamp, now),
        }
    }

    /// Whether any snapshot has ever been validated and applied.
    pub fn has_applied_snapshot(&self) -> bool {
        self.last_applied_ms.load(Ordering::Acquire) != 0
    }

    /// The exact instant at which the current applied snapshot crosses the
    /// bound, or `None` when nothing is pending.
    ///
    /// `None` means "there is no deadline to schedule": the bound is disabled,
    /// the DP already latched stale, the DP still has (or may still have) an
    /// authoritative source, or the computed deadline is not representable as an
    /// [`Instant`] because an astronomical configured bound overflows the
    /// platform monotonic clock range. An unrepresentable deadline cannot occur
    /// within that range, so returning `None` is correct rather than panicking
    /// on unchecked `Instant + Duration` or arming a shorter substitute timer.
    /// The monitor then waits on [`Self::wait_for_change`] alone until a CP
    /// event or `/health` evaluation moves state; it never busy-polls.
    pub fn next_stale_deadline_at(&self, now: Instant) -> Option<Instant> {
        if !self.enabled() {
            return None;
        }
        if self.state.load(Ordering::Acquire) & STALE_BIT != 0 {
            return None;
        }
        if self.cp_authority() != CpAuthority::Lost {
            return None;
        }
        let applied = self.last_applied_ms.load(Ordering::Acquire);
        let base = match applied {
            0 => self.epoch,
            stamp => self
                .epoch
                .checked_add(Duration::from_millis(stamp.saturating_sub(1)))?,
        };
        let deadline = base.checked_add(self.max_stale)?;
        Some(deadline.max(now))
    }

    /// The current state word (`generation << 1 | stale`).
    pub fn state_word(&self) -> u64 {
        self.state.load(Ordering::Acquire)
    }

    /// The last published admission word (`generation << 1 | blocked`).
    pub fn published_admission_word(&self) -> u64 {
        self.admission.load(Ordering::Acquire)
    }

    /// Attempt to latch the sticky stale bit for the generation carried by
    /// `observed_state`.
    ///
    /// Returns `true` only when this call installed the bit. It returns `false`
    /// when the bit was already set and — the point of the whole signature —
    /// when the generation moved: a valid snapshot applied while the caller was
    /// computing, so a verdict about the superseded generation must be
    /// discarded instead of committed on top of the recovery.
    pub fn try_latch_stale(&self, observed_state: u64) -> bool {
        if observed_state & STALE_BIT != 0 {
            return false;
        }
        match self.state.compare_exchange(
            observed_state,
            observed_state | STALE_BIT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.stale_transitions_total.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    /// Re-evaluate the bound and publish the admission gate. Pure atomics — no
    /// locks, no allocation — so `/health`, the deadline monitor, and the CP
    /// event paths can all call it freely.
    pub fn evaluate(&self) -> DpConfigFreshnessSnapshot {
        self.evaluate_at(Instant::now())
    }

    /// [`Self::evaluate`] with an explicit instant (tests).
    pub fn evaluate_at(&self, now: Instant) -> DpConfigFreshnessSnapshot {
        // Latch loop. Read the state word FIRST, then everything the verdict
        // depends on: a concurrent apply bumps the word, so the compare-exchange
        // rejects a verdict computed from a mixture of generations instead of
        // silently committing it.
        let mut state = loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & STALE_BIT != 0 {
                break observed;
            }
            let applied = self.last_applied_ms.load(Ordering::Acquire);
            let should_latch = self.enabled()
                && self.cp_authority() == CpAuthority::Lost
                && self.age_from(applied, now) >= self.max_stale;
            if !should_latch {
                break observed;
            }
            if self.try_latch_stale(observed) {
                break observed | STALE_BIT;
            }
            // Either another evaluator latched the same generation or the
            // generation moved because a snapshot applied. Recompute from
            // scratch rather than committing a mixed-generation verdict.
        };
        // Re-read once: a snapshot may have applied after the loop settled, in
        // which case the newer word is the one to publish.
        let latest = self.state.load(Ordering::Acquire);
        if latest > state {
            state = latest;
        }
        let stale = state & STALE_BIT != 0;
        let blocked = stale && self.action == StaleAction::FailClosed;
        let word = (state & !STALE_BIT) | u64::from(blocked);
        publish_monotonic(&self.admission, word);
        if self.publishes {
            publish_monotonic(&ADMISSION, word);
        }

        let authority = self.cp_authority();
        let age = self.age_at(now);
        DpConfigFreshnessSnapshot {
            stale,
            reason: self.reason(stale, authority).as_str(),
            stale_action: self.action.as_str(),
            new_traffic_blocked: self.admission.load(Ordering::Acquire) & STALE_BIT != 0,
            cp_connected: authority == CpAuthority::Connected,
            cp_authority: authority.as_str(),
            cp_disconnected_seconds: self.cp_outage_at(now).as_secs(),
            max_stale_seconds: self.max_stale.as_secs(),
            applied_snapshot: self.has_applied_snapshot(),
            snapshot_age_seconds: age.as_secs(),
            applied_total: self.applied_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            apply_failed_total: self.apply_failed_total.load(Ordering::Relaxed),
            stale_transitions_total: self.stale_transitions_total.load(Ordering::Relaxed),
        }
    }

    /// Reason precedence: the strongest currently-true condition wins, so the
    /// four operator-distinguishable states (`cp_disconnected`,
    /// `snapshot_stale`, `snapshot_rejected`, `snapshot_apply_failed`) never
    /// mask a more severe one.
    fn reason(&self, stale: bool, authority: CpAuthority) -> FreshnessReason {
        if stale {
            return FreshnessReason::SnapshotStale;
        }
        if !self.has_applied_snapshot() {
            return FreshnessReason::AwaitingFirstSnapshot;
        }
        if authority != CpAuthority::Connected {
            return FreshnessReason::CpDisconnected;
        }
        match self.last_outcome.load(Ordering::Relaxed) {
            OUTCOME_REJECTED => FreshnessReason::SnapshotRejected,
            OUTCOME_APPLY_FAILED => FreshnessReason::SnapshotApplyFailed,
            _ => FreshnessReason::Ok,
        }
    }
}

/// Low bit of a state/admission word, exposed so callers and tests can read a
/// word without re-deriving the layout.
pub const ADMISSION_STALE_BIT: u64 = STALE_BIT;

/// Install `word` only if it is newer than what is already published.
///
/// Words are `generation << 1 | bit` and the bit is sticky within a generation,
/// so "newer" is plain numeric greater-than. This is the whole race fix: a
/// verdict computed against generation *g* can never overwrite a value already
/// published for generation *g+1*, no matter how long the evaluator was
/// descheduled for.
pub fn publish_monotonic(slot: &AtomicU64, word: u64) {
    let mut current = slot.load(Ordering::Acquire);
    while word > current {
        match slot.compare_exchange_weak(current, word, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Record an applied snapshot on the installed tracker, if any.
pub fn record_snapshot_applied() {
    if let Some(freshness) = global() {
        freshness.record_snapshot_applied();
    }
}

/// Record a refused-before-apply CP payload on the installed tracker, if any.
pub fn record_snapshot_rejected() {
    if let Some(freshness) = global() {
        freshness.record_snapshot_rejected();
    }
}

/// Record an apply failure on the installed tracker, if any.
pub fn record_snapshot_apply_failed() {
    if let Some(freshness) = global() {
        freshness.record_snapshot_apply_failed();
    }
}

/// Record CP connectivity on the installed tracker, if any.
pub fn record_cp_connected() {
    if let Some(freshness) = global() {
        freshness.record_cp_connected();
    }
}

/// Record an intentional/handoff reconnect on the installed tracker, if any.
pub fn record_cp_reconnecting() {
    if let Some(freshness) = global() {
        freshness.record_cp_reconnecting();
    }
}

/// Record loss of every authoritative CP on the installed tracker, if any.
pub fn record_cp_authority_lost() {
    if let Some(freshness) = global() {
        freshness.record_cp_authority_lost();
    }
}

/// Fixed-cardinality projection of the installed tracker for `/health` and
/// `/metrics` (`None` outside DP mode).
pub fn snapshot() -> Option<DpConfigFreshnessSnapshot> {
    global().map(|freshness| freshness.evaluate())
}
