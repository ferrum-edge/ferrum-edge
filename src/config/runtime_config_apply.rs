//! In-process read-your-write apply for database-mode admin mutations (issue #3926).
//!
//! Successful config-database writes must not return 2xx until the same
//! authoritative poll-loop reload that periodic ticks use has accepted a
//! generation covering the captured `config_changes` watermark — or until a
//! truthful failure is known (validation rejection / timeout / sequence
//! unavailable).
//!
//! This type is a coordinator, not a second apply path:
//! - It never builds a partial snapshot, never holds a DB transaction, and
//!   never rebuilds caches itself.
//! - Admin writers capture a covering watermark from the pinned write
//!   topology after persist, release that pin, then wait on the durable
//!   topology-bound cursor the poll loop publishes after `apply_incremental` /
//!   `update_config`.
//! - Concurrent writers coalesce onto one reload: each waits for the covering
//!   watermark captured under its pin (see [`PreparedLiveApply`]), and a
//!   single poll that advances past both watermarks unblocks both waiters.
//! - External writers keep using the periodic / change-stream backstop; they
//!   are not delayed by this wait, and an in-flight admin-triggered poll still
//!   applies any rows they committed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{Instant, timeout};

use crate::config::config_change_watch::ConfigChangeWakeSignal;

/// Bound on how long a database-mode admin mutation waits for the poll loop
/// to publish the committed generation. Cache rebuilds share this budget.
pub const ADMIN_WRITE_LIVE_APPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// How a database-mode admin mutation completes relative to the poll-loop
/// apply (issue #4139).
///
/// `Sync` is the default read-your-write contract from issue #3926: 2xx only
/// after the poll loop publishes a covering generation. `Deferred` is the
/// explicit bulk-provisioning opt-in (`?apply=async`): the mutation commits
/// durably, the covering cursor is still captured fail-closed under the write
/// pins, but the handler answers `202 Accepted` with the cursor instead of
/// waiting. The client proves convergence later through
/// `GET /config/apply-status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiveApplyMode {
    #[default]
    Sync,
    Deferred,
}

/// Classification of a captured cursor against the coordinator's published
/// snapshot (issue #4139). Closed static labels for the
/// `GET /config/apply-status` JSON `state` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveApplyCursorState {
    /// The poll loop accepted a generation covering the cursor.
    Applied,
    /// No covering generation has been accepted or rejected yet.
    Pending,
    /// A completed poll attempted a sequence covering the cursor and rejected
    /// the candidate. Fail-closed: the write range is not live.
    Rejected,
    /// The cursor's topology was replaced (failover/reconnect/restart), so
    /// liveness can no longer be proven from this process. Observe config
    /// directly instead.
    Unverifiable,
}

impl LiveApplyCursorState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Unverifiable => "unverifiable",
        }
    }
}

/// Why a committed mutation is not live. Closed static labels for OpenAPI /
/// JSON `reason` — never a resource id, namespace, or driver error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveApplyFailure {
    /// The poll loop loaded a covering sequence and rejected the candidate.
    ConfigRejected,
    /// The wait budget elapsed before an accepted generation covered the write.
    Timeout,
    /// The covering sequence could not be read from the pinned topology after persist.
    SequenceUnavailable,
}

/// Covering `config_changes` watermark captured under a write-topology pin
/// after a durable mutation (issue #3926).
///
/// Persistence APIs do not cheaply return the mutation's exact assigned
/// sequence from the existing admission transaction, so handlers read
/// `latest_change_sequence` while the pin (and a still-held namespace
/// admission guard, when available) is live. That value is `MAX(sequence)`
/// on the pinned topology and may include a later concurrent same-namespace
/// writer. Waiting for it is conservative: `accepted >= covering` still
/// implies this mutation is live. It is not this waiter's exact committed
/// row unless no concurrent writer committed in between.
///
/// Capture this **before** releasing topology / namespace pins. Await it
/// **after** those pins drop so a poll or reconnect needed to make progress
/// is not blocked. Never re-query `latest_change_sequence` after release:
/// a failover can publish a different pool whose watermark is `<= accepted`
/// and would yield a false 2xx.
#[derive(Debug, Clone)]
#[must_use = "captured covering cursor must be awaited after releasing topology pins"]
pub struct PreparedLiveApply {
    covering: PreparedLiveApplyCovering,
}

/// Process-local database topology plus its durable change-log watermark.
///
/// A sequence has meaning only inside the database/pool generation that
/// produced it. Keeping the pair as one value prevents a stale high watermark
/// from one topology from covering a lower watermark after failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveApplyCursor {
    pub topology_epoch: u64,
    pub sequence: u64,
}

impl LiveApplyCursor {
    pub const fn new(topology_epoch: u64, sequence: u64) -> Self {
        Self {
            topology_epoch,
            sequence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedLiveApplyCovering {
    /// No poll-loop coordinator, or the write targeted a namespace this process
    /// does not serve.
    Noop,
    Cursor(LiveApplyCursor),
}

impl PreparedLiveApply {
    pub fn noop() -> Self {
        Self {
            covering: PreparedLiveApplyCovering::Noop,
        }
    }

    pub fn from_covering_sequence(sequence: u64) -> Self {
        Self::from_covering_cursor(LiveApplyCursor::new(0, sequence))
    }

    pub fn from_covering_cursor(cursor: LiveApplyCursor) -> Self {
        Self {
            covering: PreparedLiveApplyCovering::Cursor(cursor),
        }
    }

    pub fn is_noop(&self) -> bool {
        matches!(self.covering, PreparedLiveApplyCovering::Noop)
    }

    /// Covering watermark to wait for, if this process serves the write.
    pub fn covering_sequence(&self) -> Option<u64> {
        match self.covering {
            PreparedLiveApplyCovering::Noop => None,
            PreparedLiveApplyCovering::Cursor(cursor) => Some(cursor.sequence),
        }
    }

    /// Topology-bound covering watermark to wait for.
    pub fn covering_cursor(&self) -> Option<LiveApplyCursor> {
        match self.covering {
            PreparedLiveApplyCovering::Noop => None,
            PreparedLiveApplyCovering::Cursor(cursor) => Some(cursor),
        }
    }
}

impl LiveApplyFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigRejected => "config_rejected",
            Self::Timeout => "reload_timeout",
            Self::SequenceUnavailable => "sequence_unavailable",
        }
    }

    pub fn error_message(self) -> &'static str {
        match self {
            Self::ConfigRejected => {
                "Configuration was committed but is not live: runtime reload rejected the candidate"
            }
            Self::Timeout => {
                "Configuration was committed but is not live: runtime reload did not apply in time"
            }
            Self::SequenceUnavailable => {
                "Configuration was committed but live-apply status could not be determined"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ApplySnapshot {
    topology_epoch: u64,
    accepted: u64,
    rejected_through: u64,
    issued_through: Option<u64>,
}

/// Process-local coordinator shared by the database-mode poll loop and admin
/// write handlers.
pub struct RuntimeConfigApply {
    namespace: String,
    timeout: Duration,
    wake: Arc<ConfigChangeWakeSignal>,
    snapshot: watch::Sender<ApplySnapshot>,
    waiter_count: AtomicUsize,
    max_waiting_epoch: AtomicU64,
    max_waiting: AtomicU64,
}

impl RuntimeConfigApply {
    pub fn new(namespace: impl Into<String>, accepted_sequence: u64) -> Self {
        Self::with_timeout_at_epoch(
            namespace,
            0,
            accepted_sequence,
            ADMIN_WRITE_LIVE_APPLY_TIMEOUT,
        )
    }

    pub fn at_epoch(
        namespace: impl Into<String>,
        topology_epoch: u64,
        accepted_sequence: u64,
    ) -> Self {
        Self::with_timeout_at_epoch(
            namespace,
            topology_epoch,
            accepted_sequence,
            ADMIN_WRITE_LIVE_APPLY_TIMEOUT,
        )
    }

    pub fn with_timeout(
        namespace: impl Into<String>,
        accepted_sequence: u64,
        timeout: Duration,
    ) -> Self {
        Self::with_timeout_at_epoch(namespace, 0, accepted_sequence, timeout)
    }

    pub fn with_timeout_at_epoch(
        namespace: impl Into<String>,
        topology_epoch: u64,
        accepted_sequence: u64,
        timeout: Duration,
    ) -> Self {
        let (snapshot, _) = watch::channel(ApplySnapshot {
            topology_epoch,
            accepted: accepted_sequence,
            rejected_through: 0,
            issued_through: None,
        });
        Self {
            namespace: namespace.into(),
            timeout,
            wake: Arc::new(ConfigChangeWakeSignal::new()),
            snapshot,
            waiter_count: AtomicUsize::new(0),
            max_waiting_epoch: AtomicU64::new(topology_epoch),
            max_waiting: AtomicU64::new(0),
        }
    }

    pub fn serves_namespace(&self, namespace: &str) -> bool {
        self.namespace == namespace
    }

    pub fn wake_signal(&self) -> Arc<ConfigChangeWakeSignal> {
        Arc::clone(&self.wake)
    }

    pub fn accepted_sequence(&self) -> u64 {
        self.snapshot.borrow().accepted
    }

    pub fn accepted_cursor(&self) -> LiveApplyCursor {
        let snapshot = *self.snapshot.borrow();
        LiveApplyCursor::new(snapshot.topology_epoch, snapshot.accepted)
    }

    pub fn waiter_count(&self) -> usize {
        self.waiter_count.load(Ordering::Acquire)
    }

    /// Record a cursor returned by an admin mutation in this process.
    ///
    /// The status endpoint only permits blocking waits at or below this
    /// topology-local high-water mark. This prevents client-chosen future
    /// sequences from continuously re-arming the database poll loop while
    /// preserving the covering-cursor semantics for concurrent mutations.
    pub fn record_issued_cursor(&self, cursor: LiveApplyCursor) {
        self.snapshot.send_modify(|snap| {
            if cursor.topology_epoch == snap.topology_epoch {
                snap.issued_through = Some(
                    snap.issued_through
                        .map_or(cursor.sequence, |issued| issued.max(cursor.sequence)),
                );
            }
        });
    }

    /// Whether `cursor` is covered by a cursor minted by this process in the
    /// currently observed topology.
    pub fn cursor_was_issued(&self, cursor: LiveApplyCursor) -> bool {
        let snapshot = *self.snapshot.borrow();
        snapshot.topology_epoch == cursor.topology_epoch
            && snapshot
                .issued_through
                .is_some_and(|issued| cursor.sequence <= issued)
    }

    /// Publish that the poll loop accepted a generation covering `sequence`.
    pub fn record_accepted(&self, sequence: u64) {
        let topology_epoch = self.snapshot.borrow().topology_epoch;
        self.record_accepted_cursor(LiveApplyCursor::new(topology_epoch, sequence));
    }

    /// Publish an accepted cursor without ever comparing it to a different
    /// topology's sequence. Older in-flight poll results are ignored.
    pub fn record_accepted_cursor(&self, cursor: LiveApplyCursor) {
        self.snapshot.send_modify(|snap| {
            if cursor.topology_epoch > snap.topology_epoch {
                snap.topology_epoch = cursor.topology_epoch;
                snap.accepted = cursor.sequence;
                snap.rejected_through = 0;
                snap.issued_through = None;
            } else if cursor.topology_epoch == snap.topology_epoch
                && cursor.sequence > snap.accepted
            {
                snap.accepted = cursor.sequence;
            }
        });
    }

    /// Publish that a completed poll attempted `sequence` and rejected it.
    /// Waiters whose covering sequence is `<= sequence` fail closed.
    pub fn record_rejected(&self, sequence: u64) {
        let topology_epoch = self.snapshot.borrow().topology_epoch;
        self.record_rejected_cursor(LiveApplyCursor::new(topology_epoch, sequence));
    }

    pub fn record_rejected_cursor(&self, cursor: LiveApplyCursor) {
        self.snapshot.send_modify(|snap| {
            if cursor.topology_epoch > snap.topology_epoch {
                snap.topology_epoch = cursor.topology_epoch;
                snap.accepted = 0;
                snap.rejected_through = cursor.sequence;
                snap.issued_through = None;
            } else if cursor.topology_epoch == snap.topology_epoch
                && cursor.sequence > snap.rejected_through
            {
                snap.rejected_through = cursor.sequence;
            }
        });
    }

    /// Observe a successfully published database topology before it has an
    /// accepted config cursor. This immediately makes older waiters fail
    /// `sequence_unavailable` and makes lower sequences in the new topology
    /// wait instead of short-circuiting on the old accepted high-water mark.
    pub fn observe_topology(&self, topology_epoch: u64) {
        self.snapshot.send_modify(|snap| {
            if topology_epoch > snap.topology_epoch {
                snap.topology_epoch = topology_epoch;
                snap.accepted = 0;
                snap.rejected_through = 0;
                snap.issued_through = None;
            }
        });
    }

    /// Re-arm an immediate poll when admin waiters are still blocked on a
    /// sequence this tick did not accept. Consumed permits must not leave
    /// waiters parked on the periodic interval.
    pub fn nudge_if_waiters_pending(&self) {
        if self.waiter_count.load(Ordering::Acquire) == 0 {
            return;
        }
        let waiting_epoch = self.max_waiting_epoch.load(Ordering::Acquire);
        let waiting = self.max_waiting.load(Ordering::Acquire);
        let snapshot = *self.snapshot.borrow();
        if snapshot.topology_epoch < waiting_epoch
            || (snapshot.topology_epoch == waiting_epoch && snapshot.accepted < waiting)
        {
            self.wake.signal_immediate();
        }
    }

    /// Classify `cursor` against the published snapshot without waiting and
    /// without registering a waiter (issue #4139). Never reads the database;
    /// pair it with a process-topology check when the caller must distinguish
    /// a genuinely pending cursor from one minted by a different process.
    pub fn cursor_state(&self, cursor: LiveApplyCursor) -> LiveApplyCursorState {
        match classify_snapshot(*self.snapshot.borrow(), cursor) {
            Some(Ok(())) => LiveApplyCursorState::Applied,
            Some(Err(LiveApplyFailure::ConfigRejected)) => LiveApplyCursorState::Rejected,
            Some(Err(_)) => LiveApplyCursorState::Unverifiable,
            None => LiveApplyCursorState::Pending,
        }
    }

    /// Wait until the poll loop has accepted a generation covering `sequence`
    /// or a truthful failure is known. `sequence` must already have been
    /// captured under the write-topology pin; this method never reads the
    /// database. Signals an immediate coalesced wake so the wait does not sit
    /// on `FERRUM_DB_POLL_INTERVAL`.
    pub async fn await_committed(&self, sequence: u64) -> Result<(), LiveApplyFailure> {
        let topology_epoch = self.snapshot.borrow().topology_epoch;
        self.await_committed_cursor(LiveApplyCursor::new(topology_epoch, sequence))
            .await
    }

    pub async fn await_committed_cursor(
        &self,
        cursor: LiveApplyCursor,
    ) -> Result<(), LiveApplyFailure> {
        self.await_committed_cursor_with_timeout(cursor, self.timeout)
            .await
    }

    /// [`Self::await_committed_cursor`] with an explicit wait budget, for
    /// `GET /config/apply-status?wait_ms=` (issue #4139). Callers must clamp
    /// `wait` to at most [`ADMIN_WRITE_LIVE_APPLY_TIMEOUT`]-scale budgets; the
    /// coordinator does not re-clamp so tests can exercise short waits.
    pub async fn await_committed_cursor_with_timeout(
        &self,
        cursor: LiveApplyCursor,
        wait: Duration,
    ) -> Result<(), LiveApplyFailure> {
        if let Some(result) = classify_snapshot(*self.snapshot.borrow(), cursor) {
            return result;
        }

        self.max_waiting_epoch
            .fetch_max(cursor.topology_epoch, Ordering::AcqRel);
        self.max_waiting
            .fetch_max(cursor.sequence, Ordering::AcqRel);
        self.waiter_count.fetch_add(1, Ordering::AcqRel);
        struct WaiterGuard<'a>(&'a RuntimeConfigApply);
        impl Drop for WaiterGuard<'_> {
            fn drop(&mut self) {
                self.0.waiter_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _guard = WaiterGuard(self);

        self.wake.signal_immediate();

        let mut rx = self.snapshot.subscribe();
        let deadline = Instant::now() + wait;
        loop {
            {
                let snap = *rx.borrow();
                if let Some(result) = classify_snapshot(snap, cursor) {
                    return result;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(LiveApplyFailure::Timeout);
            }
            match timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(LiveApplyFailure::Timeout),
                Err(_) => return Err(LiveApplyFailure::Timeout),
            }
        }
    }
}

fn classify_snapshot(
    snapshot: ApplySnapshot,
    cursor: LiveApplyCursor,
) -> Option<Result<(), LiveApplyFailure>> {
    if snapshot.topology_epoch > cursor.topology_epoch {
        return Some(Err(LiveApplyFailure::SequenceUnavailable));
    }
    if snapshot.topology_epoch < cursor.topology_epoch {
        return None;
    }
    if snapshot.accepted >= cursor.sequence {
        return Some(Ok(()));
    }
    if snapshot.rejected_through >= cursor.sequence {
        return Some(Err(LiveApplyFailure::ConfigRejected));
    }
    None
}
