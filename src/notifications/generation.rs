//! Per-plugin-generation tracking for notification dispatch tasks.
//!
//! Each producer (today: `proxy_alerts`) owns one [`DispatchGeneration`]. While
//! the generation is admitting, new work may be spawned through the process
//! observability delivery registry. On reload/`Drop` the generation stops
//! admitting and cooperatively cancels in-flight work; tasks that observe the
//! cancel flag settle as `Abandoned(GenerationRetired)`. In-flight transport
//! attempts race [`DispatchGeneration::cancelled`] and are dropped on
//! retirement rather than held until the transport timeout. Process shutdown
//! drains the same tasks under the global observability budget and aborts
//! whatever remains when the deadline expires — those aborts settle as
//! `Abandoned(ShutdownDeadline)` via [`DeliveryTaskGuard`].
//!
//! # Abandonment is not one thing
//!
//! Every non-outcome exit carries a precise, compiled-in
//! [`AbandonReason`], and the metrics layer keeps two disjoint families:
//!
//! - **Pre-body rejections** (`GenerationClosed`, `RegistryRejected`) —
//!   counted in `rejected_total{reason}`. No `attempted`, no `in_flight`.
//! - **Post-body abandonment** (`GenerationRetired`, `ShutdownDeadline`,
//!   `TaskDropped`) — counted in `abandoned_total{reason}`, releasing the
//!   `in_flight` reservation the body start took.
//!
//! `attempted` / `in_flight` advance when the registry-owned delivery **body
//! starts** (first statement of the task future), not when the first channel
//! transport call is polled. That boundary is load-bearing for hard-deadline
//! drop classification: a task the registry never ran must stay a rejection,
//! while a body that started and is later hard-aborted must land on
//! `ShutdownDeadline`. An admit-then-cancel race can therefore increment
//! `attempted` with no channel call; that is the documented contract.
//!
//! Only `ShutdownDeadline` advances `abandoned_at_deadline_total`, so that
//! metric is a true hard-deadline signal rather than a catch-all.
//!
//! In every case — including the paths that record no attempt — the producer
//! callback runs exactly once, so reserved cooldown / pending incident state is
//! always rolled back.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::Notify;

use super::metrics::{DeliveryMetrics, global as global_metrics};
use super::outcome::AbandonReason;

/// Optional completion callback invoked exactly once after a delivery settles.
///
/// The generation owns this callback, rather than the user future, so a task
/// rejected during admission or hard-aborted before its first poll still rolls
/// back producer state.
pub type DeliveryCallback = Arc<dyn Fn(DispatchSettle) + Send + Sync>;

/// Tracks in-flight dispatch tasks for one plugin-instance generation.
#[derive(Debug)]
pub struct DispatchGeneration {
    id: u64,
    admitting: AtomicBool,
    /// Cooperative cancel: set on retire/Drop so retry loops stop.
    cancelled: AtomicBool,
    /// Spawn calls between method entry and completed registry handoff/reject.
    /// Drain waits for these registrations so closing admission cannot race a
    /// caller that observed the old `admitting=true` value but has not yet
    /// incremented `in_flight`.
    active_spawns: AtomicUsize,
    in_flight: AtomicUsize,
    drained: Notify,
    /// Woken once when `cancelled` flips, so in-flight attempts observe
    /// retirement immediately instead of on a polling cadence.
    cancel_signal: Notify,
    metrics: Arc<DeliveryMetrics>,
    next_task_id: AtomicU64,
}

impl DispatchGeneration {
    pub fn new(id: u64) -> Arc<Self> {
        Self::with_metrics(id, Arc::clone(global_metrics()))
    }

    pub fn with_metrics(id: u64, metrics: Arc<DeliveryMetrics>) -> Arc<Self> {
        Arc::new(Self {
            id,
            admitting: AtomicBool::new(true),
            cancelled: AtomicBool::new(false),
            active_spawns: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            drained: Notify::new(),
            cancel_signal: Notify::new(),
            metrics,
            next_task_id: AtomicU64::new(1),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_admitting(&self) -> bool {
        self.admitting.load(Ordering::Acquire)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn metrics(&self) -> &Arc<DeliveryMetrics> {
        &self.metrics
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Stop admitting new work without cancelling in-flight tasks.
    pub fn close_admission(&self) {
        self.admitting.store(false, Ordering::Release);
    }

    /// Stop admitting and signal cooperative cancel to every in-flight task.
    ///
    /// The flag is published before the wakeup so a waiter that registered but
    /// has not re-read the flag still observes `cancelled == true` when it runs.
    pub fn cancel(&self) {
        self.admitting.store(false, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
        self.cancel_signal.notify_waiters();
    }

    /// Resolve as soon as this generation is cancelled.
    ///
    /// Cancellation is one-way, so this never completes for a live generation.
    /// The waiter is registered (via `Notified::enable`) *before* the flag is
    /// re-read, so a [`Self::cancel`] landing in that window cannot be missed —
    /// `notify_waiters` retains no permit for a not-yet-registered waiter.
    ///
    /// This future holds no lock and allocates nothing on the steady-state
    /// path; it is safe to re-create it on every retry iteration.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.cancel_signal.notified();
            tokio::pin!(notified);
            let _ = notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.as_mut().await;
        }
    }

    fn begin_task(&self) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
    }

    fn end_task(&self) {
        let prev = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            self.drained.notify_waiters();
        }
    }

    fn end_spawn(&self) {
        let prev = self.active_spawns.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            self.drained.notify_waiters();
        }
    }

    fn is_drained(&self) -> bool {
        self.active_spawns.load(Ordering::Acquire) == 0
            && self.in_flight.load(Ordering::Acquire) == 0
    }

    /// Wait until spawn handoffs and in-flight tasks reach zero or `timeout`
    /// elapses.
    pub async fn wait_drain(&self, timeout: std::time::Duration) -> bool {
        if self.is_drained() {
            return true;
        }
        let wait = async {
            loop {
                // Register the waiter (via `Notified::enable`) *before*
                // re-reading drain state so a zero transition cannot be lost —
                // `notify_waiters` retains no permit for a future that has only
                // been constructed but not yet registered.
                let notified = self.drained.notified();
                tokio::pin!(notified);
                let _ = notified.as_mut().enable();
                if self.is_drained() {
                    return true;
                }
                notified.as_mut().await;
            }
        };
        matches!(tokio::time::timeout(timeout, wait).await, Ok(true))
    }

    /// Spawn a dispatch future into the global observability delivery registry.
    ///
    /// Returns `false` when this generation is closed or the global registry
    /// rejects admission (shutdown / capacity). Rejection is a visible drop —
    /// never queued.
    ///
    /// Every rejection path settles exactly once with a precise, compiled-in
    /// [`AbandonReason`], so the producer callback always runs and the
    /// operator can tell a pre-body admission rejection apart from a
    /// genuine hard abort at the shutdown deadline. A path that never started
    /// the delivery body records a `rejected_total{reason}` increment and does
    /// **not** inflate `attempted`.
    pub fn spawn<F>(
        self: &Arc<Self>,
        channel_type: &'static str,
        on_settle: Option<DeliveryCallback>,
        future: F,
    ) -> bool
    where
        F: Future<Output = DispatchSettle> + Send + 'static,
    {
        self.spawn_impl(channel_type, on_settle, future, None)
    }

    /// Spawn through an owned [`crate::observability_delivery::DeliverySlot`]
    /// instead of the process-global registry.
    ///
    /// Crate-private seam for internal owned-slot dispatch. Production callers
    /// use [`Self::spawn`].
    pub(crate) fn spawn_with_delivery_slot<F>(
        self: &Arc<Self>,
        channel_type: &'static str,
        on_settle: Option<DeliveryCallback>,
        slot: &crate::observability_delivery::DeliverySlot,
        future: F,
    ) -> bool
    where
        F: Future<Output = DispatchSettle> + Send + 'static,
    {
        self.spawn_impl(channel_type, on_settle, future, Some(slot))
    }

    /// Spawn a never-completing delivery body through an owned
    /// [`crate::observability_delivery::DeliverySlot`].
    ///
    /// Hidden test seam only: external shutdown-deadline regressions must drive
    /// a hard abort on an owned slot without closing process-global admission.
    /// The pending body is constructed internally — callers cannot inject an
    /// arbitrary future. External regressions live under `tests/`; production
    /// callers use [`Self::spawn`].
    #[doc(hidden)]
    pub fn spawn_pending_with_delivery_slot_for_test(
        self: &Arc<Self>,
        channel_type: &'static str,
        on_settle: Option<DeliveryCallback>,
        slot: &crate::observability_delivery::DeliverySlot,
        body_entered_tx: tokio::sync::oneshot::Sender<()>,
        pending_body_dropped_tx: tokio::sync::oneshot::Sender<()>,
    ) -> bool {
        self.spawn_with_delivery_slot(channel_type, on_settle, slot, async move {
            let _drop_witness = PendingDeliveryBodyDropWitness {
                tx: Some(pending_body_dropped_tx),
            };
            let _ = body_entered_tx.send(());
            std::future::pending::<DispatchSettle>().await
        })
    }

    fn spawn_impl<F>(
        self: &Arc<Self>,
        channel_type: &'static str,
        on_settle: Option<DeliveryCallback>,
        future: F,
        slot: Option<&crate::observability_delivery::DeliverySlot>,
    ) -> bool
    where
        F: Future<Output = DispatchSettle> + Send + 'static,
    {
        self.active_spawns.fetch_add(1, Ordering::AcqRel);
        let _spawn_registration = SpawnRegistration {
            generation: self.as_ref(),
        };
        if !self.is_admitting() || self.is_cancelled() {
            // Pre-`begin_task` admission rejection. Historically this path
            // invoked the producer callback and incremented nothing at all,
            // leaving reload-time rejections completely invisible. It is now
            // counted under its own bounded reason without pretending the
            // delivery body started.
            self.metrics
                .record_rejected(channel_type, AbandonReason::GenerationClosed);
            if let Some(callback) = on_settle {
                invoke_delivery_callback(
                    &callback,
                    DispatchSettle::Abandoned(AbandonReason::GenerationClosed),
                    channel_type,
                );
            }
            return false;
        }
        let generation = Arc::clone(self);
        let _task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);

        // Reserve local drain accounting before asking the delivery registry so
        // a successful handoff cannot race a zero in-flight read on Drop. The
        // `attempted` metric is deliberately NOT reserved here: it is recorded
        // by the task body, so a task the registry never runs stays a
        // rejection rather than a phantom attempt.
        generation.begin_task();

        // Construct the settlement guard before handing the future to the
        // process registry. If admission rejects, shutdown aborts the task
        // before its first poll, or the task panics, dropping the captured guard
        // still records abandonment and invokes the producer callback.
        let settlement = Arc::new(DeliveryTaskSettlement {
            generation: Arc::clone(&generation),
            channel_type,
            on_settle,
            settled: AtomicBool::new(false),
            attempt_started: AtomicBool::new(false),
            delivery_context: OnceLock::new(),
        });
        let guard = DeliveryTaskGuard {
            settlement: Arc::clone(&settlement),
        };
        let factory = {
            let generation = Arc::clone(&generation);
            let settlement = Arc::clone(&settlement);
            move |ctx: crate::observability_delivery::DeliveryTaskContext| {
                // Bind classification to the exact lifecycle this spawn admits
                // against. A later slot replacement must not reclassify A's
                // hard abort using B's non-cancelling current generation.
                let _ = settlement.delivery_context.set(ctx);
                async move {
                    // First statement of the task body: the registry actually ran
                    // us. This is the attempt-accounting boundary — body start,
                    // not the first channel transport poll. Keeping the marker
                    // here (before any `.await`) preserves hard-deadline drop
                    // classification: a task the registry rejected can never
                    // reach this line, so an unsettled drop before it is
                    // unambiguously a registry rejection, while a body that
                    // started and is later hard-aborted lands on
                    // `ShutdownDeadline`. Admit-then-cancel may therefore
                    // advance `attempted` with no channel call; that is the
                    // documented contract.
                    settlement.mark_attempt_started();
                    let settle = if generation.is_cancelled() {
                        DispatchSettle::Abandoned(AbandonReason::GenerationRetired)
                    } else {
                        future.await
                    };
                    guard.settle(settle);
                }
            }
        };
        let admitted = match slot {
            Some(slot) => slot.spawn_terminal_with_context(factory),
            None => crate::observability_delivery::spawn_terminal_with_context(factory),
        };

        if !admitted {
            // The registry may drop/abort its future asynchronously. Settle
            // synchronously here; the captured guard is protected by the same
            // atomic exactly-once edge and becomes a no-op when it is dropped.
            settlement.settle(DispatchSettle::Abandoned(AbandonReason::RegistryRejected));
            return false;
        }
        true
    }
}

/// Drop witness for a delivery body that must stay pending until hard-aborted.
struct PendingDeliveryBodyDropWitness {
    tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for PendingDeliveryBodyDropWitness {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

struct SpawnRegistration<'a> {
    generation: &'a DispatchGeneration,
}

impl Drop for SpawnRegistration<'_> {
    fn drop(&mut self) {
        self.generation.end_spawn();
    }
}

/// Terminal settle outcome recorded exactly once per dispatch task.
///
/// [`DispatchSettle::Abandoned`] carries the precise, fixed-cardinality reason
/// so producers and metrics can distinguish a hard shutdown-deadline abort from
/// reload retirement, registry rejection, backpressure, or a dropped task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSettle {
    Succeeded,
    FailedTransient,
    FailedPermanent,
    Abandoned(AbandonReason),
}

impl DispatchSettle {
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub const fn abandon_reason(self) -> Option<AbandonReason> {
        match self {
            Self::Abandoned(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Shared exactly-once settlement edge. The caller keeps a reference until the
/// process registry confirms admission; the task guard owns the other reference.
struct DeliveryTaskSettlement {
    generation: Arc<DispatchGeneration>,
    channel_type: &'static str,
    on_settle: Option<DeliveryCallback>,
    settled: AtomicBool,
    /// Set by the first statement of the task body (registry-owned body start).
    /// `false` means the registry never ran the task, so `attempted`/`in_flight`
    /// were never reserved and an unsettled drop is a rejection rather than an
    /// abandoned attempt. This is intentionally *not* "first channel transport
    /// poll": delaying the marker past an `.await` would misclassify hard
    /// shutdown aborts as `RegistryRejected`.
    attempt_started: AtomicBool,
    /// Exact observability lifecycle this task was admitted against. Populated
    /// by the context-bearing spawn factory; absent only when that factory
    /// never ran (should not happen for the notification spawn path).
    delivery_context: OnceLock<crate::observability_delivery::DeliveryTaskContext>,
}

impl DeliveryTaskSettlement {
    /// Publish that the registry actually started this task body, and reserve
    /// the attempt in metrics. Called exactly once as the first statement of
    /// the task body — before any `.await` and before the first channel
    /// transport poll — so hard-deadline drop classification stays race-free.
    fn mark_attempt_started(&self) {
        self.attempt_started.store(true, Ordering::Release);
        self.generation.metrics.record_attempted(self.channel_type);
    }

    /// Reason to record when the task future is dropped without an explicit
    /// settle.
    fn drop_reason(&self) -> AbandonReason {
        if !self.attempt_started.load(Ordering::Acquire) {
            // The registry refused or aborted the task before its body ran.
            // Pre-attempt rejection wins even if the captured lifecycle is
            // already cancelling at its deadline.
            AbandonReason::RegistryRejected
        } else if self
            .delivery_context
            .get()
            .is_some_and(|ctx| ctx.is_aborting_at_deadline())
        {
            AbandonReason::ShutdownDeadline
        } else {
            AbandonReason::TaskDropped
        }
    }

    fn settle(&self, outcome: DispatchSettle) {
        if self
            .settled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        match outcome {
            DispatchSettle::Succeeded => {
                self.generation.metrics.record_succeeded(self.channel_type);
            }
            DispatchSettle::FailedTransient => {
                self.generation
                    .metrics
                    .record_failed_transient(self.channel_type);
            }
            DispatchSettle::FailedPermanent => {
                self.generation
                    .metrics
                    .record_failed_permanent(self.channel_type);
            }
            DispatchSettle::Abandoned(reason) => {
                if self.attempt_started.load(Ordering::Acquire) {
                    // The delivery body started: release the `in_flight`
                    // reservation and count it under the post-body taxonomy.
                    // Transport may or may not have been polled.
                    self.generation
                        .metrics
                        .record_abandoned(self.channel_type, reason);
                } else {
                    // The body never started: never inflate `attempted`, and
                    // never decrement an `in_flight` reservation that was not
                    // taken.
                    self.generation
                        .metrics
                        .record_rejected(self.channel_type, reason);
                }
            }
        }
        if let Some(callback) = self.on_settle.as_ref() {
            invoke_delivery_callback(callback, outcome, self.channel_type);
        }
        // A drained generation guarantees producer settlement is complete, not
        // merely that the transport future returned.
        self.generation.end_task();
    }
}

pub(crate) fn invoke_delivery_callback(
    callback: &DeliveryCallback,
    outcome: DispatchSettle,
    channel_type: &'static str,
) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(outcome))).is_err() {
        tracing::warn!(
            channel_type,
            ?outcome,
            "notification delivery settle callback panicked; state rollback may be incomplete"
        );
    }
}

/// Ensures a cancelled/aborted dispatch task still decrements in-flight,
/// records abandonment, and rolls back producer state when its future is
/// dropped without returning a settle outcome.
struct DeliveryTaskGuard {
    settlement: Arc<DeliveryTaskSettlement>,
}

impl DeliveryTaskGuard {
    fn settle(&self, outcome: DispatchSettle) {
        self.settlement.settle(outcome);
    }
}

impl Drop for DeliveryTaskGuard {
    fn drop(&mut self) {
        // Unsettled drop: classify precisely instead of blanket-charging the
        // shutdown-deadline counter. `drop_reason` distinguishes a registry
        // rejection (task body never ran), a hard abort on the exact lifecycle
        // this task was admitted against, and any other dropped task.
        let reason = self.settlement.drop_reason();
        self.settlement.settle(DispatchSettle::Abandoned(reason));
    }
}
