//! Structured ownership for deferred observability delivery.
//!
//! Request drain and observability drain are deliberately separate phases.
//! Streaming terminal hooks and mirror summaries may still be running after
//! the last proxy body releases its request guard. Once request drain is
//! complete, [`shutdown`] closes external task admission, waits for already
//! admitted terminal work (including internally spawned mirror work), then
//! closes and awaits every registered queue worker under one absolute budget.
//!
//! # Task admission budget
//!
//! Terminal, mirror, and deadline-cleanup work share one aggregate pending-task
//! budget (`FERRUM_LOG_DELIVERY_MAX_TASKS`). Admission reserves a permit with a
//! lock-free counter *before* spawning or inserting into the task registry.
//! When the budget is exhausted, spawn returns `false` immediately (non-blocking
//! reject), increments the aggregate and budget-specific rejected-task
//! counters, and may emit a warning on the caller thread that is both sampled
//! and bounded to one line per window. Callers must treat rejection as the
//! observable signal and must not spawn further deferred work to report the
//! drop. Permits release when the task completes or is cancelled, so capacity
//! recovers without waiting for shutdown. The shared shutdown-drain deadline is
//! unchanged.
//!
//! # Generations
//!
//! A drained lifecycle is terminal: its task and worker admission stay closed
//! and its bounded drain report stays cached, so late producers on a shutting
//! down process cannot re-open delivery work behind the drain. In-process
//! callers (embedders, harnesses, supervisors) that start, stop, and start the
//! gateway again in one process therefore need a *fresh* lifecycle rather than
//! a reset of the drained one.
//!
//! [`DeliverySlot`] owns that state machine. It holds the current generation in
//! an [`ArcSwap`] and hands producers a snapshot of it:
//!
//! - [`DeliverySlot::begin_cycle`] reuses the current generation while it is
//!   still open, and installs a fresh generation when the current one is
//!   draining or closed. The install is a compare-and-swap against the exact
//!   observed generation, so two concurrent serving cycles cannot both replace
//!   the same generation and lose one of them.
//! - Producers (`spawn_*`, `register_worker`) always snapshot the *current*
//!   generation, so nothing is admitted into an old draining generation once a
//!   new one is installed.
//! - [`DeliverySlot::shutdown`] captures its generation up front and never
//!   re-reads the slot, so a stale generation's cleanup can never close a newer
//!   generation. Each generation keeps its own bounded queues, worker set,
//!   counters, and cached drain report.
//!
//! Producers are process-global by construction (request paths carry no
//! lifecycle handle), so concurrently *overlapping* in-process serving cycles
//! still share one generation and the first drain closes it for both. The
//! supported in-process model is sequential: start, drain, start again.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tokio::sync::{Notify, watch};
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

/// One delivery generation is open for new tasks and workers.
const GENERATION_OPEN: u8 = 0;
/// Shutdown has started on this generation; admission is closing down.
const GENERATION_DRAINING: u8 = 1;
/// Shutdown finished; admission is permanently closed and the report cached.
const GENERATION_CLOSED: u8 = 2;

static LIFECYCLE: OnceLock<DeliverySlot> = OnceLock::new();

fn global() -> &'static DeliverySlot {
    LIFECYCLE.get_or_init(|| DeliverySlot::new(0))
}

/// Configure the hot task registry before serving-mode plugin activation.
///
/// Called once per process from `main` before mode dispatch. First use creates
/// the open generation with the configured sharding and task budget. If an
/// earlier non-serving caller already touched the registry, the overrides are
/// recorded for the next generation without replacing an open lifecycle that
/// may own live workers.
///
/// Tests and non-serving callers that reach the registry first use the same
/// auto-sized fallback as other concurrent runtime maps and the default task
/// budget.
pub fn initialize(pool_shard_override: usize, max_tasks: usize) {
    LIFECYCLE
        .get_or_init(|| DeliverySlot::with_limits(pool_shard_override, max_tasks))
        .initialize_with_limits(pool_shard_override, max_tasks);
}

/// Open the delivery generation for a serving cycle.
///
/// Serving modes call this before plugin activation registers queue workers.
/// It reuses the currently open generation and installs a fresh one when the
/// previous cycle already drained, which is what makes an in-process
/// start -> shutdown -> start sequence deliver again.
pub fn begin_serving_cycle() -> u64 {
    let generation = global().begin_cycle();
    debug!(
        generation,
        "observability delivery lifecycle open for this serving cycle"
    );
    generation
}

/// Process-global holder for the current delivery generation.
///
/// Tests construct their own slot so lifecycle coverage never closes the
/// process-global registry out from under concurrently running suites.
pub struct DeliverySlot {
    current: ArcSwap<DeliveryLifecycle>,
    pool_shard_override: AtomicUsize,
    max_tasks: AtomicUsize,
    next_generation: AtomicU64,
}

impl DeliverySlot {
    pub fn new(pool_shard_override: usize) -> Self {
        Self::with_limits(
            pool_shard_override,
            crate::logging::LOG_DELIVERY_MAX_TASKS_DEFAULT,
        )
    }

    /// Construct a slot with an explicit aggregate task admission budget.
    ///
    /// Used by deterministic capacity tests and by process startup after env
    /// parsing. Values outside the documented clamp are brought into range.
    pub fn with_limits(pool_shard_override: usize, max_tasks: usize) -> Self {
        let max_tasks = clamp_max_tasks(max_tasks);
        Self {
            current: ArcSwap::from_pointee(DeliveryLifecycle::with_limits(
                pool_shard_override,
                1,
                max_tasks,
            )),
            pool_shard_override: AtomicUsize::new(pool_shard_override),
            max_tasks: AtomicUsize::new(max_tasks),
            next_generation: AtomicU64::new(2),
        }
    }

    /// Record the shard override and make sure an open generation is current.
    ///
    /// A generation that is already open is never replaced, so a caller that
    /// re-initializes mid-serve cannot orphan queue workers that are still
    /// registered against it. The new override applies to the next generation.
    /// A drained generation is replaced immediately, which is what lets a
    /// second in-process serve deliver again.
    #[allow(dead_code)] // Used by external lifecycle tests; production calls `initialize_with_limits`.
    pub fn initialize(&self, pool_shard_override: usize) {
        self.initialize_with_limits(pool_shard_override, self.max_tasks.load(Ordering::Acquire));
    }

    /// Record shard and task-budget overrides for the next open generation.
    pub fn initialize_with_limits(&self, pool_shard_override: usize, max_tasks: usize) {
        self.pool_shard_override
            .store(pool_shard_override, Ordering::Release);
        self.max_tasks
            .store(clamp_max_tasks(max_tasks), Ordering::Release);
        // Reuse the same state-aware CAS loop as serving-cycle admission.
        // Re-checking after every failed CAS is essential: another caller may
        // have installed an open generation after we first observed a drained
        // one, and replacing that generation would orphan its live workers.
        self.begin_cycle();
    }

    /// Swap a fresh generation in for `observed`, or fail if it already moved.
    fn try_install_generation(&self, observed: &Arc<DeliveryLifecycle>) -> Option<u64> {
        let next = self.new_generation();
        let generation = next.generation;
        let previous = self.current.compare_and_swap(observed, next);
        Arc::ptr_eq(observed, &*previous).then_some(generation)
    }

    fn new_generation(&self) -> Arc<DeliveryLifecycle> {
        Arc::new(DeliveryLifecycle::with_limits(
            self.pool_shard_override.load(Ordering::Acquire),
            self.next_generation.fetch_add(1, Ordering::Relaxed),
            self.max_tasks.load(Ordering::Acquire),
        ))
    }

    /// Reuse the open generation, or install a fresh one after a drain.
    ///
    /// Returns the generation id serving work will be admitted into.
    pub fn begin_cycle(&self) -> u64 {
        loop {
            let current = self.current.load_full();
            if current.state() == GENERATION_OPEN {
                return current.generation;
            }
            if let Some(generation) = self.try_install_generation(&current) {
                return generation;
            }
        }
    }

    /// Generation id currently admitting delivery work.
    #[allow(dead_code)] // Used by external lifecycle tests; the bin reads the field directly.
    pub fn current_generation(&self) -> u64 {
        self.current.load().generation
    }

    /// Configured aggregate task admission budget for the current generation.
    #[allow(dead_code)] // Used by external lifecycle tests; the bin reads the lifecycle field in `render_prometheus`.
    pub fn max_tasks(&self) -> usize {
        self.current.load().max_tasks
    }

    /// Tasks currently held in the registry for the current generation.
    #[allow(dead_code)] // Used by external lifecycle tests; the bin reads `tasks.len()` in `render_prometheus`.
    pub fn active_tasks(&self) -> usize {
        self.current.load().tasks.len()
    }

    /// Reserved admission permits for the current generation (registry plus
    /// in-flight spawn handoff).
    #[allow(dead_code)] // Used by external lifecycle tests; the bin reads the atomic in `render_prometheus`.
    pub fn admitted_tasks(&self) -> u64 {
        self.current.load().admitted_tasks.load(Ordering::Acquire)
    }

    /// Aggregate rejected-task count for the current generation.
    #[allow(dead_code)] // Used by external lifecycle tests; the bin uses `rejected_task_count()` in `render_prometheus`.
    pub fn rejected_tasks(&self) -> u64 {
        self.current.load().rejected_task_count()
    }

    /// Budget-exhaustion rejects only, for the current generation.
    ///
    /// The aggregate `rejected_tasks` counter also covers closed-admission and
    /// no-runtime rejects, so operators cannot use it alone to tell whether
    /// `FERRUM_LOG_DELIVERY_MAX_TASKS` is the limiting factor.
    #[allow(dead_code)] // Used by external lifecycle tests; the bin reads the atomic in `render_prometheus`.
    pub fn capacity_rejected_tasks(&self) -> u64 {
        self.current.load().capacity_rejection_count()
    }

    fn snapshot(&self) -> Arc<DeliveryLifecycle> {
        self.current.load_full()
    }

    /// Register request/body-originated terminal cleanup.
    pub fn spawn_terminal<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.snapshot()
            .spawn(TaskAdmission::External, DeliveryTaskKind::Terminal, future)
    }

    /// Register terminal cleanup with a probe for the exact admitted lifecycle.
    ///
    /// The factory receives a [`DeliveryTaskContext`] bound to the same
    /// generation `Arc` that performs admission — one snapshot, not a context
    /// sample followed by a second load that could observe a replacement.
    pub(crate) fn spawn_terminal_with_context<F, Fut>(&self, factory: F) -> bool
    where
        F: FnOnce(DeliveryTaskContext) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.snapshot().spawn_with_context(
            TaskAdmission::External,
            DeliveryTaskKind::Terminal,
            factory,
        )
    }

    /// Register mirror work spawned by an already admitted delivery task.
    pub fn spawn_mirror<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.snapshot()
            .spawn(TaskAdmission::Internal, DeliveryTaskKind::Mirror, future)
    }

    /// Register deadline-detached buffered response cleanup.
    pub fn spawn_deadline_cleanup<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.snapshot().spawn(
            TaskAdmission::External,
            DeliveryTaskKind::DeadlineCleanup,
            future,
        )
    }

    pub fn register_worker(&self, worker: Arc<DeliveryWorkerControl>) -> u64 {
        self.snapshot().register_worker(worker)
    }

    /// Drain the generation that is current when the drain starts.
    ///
    /// The generation is captured before the first await, so a later cycle
    /// installed while this drain runs is never closed by it.
    pub async fn shutdown(&self, timeout: Duration) -> DeliveryDrainReport {
        let lifecycle = self.snapshot();
        lifecycle.shutdown(timeout).await
    }

    /// Shut down the captured lifecycle and signal once admission is closed
    /// and its absolute drain deadline has been established.
    ///
    /// Hidden test seam only: external paused-time regressions use the signal
    /// as a causal barrier instead of polling admission or relying on scheduler
    /// order. Production callers use [`Self::shutdown`].
    #[allow(dead_code)] // Used by external lifecycle tests; production callers use `shutdown`.
    #[doc(hidden)]
    pub async fn shutdown_with_admission_closed_for_test(
        &self,
        timeout: Duration,
        admission_closed_tx: tokio::sync::oneshot::Sender<()>,
    ) -> DeliveryDrainReport {
        let lifecycle = self.snapshot();
        lifecycle
            .shutdown_with_admission_closed_signal(timeout, Some(admission_closed_tx))
            .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryTaskKind {
    Terminal,
    Mirror,
    DeadlineCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskAdmission {
    External,
    Internal,
}

struct TrackedTask {
    kind: DeliveryTaskKind,
    abort: AbortHandle,
}

struct DeliveryCounters {
    rejected_terminal: AtomicU64,
    rejected_mirror: AtomicU64,
    rejected_deadline_cleanup: AtomicU64,
    cancelled_terminal: AtomicU64,
    cancelled_mirror: AtomicU64,
    cancelled_deadline_cleanup: AtomicU64,
    lost_worker_records: AtomicU64,
    timed_out_drains: AtomicU64,
}

impl DeliveryCounters {
    const fn new() -> Self {
        Self {
            rejected_terminal: AtomicU64::new(0),
            rejected_mirror: AtomicU64::new(0),
            rejected_deadline_cleanup: AtomicU64::new(0),
            cancelled_terminal: AtomicU64::new(0),
            cancelled_mirror: AtomicU64::new(0),
            cancelled_deadline_cleanup: AtomicU64::new(0),
            lost_worker_records: AtomicU64::new(0),
            timed_out_drains: AtomicU64::new(0),
        }
    }

    fn record_rejected(&self, kind: DeliveryTaskKind) {
        match kind {
            DeliveryTaskKind::Terminal => &self.rejected_terminal,
            DeliveryTaskKind::Mirror => &self.rejected_mirror,
            DeliveryTaskKind::DeadlineCleanup => &self.rejected_deadline_cleanup,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn record_cancelled(&self, kind: DeliveryTaskKind) {
        match kind {
            DeliveryTaskKind::Terminal => &self.cancelled_terminal,
            DeliveryTaskKind::Mirror => &self.cancelled_mirror,
            DeliveryTaskKind::DeadlineCleanup => &self.cancelled_deadline_cleanup,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

fn clamp_max_tasks(max_tasks: usize) -> usize {
    max_tasks.clamp(
        crate::logging::LOG_DELIVERY_MAX_TASKS_MIN,
        crate::logging::LOG_DELIVERY_MAX_TASKS_MAX,
    )
}

/// Exact delivery-lifecycle probe captured at task admission.
///
/// Notification settlement consults this snapshot rather than the process-global
/// current generation, so a draining lifecycle that is replaced mid-drain still
/// classifies its own hard aborts correctly.
#[derive(Clone)]
pub(crate) struct DeliveryTaskContext {
    lifecycle: Arc<DeliveryLifecycle>,
}

impl DeliveryTaskContext {
    /// Whether this exact lifecycle has begun hard-aborting admitted tasks
    /// because its shutdown drain deadline expired.
    #[inline]
    pub(crate) fn is_aborting_at_deadline(&self) -> bool {
        self.lifecycle.cancelling_tasks.load(Ordering::Acquire)
    }
}

struct DeliveryLifecycle {
    generation: u64,
    state: AtomicU8,
    max_tasks: usize,
    admitted_tasks: AtomicU64,
    /// Capacity-only rejection count. Kept separate from the aggregate
    /// rejected-task counters (which also cover closed-admission and
    /// no-runtime rejects) so the caller-thread warning rate limit cannot be
    /// starved by shutdown-time rejects.
    capacity_rejections: AtomicU64,
    /// Monotonic milliseconds at which the last capacity warning was emitted,
    /// `0` before the first. Bounds the *rate* of caller-thread diagnostics;
    /// the count gate alone only samples them, so a sustained flood could
    /// still scale warnings with rejected traffic.
    capacity_warn_last_ms: AtomicU64,
    accepting_external_tasks: AtomicBool,
    accepting_internal_tasks: AtomicBool,
    accepting_workers: AtomicBool,
    cancelling_tasks: AtomicBool,
    active_task_registrations: AtomicU64,
    next_task_id: AtomicU64,
    next_worker_id: AtomicU64,
    tasks: DashMap<u64, TrackedTask>,
    tasks_changed: Notify,
    workers: Mutex<HashMap<u64, Arc<DeliveryWorkerControl>>>,
    workers_changed: Arc<Notify>,
    counters: DeliveryCounters,
    shutdown_report: tokio::sync::Mutex<Option<DeliveryDrainReport>>,
}

impl DeliveryLifecycle {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_limits(0, 1, crate::logging::LOG_DELIVERY_MAX_TASKS_DEFAULT)
    }

    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    fn with_limits(pool_shard_override: usize, generation: u64, max_tasks: usize) -> Self {
        Self {
            generation,
            state: AtomicU8::new(GENERATION_OPEN),
            max_tasks: clamp_max_tasks(max_tasks),
            admitted_tasks: AtomicU64::new(0),
            capacity_rejections: AtomicU64::new(0),
            capacity_warn_last_ms: AtomicU64::new(0),
            accepting_external_tasks: AtomicBool::new(true),
            accepting_internal_tasks: AtomicBool::new(true),
            accepting_workers: AtomicBool::new(true),
            cancelling_tasks: AtomicBool::new(false),
            active_task_registrations: AtomicU64::new(0),
            next_task_id: AtomicU64::new(1),
            next_worker_id: AtomicU64::new(1),
            tasks: DashMap::with_shard_amount(crate::util::sharding::pool_shard_amount(
                pool_shard_override,
            )),
            tasks_changed: Notify::new(),
            workers: Mutex::new(HashMap::new()),
            workers_changed: Arc::new(Notify::new()),
            counters: DeliveryCounters::new(),
            shutdown_report: tokio::sync::Mutex::new(None),
        }
    }

    fn rejected_task_count(&self) -> u64 {
        self.counters
            .rejected_terminal
            .load(Ordering::Relaxed)
            .saturating_add(self.counters.rejected_mirror.load(Ordering::Relaxed))
            .saturating_add(
                self.counters
                    .rejected_deadline_cleanup
                    .load(Ordering::Relaxed),
            )
    }

    fn try_reserve_task_permit(&self) -> Option<TaskAdmissionPermit<'_>> {
        let max_tasks = self.max_tasks as u64;
        // Bounded compare-and-swap rather than add-then-undo: concurrent
        // callers must never publish a reservation depth above the configured
        // budget, not even transiently on the exported gauge.
        self.admitted_tasks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |admitted| {
                (admitted < max_tasks).then_some(admitted + 1)
            })
            .ok()
            .map(|_| TaskAdmissionPermit {
                lifecycle: self,
                live: true,
            })
    }

    fn release_task_permit(&self) {
        let released =
            self.admitted_tasks
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |admitted| {
                    admitted.checked_sub(1)
                });
        debug_assert!(
            released.is_ok(),
            "delivery task permit release requires an owned permit"
        );
    }

    /// Budget-exhaustion rejects only. The aggregate `rejected_task_count`
    /// also covers closed-admission and no-runtime rejects.
    fn capacity_rejection_count(&self) -> u64 {
        self.capacity_rejections.load(Ordering::Relaxed)
    }

    /// Claim the capacity-warning window, returning `true` for the single
    /// caller that may emit this window's line.
    ///
    /// The count gate in `record_capacity_rejection` only *samples* rejections,
    /// so under a sustained flood the warning rate would still scale with
    /// attacker-driven traffic. This adds an absolute ceiling of one line per
    /// window per delivery lifecycle generation, matching the mesh-authz idiom.
    /// Only the sampled
    /// callers read the clock, so the reject path stays allocation- and
    /// syscall-free.
    fn claim_capacity_warning_window(&self) -> bool {
        const WINDOW_MS: u64 = 5_000;
        let now = crate::socket_opts::monotonic_now_ms();
        let last = self.capacity_warn_last_ms.load(Ordering::Relaxed);
        // Emit on the first event (`last == 0`) or after a full window. A single
        // CAS claims the window; losers stay silent. `saturating_sub` guards a
        // coarse clock that does not advance between calls.
        if last != 0 && now.saturating_sub(last) < WINDOW_MS {
            return false;
        }
        self.capacity_warn_last_ms
            .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    fn record_capacity_rejection(&self, kind: DeliveryTaskKind) {
        self.counters.record_rejected(kind);
        let capacity_rejections = self
            .capacity_rejections
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        // Rate-limit caller-thread diagnostics so a saturated sink cannot turn
        // capacity rejects into a logging storm or recursive deferred work.
        // Process `warn!` flows through the non-blocking log sinks, not through
        // deferred delivery spawn, so this cannot re-enter admission.
        if (capacity_rejections == 1 || capacity_rejections.is_multiple_of(1_024))
            && self.claim_capacity_warning_window()
        {
            warn!(
                generation = self.generation,
                ?kind,
                max_tasks = self.max_tasks,
                admitted_tasks = self.admitted_tasks.load(Ordering::Acquire),
                capacity_rejections,
                rejected_tasks = self.rejected_task_count(),
                "observability delivery task budget exhausted; rejecting admission"
            );
        }
    }

    fn spawn<F>(
        self: &Arc<Self>,
        admission: TaskAdmission,
        kind: DeliveryTaskKind,
        future: F,
    ) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_with_context(admission, kind, |_| future)
    }

    /// Admit `factory`'s future against this exact lifecycle `Arc`.
    ///
    /// The context passed to `factory` is built from `self` before admission
    /// continues, so callers never observe a different generation than the one
    /// that reserved the permit and inserted the registry entry.
    fn spawn_with_context<F, Fut>(
        self: &Arc<Self>,
        admission: TaskAdmission,
        kind: DeliveryTaskKind,
        factory: F,
    ) -> bool
    where
        F: FnOnce(DeliveryTaskContext) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Bind the probe to this Arc before any further slot-level load can
        // diverge. Admission below runs on the same generation.
        let future = factory(DeliveryTaskContext {
            lifecycle: Arc::clone(self),
        });
        if !self.accepts(admission) {
            self.counters.record_rejected(kind);
            return false;
        }
        self.active_task_registrations
            .fetch_add(1, Ordering::AcqRel);
        let _registration = TaskRegistration {
            lifecycle: self.as_ref(),
        };
        if !self.accepts(admission) {
            self.counters.record_rejected(kind);
            return false;
        }
        let Some(mut permit) = self.try_reserve_task_permit() else {
            self.record_capacity_rejection(kind);
            return false;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // `permit` drops and releases; no registry entry exists yet.
            self.counters.record_rejected(kind);
            return false;
        };

        let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let lifecycle = Arc::clone(self);
        let task = handle.spawn(async move {
            if start_rx.await.is_err() {
                // Caller dropped `start_tx` after releasing or transferring the
                // permit (cancel/send-failure paths). Do not release again.
                return;
            }
            let _completion = TaskCompletion {
                task_id,
                lifecycle: Arc::clone(&lifecycle),
            };
            future.await;
        });
        let abort = task.abort_handle();
        drop(task);

        self.tasks.insert(task_id, TrackedTask { kind, abort });
        if self.cancelling_tasks.load(Ordering::Acquire) {
            if let Some((_, task)) = self.tasks.remove(&task_id) {
                task.abort.abort();
                // This removal owns the permit via `permit` drop below.
                self.counters.record_cancelled(kind);
            } else {
                // `cancel_remaining` already removed the entry and released.
                permit.disarm();
            }
            return false;
        }
        if start_tx.send(()).is_err() {
            // Task never started. Reclaim the registry entry when we still own
            // it; if `cancel_remaining` won the race it already released.
            if self.tasks.remove(&task_id).is_none() {
                permit.disarm();
            } else {
                self.counters.record_cancelled(kind);
            }
            self.tasks_changed.notify_one();
            return false;
        }
        // Successful handoff: registry/`TaskCompletion` owns release.
        permit.disarm();
        true
    }

    fn accepts(&self, admission: TaskAdmission) -> bool {
        match admission {
            TaskAdmission::External => self.accepting_external_tasks.load(Ordering::Acquire),
            TaskAdmission::Internal => self.accepting_internal_tasks.load(Ordering::Acquire),
        }
    }

    fn finish_task(&self, task_id: u64) {
        if self.tasks.remove(&task_id).is_some() {
            self.release_task_permit();
        }
        self.tasks_changed.notify_one();
    }

    fn finish_task_registration(&self) {
        let previous = self
            .active_task_registrations
            .fetch_sub(1, Ordering::AcqRel);
        if previous <= 1 {
            self.tasks_changed.notify_one();
        }
    }

    fn register_worker(&self, worker: Arc<DeliveryWorkerControl>) -> u64 {
        let worker_id = self.next_worker_id.fetch_add(1, Ordering::Relaxed);
        worker.register_completion_notify(&self.workers_changed);
        let registered = match self.workers.lock() {
            Ok(mut workers) => {
                if !self.accepting_workers.load(Ordering::Acquire) {
                    false
                } else {
                    workers.retain(|_, registered| !registered.is_finished());
                    workers.insert(worker_id, Arc::clone(&worker));
                    true
                }
            }
            Err(poisoned) => {
                let mut workers = poisoned.into_inner();
                if !self.accepting_workers.load(Ordering::Acquire) {
                    false
                } else {
                    workers.retain(|_, registered| !registered.is_finished());
                    workers.insert(worker_id, Arc::clone(&worker));
                    true
                }
            }
        };
        if !registered {
            self.counters
                .lost_worker_records
                .fetch_add(worker.pending_records(), Ordering::Relaxed);
            worker.abort();
        }
        worker_id
    }

    async fn wait_for_tasks(&self, deadline: Instant) -> bool {
        loop {
            let changed = self.tasks_changed.notified();
            if self.tasks.is_empty() && self.active_task_registrations.load(Ordering::Acquire) == 0
            {
                return true;
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return false;
            }
        }
    }

    async fn wait_for_workers(&self, deadline: Instant) -> bool {
        loop {
            let changed = self.workers_changed.notified();
            let workers = match self.workers.lock() {
                Ok(workers) => workers.values().cloned().collect::<Vec<_>>(),
                Err(poisoned) => poisoned.into_inner().values().cloned().collect::<Vec<_>>(),
            };
            if workers.iter().all(|worker| worker.is_finished()) {
                return true;
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return false;
            }
        }
    }

    fn close_workers(&self) {
        let workers = match self.workers.lock() {
            Ok(workers) => workers.values().cloned().collect::<Vec<_>>(),
            Err(poisoned) => poisoned.into_inner().values().cloned().collect::<Vec<_>>(),
        };
        for worker in workers {
            worker.close_admission();
        }
    }

    fn cancel_remaining(&self) {
        self.cancelling_tasks.store(true, Ordering::Release);
        let task_ids = self
            .tasks
            .iter()
            .map(|task| *task.key())
            .collect::<Vec<_>>();
        for task_id in task_ids {
            if let Some((_, task)) = self.tasks.remove(&task_id) {
                task.abort.abort();
                self.release_task_permit();
                self.counters.record_cancelled(task.kind);
            }
        }

        let workers = match self.workers.lock() {
            Ok(workers) => workers.values().cloned().collect::<Vec<_>>(),
            Err(poisoned) => poisoned.into_inner().values().cloned().collect::<Vec<_>>(),
        };
        for worker in workers {
            if worker.is_finished() {
                continue;
            }
            let pending_records = worker.pending_records();
            warn!(
                plugin = worker.plugin_name(),
                record_count = pending_records,
                "observability delivery worker did not drain before shutdown"
            );
            self.counters
                .lost_worker_records
                .fetch_add(pending_records, Ordering::Relaxed);
            worker.abort();
        }
        self.tasks_changed.notify_one();
        self.workers_changed.notify_one();
    }

    async fn shutdown(&self, timeout: Duration) -> DeliveryDrainReport {
        self.shutdown_with_admission_closed_signal(timeout, None)
            .await
    }

    async fn shutdown_with_admission_closed_signal(
        &self,
        timeout: Duration,
        admission_closed_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> DeliveryDrainReport {
        let mut cached_report = self.shutdown_report.lock().await;
        if let Some(report) = *cached_report {
            if let Some(tx) = admission_closed_tx {
                let _ = tx.send(());
            }
            return report;
        }

        // Publish the draining state before closing admission so a serving
        // cycle that starts during this drain installs a fresh generation
        // instead of enqueueing into the one being closed here.
        self.state.store(GENERATION_DRAINING, Ordering::Release);
        self.accepting_external_tasks
            .store(false, Ordering::Release);
        let deadline = Instant::now() + timeout;
        if let Some(tx) = admission_closed_tx {
            let _ = tx.send(());
        }

        let tasks_drained = self.wait_for_tasks(deadline).await;
        self.accepting_internal_tasks
            .store(false, Ordering::Release);
        self.accepting_workers.store(false, Ordering::Release);
        self.close_workers();
        let workers_drained = tasks_drained && self.wait_for_workers(deadline).await;
        if !tasks_drained || !workers_drained {
            self.counters
                .timed_out_drains
                .fetch_add(1, Ordering::Relaxed);
            self.cancel_remaining();
        }

        let report = self.report(tasks_drained, workers_drained);
        if !report.complete() {
            warn!(
                task_count = report.cancelled_tasks,
                record_count = report.lost_worker_records,
                timeout_ms = timeout.as_millis(),
                "observability delivery drain exceeded its shutdown budget"
            );
        }
        *cached_report = Some(report);
        self.state.store(GENERATION_CLOSED, Ordering::Release);
        report
    }

    fn report(&self, tasks_drained: bool, workers_drained: bool) -> DeliveryDrainReport {
        DeliveryDrainReport {
            tasks_drained,
            workers_drained,
            rejected_tasks: self.rejected_task_count(),
            cancelled_tasks: self
                .counters
                .cancelled_terminal
                .load(Ordering::Relaxed)
                .saturating_add(self.counters.cancelled_mirror.load(Ordering::Relaxed))
                .saturating_add(
                    self.counters
                        .cancelled_deadline_cleanup
                        .load(Ordering::Relaxed),
                ),
            lost_worker_records: self.counters.lost_worker_records.load(Ordering::Relaxed),
        }
    }
}

struct TaskCompletion {
    task_id: u64,
    lifecycle: Arc<DeliveryLifecycle>,
}

struct TaskRegistration<'a> {
    lifecycle: &'a DeliveryLifecycle,
}

/// Lock-free admission permit held between reserve and successful registry
/// handoff. Drop releases unless [`TaskAdmissionPermit::disarm`] transfers
/// ownership to the registry/`TaskCompletion` path.
struct TaskAdmissionPermit<'a> {
    lifecycle: &'a DeliveryLifecycle,
    live: bool,
}

impl TaskAdmissionPermit<'_> {
    fn disarm(&mut self) {
        self.live = false;
    }
}

impl Drop for TaskAdmissionPermit<'_> {
    fn drop(&mut self) {
        if self.live {
            self.lifecycle.release_task_permit();
        }
    }
}

impl Drop for TaskRegistration<'_> {
    fn drop(&mut self) {
        self.lifecycle.finish_task_registration();
    }
}

impl Drop for TaskCompletion {
    fn drop(&mut self) {
        self.lifecycle.finish_task(self.task_id);
    }
}

/// Lifecycle control shared by a queue worker and the process registry.
///
/// The worker owns a [`WorkerCompletion`] guard for its entire future. Its
/// destructor signals completion even if the future panics or is aborted.
pub struct DeliveryWorkerControl {
    plugin_name: &'static str,
    accepting: AtomicBool,
    active_admissions: AtomicU64,
    admissions_changed: Notify,
    close_tx: watch::Sender<bool>,
    abort: OnceLock<AbortHandle>,
    finished: AtomicBool,
    completed_cleanly: AtomicBool,
    finished_notify: Notify,
    pending: Arc<dyn Fn() -> u64 + Send + Sync>,
    completion_notifiers: Mutex<Vec<Weak<Notify>>>,
}

impl DeliveryWorkerControl {
    pub fn new<F>(plugin_name: &'static str, pending: F) -> (Arc<Self>, watch::Receiver<bool>)
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        let (close_tx, close_rx) = watch::channel(false);
        (
            Arc::new(Self {
                plugin_name,
                accepting: AtomicBool::new(true),
                active_admissions: AtomicU64::new(0),
                admissions_changed: Notify::new(),
                close_tx,
                abort: OnceLock::new(),
                finished: AtomicBool::new(false),
                completed_cleanly: AtomicBool::new(false),
                finished_notify: Notify::new(),
                pending: Arc::new(pending),
                completion_notifiers: Mutex::new(Vec::new()),
            }),
            close_rx,
        )
    }

    pub fn install_abort_handle(&self, abort: AbortHandle) -> Result<(), &'static str> {
        self.abort
            .set(abort)
            .map_err(|_| "delivery worker abort handle already installed")
    }

    pub fn completion(self: &Arc<Self>) -> WorkerCompletion {
        WorkerCompletion {
            control: Arc::clone(self),
            clean: false,
        }
    }

    pub fn accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    pub fn try_admit(self: &Arc<Self>) -> Option<DeliveryWorkerAdmission> {
        if !self.accepting() {
            return None;
        }
        self.active_admissions.fetch_add(1, Ordering::AcqRel);
        if !self.accepting() {
            self.release_admission();
            return None;
        }
        Some(DeliveryWorkerAdmission {
            control: Arc::clone(self),
        })
    }

    pub async fn wait_for_admissions(&self) {
        loop {
            let changed = self.admissions_changed.notified();
            if self.active_admissions.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }

    pub fn plugin_name(&self) -> &'static str {
        self.plugin_name
    }

    pub fn close_admission(&self) {
        self.accepting.store(false, Ordering::Release);
        let _ = self.close_tx.send(true);
    }

    pub fn pending_records(&self) -> u64 {
        (self.pending)()
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    pub fn abort(&self) {
        self.close_admission();
        if let Some(abort) = self.abort.get() {
            abort.abort();
        }
    }

    fn register_completion_notify(&self, notify: &Arc<Notify>) {
        match self.completion_notifiers.lock() {
            Ok(mut notifiers) => notifiers.push(Arc::downgrade(notify)),
            Err(poisoned) => poisoned.into_inner().push(Arc::downgrade(notify)),
        }
    }

    fn release_admission(&self) {
        let previous = self.active_admissions.fetch_sub(1, Ordering::AcqRel);
        if previous <= 1 {
            self.admissions_changed.notify_one();
        }
    }

    #[allow(dead_code)] // Used by explicit sink finalizers and lifecycle tests.
    pub async fn wait_finished(&self) -> bool {
        loop {
            let finished = self.finished_notify.notified();
            if self.is_finished() {
                return self.completed_cleanly.load(Ordering::Acquire);
            }
            finished.await;
        }
    }
}

pub struct DeliveryWorkerAdmission {
    control: Arc<DeliveryWorkerControl>,
}

impl Drop for DeliveryWorkerAdmission {
    fn drop(&mut self) {
        self.control.release_admission();
    }
}

pub struct WorkerCompletion {
    control: Arc<DeliveryWorkerControl>,
    clean: bool,
}

impl WorkerCompletion {
    pub fn complete(&mut self) {
        self.clean = true;
    }
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        self.control
            .completed_cleanly
            .store(self.clean, Ordering::Release);
        self.control.finished.store(true, Ordering::Release);
        self.control.finished_notify.notify_waiters();
        self.control.finished_notify.notify_one();
        let notifiers = match self.control.completion_notifiers.lock() {
            Ok(notifiers) => notifiers.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        for notify in notifiers {
            if let Some(notify) = notify.upgrade() {
                notify.notify_one();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryDrainReport {
    pub tasks_drained: bool,
    pub workers_drained: bool,
    pub rejected_tasks: u64,
    pub cancelled_tasks: u64,
    pub lost_worker_records: u64,
}

impl DeliveryDrainReport {
    pub const fn complete(self) -> bool {
        self.tasks_drained && self.workers_drained
    }
}

/// Test-owned delivery lifecycle that never touches the process-global singleton.
///
/// Lib/unit suites run in parallel and serving-mode paths may permanently close
/// [`shutdown`]'s process-global admission. Deferred-log unit tests bind an
/// owned lifecycle so terminal dispatch stays deterministic without mutating
/// global state from concurrent tests.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct OwnedDeliveryLifecycle {
    inner: Arc<DeliveryLifecycle>,
}

#[cfg(test)]
impl OwnedDeliveryLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(DeliveryLifecycle::new()),
        }
    }

    pub(crate) fn spawn_terminal<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.inner
            .spawn(TaskAdmission::External, DeliveryTaskKind::Terminal, future)
    }

    /// Await admitted tasks without closing admission on this owned lifecycle.
    pub(crate) async fn drain_tasks(&self, timeout: Duration) -> bool {
        self.inner.wait_for_tasks(Instant::now() + timeout).await
    }
}

/// Register request/body-originated terminal cleanup.
pub fn spawn_terminal<F>(future: F) -> bool
where
    F: Future<Output = ()> + Send + 'static,
{
    global().spawn_terminal(future)
}

/// Register terminal cleanup with a probe for the exact admitted lifecycle.
///
/// See [`DeliverySlot::spawn_terminal_with_context`].
pub(crate) fn spawn_terminal_with_context<F, Fut>(factory: F) -> bool
where
    F: FnOnce(DeliveryTaskContext) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    global().spawn_terminal_with_context(factory)
}

/// Register mirror work spawned by an already admitted delivery task.
///
/// Internal admission remains open while shutdown drains terminal work so a
/// terminal task that reaches mirror collection after request drain is not
/// spuriously rejected.
pub fn spawn_mirror<F>(future: F) -> bool
where
    F: Future<Output = ()> + Send + 'static,
{
    global().spawn_mirror(future)
}

/// Register deadline-detached buffered response cleanup.
pub fn spawn_deadline_cleanup<F>(future: F) -> bool
where
    F: Future<Output = ()> + Send + 'static,
{
    global().spawn_deadline_cleanup(future)
}

pub fn register_worker(worker: Arc<DeliveryWorkerControl>) -> u64 {
    global().register_worker(worker)
}

pub async fn shutdown(timeout: Duration) -> DeliveryDrainReport {
    global().shutdown(timeout).await
}

pub fn render_prometheus() -> String {
    let lifecycle = global().snapshot();
    let generation = lifecycle.generation;
    let report = lifecycle.report(true, true);
    let active_tasks = lifecycle.tasks.len();
    let admitted_tasks = lifecycle.admitted_tasks.load(Ordering::Acquire);
    let max_tasks = lifecycle.max_tasks;
    let capacity_rejections = lifecycle.capacity_rejection_count();
    let retained_bytes = crate::plugins::utils::byte_budget::process_retained_bytes();
    let max_retained_bytes = crate::plugins::utils::byte_budget::process_max_retained_bytes();
    let retained_high_water =
        crate::plugins::utils::byte_budget::process_retained_bytes_high_water();
    let ceiling_rejections = crate::plugins::utils::byte_budget::process_ceiling_rejections();
    let batch_lost_records =
        crate::plugins::utils::byte_budget::batch_materialization_lost_records();
    let batch_loss_events = crate::plugins::utils::byte_budget::batch_materialization_loss_events();
    let batch_fallbacks = crate::plugins::utils::byte_budget::batch_materialization_fallbacks();
    let active_workers = match lifecycle.workers.lock() {
        Ok(workers) => workers
            .values()
            .filter(|worker| !worker.is_finished())
            .count(),
        Err(poisoned) => poisoned
            .into_inner()
            .values()
            .filter(|worker| !worker.is_finished())
            .count(),
    };
    format!(
        "# HELP ferrum_observability_delivery_generation Current delivery lifecycle generation; increments when a serving cycle reopens delivery after a drain.\n\
         # TYPE ferrum_observability_delivery_generation gauge\n\
         ferrum_observability_delivery_generation {generation}\n\
         # HELP ferrum_observability_delivery_active_tasks Deferred observability tasks currently owned by the shutdown lifecycle.\n\
         # TYPE ferrum_observability_delivery_active_tasks gauge\n\
         ferrum_observability_delivery_active_tasks {active_tasks}\n\
         # HELP ferrum_observability_delivery_admitted_tasks Deferred observability tasks holding an admission permit (registry plus in-flight spawn handoff).\n\
         # TYPE ferrum_observability_delivery_admitted_tasks gauge\n\
         ferrum_observability_delivery_admitted_tasks {admitted_tasks}\n\
         # HELP ferrum_observability_delivery_max_tasks Configured aggregate admission budget for terminal, mirror, and deadline-cleanup tasks.\n\
         # TYPE ferrum_observability_delivery_max_tasks gauge\n\
         ferrum_observability_delivery_max_tasks {max_tasks}\n\
         # HELP ferrum_observability_delivery_active_workers Queue workers currently owned by the shutdown lifecycle.\n\
         # TYPE ferrum_observability_delivery_active_workers gauge\n\
         ferrum_observability_delivery_active_workers {active_workers}\n\
         # HELP ferrum_observability_delivery_rejected_tasks_total Delivery tasks rejected after lifecycle admission closed, task-budget exhaustion, or without a runtime.\n\
         # TYPE ferrum_observability_delivery_rejected_tasks_total counter\n\
         ferrum_observability_delivery_rejected_tasks_total {}\n\
         # HELP ferrum_observability_delivery_capacity_rejected_tasks_total Delivery tasks rejected specifically because the aggregate task budget was exhausted.\n\
         # TYPE ferrum_observability_delivery_capacity_rejected_tasks_total counter\n\
         ferrum_observability_delivery_capacity_rejected_tasks_total {capacity_rejections}\n\
         # HELP ferrum_observability_delivery_cancelled_tasks_total Delivery tasks cancelled on shutdown-budget expiry or during spawn/cancel handoff races.\n\
         # TYPE ferrum_observability_delivery_cancelled_tasks_total counter\n\
         ferrum_observability_delivery_cancelled_tasks_total {}\n\
         # HELP ferrum_observability_delivery_lost_worker_records_total Queued records abandoned when worker drain exceeded the shutdown budget.\n\
         # TYPE ferrum_observability_delivery_lost_worker_records_total counter\n\
         ferrum_observability_delivery_lost_worker_records_total {}\n\
         # HELP ferrum_observability_delivery_drain_timeouts_total Observability shutdown drains that exhausted their shared deadline.\n\
         # TYPE ferrum_observability_delivery_drain_timeouts_total counter\n\
         ferrum_observability_delivery_drain_timeouts_total {}\n\
         # HELP ferrum_observability_retained_bytes Bytes currently retained across every observability sink instance in this process.\n\
         # TYPE ferrum_observability_retained_bytes gauge\n\
         ferrum_observability_retained_bytes {retained_bytes}\n\
         # HELP ferrum_observability_max_retained_bytes Configured process-wide retained-byte ceiling shared by all observability sink instances.\n\
         # TYPE ferrum_observability_max_retained_bytes gauge\n\
         ferrum_observability_max_retained_bytes {max_retained_bytes}\n\
         # HELP ferrum_observability_retained_bytes_high_water Peak process-wide observability retention observed since startup.\n\
         # TYPE ferrum_observability_retained_bytes_high_water gauge\n\
         ferrum_observability_retained_bytes_high_water {retained_high_water}\n\
         # HELP ferrum_observability_process_ceiling_rejections_total Sink admissions refused specifically by the process-wide retained-byte ceiling rather than a per-instance budget.\n\
         # TYPE ferrum_observability_process_ceiling_rejections_total counter\n\
         ferrum_observability_process_ceiling_rejections_total {ceiling_rejections}\n\
         # HELP ferrum_observability_batch_materialization_lost_records_total Log entries, spans, and rows discarded because their batch representation could not be materialized under the retained-byte ceiling. Counts records, not reservations.\n\
         # TYPE ferrum_observability_batch_materialization_lost_records_total counter\n\
         ferrum_observability_batch_materialization_lost_records_total {batch_lost_records}\n\
         # HELP ferrum_observability_batch_materialization_losses_total Discard events, each of which lost one or more records.\n\
         # TYPE ferrum_observability_batch_materialization_losses_total counter\n\
         ferrum_observability_batch_materialization_losses_total {batch_loss_events}\n\
         # HELP ferrum_observability_batch_materialization_fallbacks_total Batches delivered complete but in a degraded representation, such as uncompressed because the compressed copy could not be reserved. No record loss.\n\
         # TYPE ferrum_observability_batch_materialization_fallbacks_total counter\n\
         ferrum_observability_batch_materialization_fallbacks_total {batch_fallbacks}\n",
        report.rejected_tasks,
        report.cancelled_tasks,
        report.lost_worker_records,
        lifecycle.counters.timed_out_drains.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::Semaphore;

    use super::*;

    #[tokio::test]
    async fn shutdown_accepts_nested_mirror_work_from_admitted_terminal_task() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        let terminal_started = Arc::new(Notify::new());
        let release_terminal = Arc::new(Notify::new());
        let mirror_finished = Arc::new(AtomicBool::new(false));

        let task_lifecycle = Arc::clone(&lifecycle);
        let task_started = Arc::clone(&terminal_started);
        let task_release = Arc::clone(&release_terminal);
        let task_mirror_finished = Arc::clone(&mirror_finished);
        assert!(lifecycle.spawn(
            TaskAdmission::External,
            DeliveryTaskKind::Terminal,
            async move {
                task_started.notify_one();
                task_release.notified().await;
                assert!(task_lifecycle.spawn(
                    TaskAdmission::Internal,
                    DeliveryTaskKind::Mirror,
                    async move {
                        task_mirror_finished.store(true, Ordering::Release);
                    },
                ));
            },
        ));
        terminal_started.notified().await;

        let shutdown_lifecycle = Arc::clone(&lifecycle);
        let shutdown =
            tokio::spawn(async move { shutdown_lifecycle.shutdown(Duration::from_secs(1)).await });
        while lifecycle.accepting_external_tasks.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        release_terminal.notify_one();

        let report = shutdown.await.expect("shutdown task must join");
        assert!(report.complete());
        assert!(mirror_finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn shutdown_accepts_worker_registered_by_admitted_terminal_task() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        let terminal_started = Arc::new(Notify::new());
        let release_terminal = Arc::new(Notify::new());

        let task_lifecycle = Arc::clone(&lifecycle);
        let task_started = Arc::clone(&terminal_started);
        let task_release = Arc::clone(&release_terminal);
        assert!(lifecycle.spawn(
            TaskAdmission::External,
            DeliveryTaskKind::Terminal,
            async move {
                task_started.notify_one();
                task_release.notified().await;
                let (worker, mut close_rx) = DeliveryWorkerControl::new("terminal_sink", || 0);
                let completion = worker.completion();
                let task = tokio::spawn(async move {
                    let mut completion = completion;
                    if !*close_rx.borrow() {
                        let _ = close_rx.changed().await;
                    }
                    completion.complete();
                });
                worker
                    .install_abort_handle(task.abort_handle())
                    .expect("worker abort handle installs once");
                drop(task);
                task_lifecycle.register_worker(worker);
            },
        ));
        terminal_started.notified().await;

        let shutdown_lifecycle = Arc::clone(&lifecycle);
        let shutdown =
            tokio::spawn(async move { shutdown_lifecycle.shutdown(Duration::from_secs(1)).await });
        while lifecycle.accepting_external_tasks.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        release_terminal.notify_one();

        let report = shutdown.await.expect("shutdown task must join");
        assert!(report.complete());
        assert_eq!(report.lost_worker_records, 0);
    }

    #[tokio::test]
    async fn worker_registered_after_worker_admission_closes_is_aborted_and_accounted() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        assert!(
            lifecycle
                .shutdown(Duration::from_millis(50))
                .await
                .complete()
        );

        let (worker, _close_rx) = DeliveryWorkerControl::new("late_sink", || 3);
        let completion = worker.completion();
        let task = tokio::spawn(async move {
            let _completion = completion;
            std::future::pending::<()>().await;
        });
        worker
            .install_abort_handle(task.abort_handle())
            .expect("worker abort handle installs once");
        drop(task);
        lifecycle.register_worker(Arc::clone(&worker));

        assert!(!worker.accepting());
        assert_eq!(lifecycle.report(true, true).lost_worker_records, 3);
    }

    #[tokio::test]
    async fn shutdown_rejects_new_external_tasks_after_admission_closes() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        let report = lifecycle.shutdown(Duration::from_millis(50)).await;
        assert!(report.complete());
        assert!(
            !lifecycle.spawn(TaskAdmission::External, DeliveryTaskKind::Terminal, async {
            },)
        );
        assert_eq!(
            lifecycle.counters.rejected_terminal.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn task_timeout_aborts_and_accounts_cancelled_delivery() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        assert!(lifecycle.spawn(
            TaskAdmission::External,
            DeliveryTaskKind::Terminal,
            std::future::pending::<()>(),
        ));

        let report = lifecycle.shutdown(Duration::from_millis(10)).await;
        assert!(!report.complete());
        assert!(!report.tasks_drained);
        assert_eq!(report.cancelled_tasks, 1);
        assert_eq!(
            lifecycle.counters.timed_out_drains.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn repeated_shutdown_reuses_the_first_bounded_drain_report() {
        let lifecycle = DeliveryLifecycle::new();
        let first = lifecycle.shutdown(Duration::from_millis(50)).await;
        let second = lifecycle.shutdown(Duration::from_secs(1)).await;

        assert_eq!(second, first);
        assert_eq!(
            lifecycle.counters.timed_out_drains.load(Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn registered_worker_closes_and_finishes_inside_shared_budget() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        let (worker, mut close_rx) = DeliveryWorkerControl::new("test_sink", || 0);
        let completion = worker.completion();
        let task = tokio::spawn(async move {
            let mut completion = completion;
            if !*close_rx.borrow() {
                let _ = close_rx.changed().await;
            }
            completion.complete();
        });
        worker
            .install_abort_handle(task.abort_handle())
            .expect("worker abort handle installs once");
        drop(task);
        lifecycle.register_worker(Arc::clone(&worker));

        let report = lifecycle.shutdown(Duration::from_secs(1)).await;
        assert!(report.complete());
        assert!(worker.is_finished());
        assert_eq!(report.lost_worker_records, 0);
    }

    #[tokio::test]
    async fn worker_timeout_aborts_and_accounts_pending_records() {
        let lifecycle = Arc::new(DeliveryLifecycle::new());
        let (worker, _close_rx) = DeliveryWorkerControl::new("blocked_sink", || 3);
        let completion = worker.completion();
        let task = tokio::spawn(async move {
            let _completion = completion;
            std::future::pending::<()>().await;
        });
        worker
            .install_abort_handle(task.abort_handle())
            .expect("worker abort handle installs once");
        drop(task);
        lifecycle.register_worker(Arc::clone(&worker));

        let report = lifecycle.shutdown(Duration::from_millis(10)).await;
        assert!(!report.complete());
        assert_eq!(report.lost_worker_records, 3);
        assert_eq!(
            lifecycle.counters.timed_out_drains.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn task_budget_rejects_overflow_without_growing_the_registry() {
        let lifecycle = Arc::new(DeliveryLifecycle::with_limits(0, 1, 2));
        // Counting/closable semaphores instead of `Notify`: `notify_one`
        // permits saturate at one and `notify_waiters` only reaches waiters
        // that already registered, so several held tasks lose wakeups.
        let release = Arc::new(Semaphore::new(0));
        let started = Arc::new(Semaphore::new(0));

        for _ in 0..2 {
            let task_release = Arc::clone(&release);
            let task_started = Arc::clone(&started);
            assert!(lifecycle.spawn(
                TaskAdmission::External,
                DeliveryTaskKind::Terminal,
                async move {
                    task_started.add_permits(1);
                    let _ = task_release.acquire().await;
                },
            ));
        }
        started
            .acquire_many(2)
            .await
            .expect("held tasks report started")
            .forget();

        assert_eq!(lifecycle.tasks.len(), 2);
        assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 2);
        assert!(
            !lifecycle.spawn(TaskAdmission::External, DeliveryTaskKind::Terminal, async {
            },)
        );
        assert!(!lifecycle.spawn(TaskAdmission::Internal, DeliveryTaskKind::Mirror, async {},));
        assert!(!lifecycle.spawn(
            TaskAdmission::External,
            DeliveryTaskKind::DeadlineCleanup,
            async {},
        ));
        assert_eq!(lifecycle.tasks.len(), 2);
        assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 2);
        assert_eq!(lifecycle.rejected_task_count(), 3);

        release.close();
        assert!(
            lifecycle
                .wait_for_tasks(Instant::now() + Duration::from_secs(5))
                .await
        );
        assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 0);
        assert!(
            lifecycle.spawn(TaskAdmission::External, DeliveryTaskKind::Terminal, async {
            },)
        );
    }

    /// The count gate alone only samples rejections, so a sustained overflow
    /// would still scale warning lines with attacker-driven traffic. The window
    /// claim is the absolute ceiling; only one caller may hold it at a time.
    #[test]
    fn capacity_warning_window_admits_one_line_per_window() {
        let lifecycle = DeliveryLifecycle::with_limits(0, 1, 1);
        assert!(
            lifecycle.claim_capacity_warning_window(),
            "the first capacity warning must always be emitted"
        );
        for _ in 0..1_000 {
            assert!(
                !lifecycle.claim_capacity_warning_window(),
                "further warnings inside the same window must be suppressed"
            );
        }
    }

    #[test]
    fn no_runtime_rejection_releases_task_permit() {
        let lifecycle = Arc::new(DeliveryLifecycle::with_limits(0, 1, 1));
        assert!(
            !lifecycle.spawn(TaskAdmission::External, DeliveryTaskKind::Terminal, async {
            },),
            "spawn without a Tokio runtime must reject"
        );
        assert_eq!(lifecycle.tasks.len(), 0);
        assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 0);
        assert_eq!(lifecycle.rejected_task_count(), 1);
    }

    #[tokio::test]
    async fn cancel_remaining_releases_task_permits() {
        let lifecycle = Arc::new(DeliveryLifecycle::with_limits(0, 1, 2));
        let release = Arc::new(Semaphore::new(0));
        let started = Arc::new(Semaphore::new(0));
        for _ in 0..2 {
            let task_release = Arc::clone(&release);
            let task_started = Arc::clone(&started);
            assert!(lifecycle.spawn(
                TaskAdmission::External,
                DeliveryTaskKind::Terminal,
                async move {
                    task_started.add_permits(1);
                    let _ = task_release.acquire().await;
                },
            ));
        }
        started
            .acquire_many(2)
            .await
            .expect("held tasks report started")
            .forget();
        assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 2);

        lifecycle.cancel_remaining();
        assert_eq!(lifecycle.tasks.len(), 0);
        assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 0);
        release.close();
    }

    /// Regression for the send-failure/cancel race: the loser of registry removal
    /// must disarm without a second `record_cancelled`, or cancelled counters
    /// can exceed the number of inserted task ids.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancel_spawn_handoff_race_counts_cancelled_at_most_once_per_task() {
        for _ in 0..64 {
            let lifecycle = Arc::new(DeliveryLifecycle::with_limits(0, 1, 64));
            let start_id = lifecycle.next_task_id.load(Ordering::Relaxed);
            let spawner_lifecycle = Arc::clone(&lifecycle);
            let cancel_lifecycle = Arc::clone(&lifecycle);

            let spawner = tokio::spawn(async move {
                for _ in 0..64 {
                    let _ = spawner_lifecycle.spawn(
                        TaskAdmission::External,
                        DeliveryTaskKind::Terminal,
                        std::future::pending::<()>(),
                    );
                }
            });
            let canceller = tokio::spawn(async move {
                for _ in 0..8 {
                    cancel_lifecycle.cancel_remaining();
                    tokio::task::yield_now().await;
                }
            });

            spawner.await.expect("spawner must join");
            canceller.await.expect("canceller must join");
            lifecycle.cancel_remaining();

            let ids_issued = lifecycle
                .next_task_id
                .load(Ordering::Relaxed)
                .saturating_sub(start_id);
            let cancelled = lifecycle
                .counters
                .cancelled_terminal
                .load(Ordering::Relaxed);
            assert_eq!(lifecycle.tasks.len(), 0);
            assert_eq!(lifecycle.admitted_tasks.load(Ordering::Acquire), 0);
            assert!(
                cancelled <= ids_issued,
                "cancelled={cancelled} must not exceed inserted task ids={ids_issued}"
            );
        }
    }

    /// Exact-generation context must outlive slot replacement.
    ///
    /// `DeliverySlot::shutdown` drains one captured lifecycle while
    /// `begin_cycle` may install a fresh open generation before that drain
    /// finishes. Hard-abort classification for tasks admitted on A must read
    /// A's `cancelling_tasks`, not the slot's current B.
    #[tokio::test]
    async fn delivery_task_context_tracks_admitted_lifecycle_across_slot_replacement() {
        let slot = DeliverySlot::new(0);
        let lifecycle_a = slot.snapshot();
        let generation_a = lifecycle_a.generation;

        let captured = Arc::new(std::sync::OnceLock::new());
        let task_started = Arc::new(Notify::new());

        let factory_captured = Arc::clone(&captured);
        let factory_started = Arc::clone(&task_started);
        assert!(
            slot.spawn_terminal_with_context(move |ctx| {
                // Capture through the spawn factory so a double-snapshot
                // implementation (context from one load, admission on another)
                // cannot silently pass a hand-built context assertion.
                let _ = factory_captured.set(ctx);
                async move {
                    factory_started.notify_one();
                    std::future::pending::<()>().await;
                }
            }),
            "admission against open lifecycle A must succeed"
        );
        task_started.notified().await;

        let ctx = captured
            .get()
            .expect("context-bearing spawn must install the admission context")
            .clone();
        assert!(
            !ctx.is_aborting_at_deadline(),
            "open lifecycle A must not report deadline abort before cancel_remaining"
        );

        // Real slot replacement path: draining A lets begin_cycle install B.
        lifecycle_a
            .state
            .store(GENERATION_DRAINING, Ordering::Release);
        let generation_b = slot.begin_cycle();
        assert_ne!(
            generation_b, generation_a,
            "begin_cycle must install a fresh generation while A drains"
        );
        let lifecycle_b = slot.snapshot();
        assert_eq!(lifecycle_b.generation, generation_b);
        assert!(
            !lifecycle_b.cancelling_tasks.load(Ordering::Acquire),
            "fresh generation B must not be cancelling"
        );

        // Hard-cancel the drained generation that still owns the admitted task.
        lifecycle_a.cancel_remaining();
        assert!(
            ctx.is_aborting_at_deadline(),
            "captured context must still observe A's deadline abort after slot replacement"
        );
        assert!(
            !lifecycle_b.cancelling_tasks.load(Ordering::Acquire),
            "slot current (B) must remain non-aborting while A cancels"
        );
        assert!(
            !slot.snapshot().cancelling_tasks.load(Ordering::Acquire),
            "current-generation sample must not be used for A's abort classification"
        );
    }
}
