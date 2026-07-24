//! Structured ownership for deferred observability delivery.
//!
//! Request drain and observability drain are deliberately separate phases.
//! Streaming terminal hooks and mirror summaries may still be running after
//! the last proxy body releases its request guard. Once request drain is
//! complete, [`shutdown`] closes external task admission, waits for already
//! admitted terminal work (including internally spawned mirror work), then
//! closes and awaits every registered queue worker under one absolute budget.
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
/// the open generation with the configured sharding. If an earlier non-serving
/// caller already touched the registry, the override is recorded for the next
/// generation without replacing an open lifecycle that may own live workers.
///
/// Tests and non-serving callers that reach the registry first use the same
/// auto-sized fallback as other concurrent runtime maps.
pub fn initialize(pool_shard_override: usize) {
    LIFECYCLE
        .get_or_init(|| DeliverySlot::new(pool_shard_override))
        .initialize(pool_shard_override);
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
    next_generation: AtomicU64,
}

impl DeliverySlot {
    pub fn new(pool_shard_override: usize) -> Self {
        Self {
            current: ArcSwap::from_pointee(DeliveryLifecycle::with_pool_shard_amount(
                pool_shard_override,
                1,
            )),
            pool_shard_override: AtomicUsize::new(pool_shard_override),
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
    pub fn initialize(&self, pool_shard_override: usize) {
        self.pool_shard_override
            .store(pool_shard_override, Ordering::Release);
        if self.current.load().state() == GENERATION_OPEN {
            return;
        }
        self.begin_new_cycle();
    }

    /// Install a fresh generation, retrying if a concurrent caller wins.
    ///
    /// The swap is a compare-and-swap against the exact generation this caller
    /// observed, so two concurrent cycles cannot both replace it and drop one
    /// of the installed generations on the floor.
    fn begin_new_cycle(&self) -> u64 {
        loop {
            let current = self.current.load_full();
            if let Some(generation) = self.try_install_generation(&current) {
                return generation;
            }
        }
    }

    /// Swap a fresh generation in for `observed`, or fail if it already moved.
    fn try_install_generation(&self, observed: &Arc<DeliveryLifecycle>) -> Option<u64> {
        let next = self.new_generation();
        let generation = next.generation;
        let previous = self.current.compare_and_swap(observed, next);
        Arc::ptr_eq(observed, &*previous).then_some(generation)
    }

    fn new_generation(&self) -> Arc<DeliveryLifecycle> {
        Arc::new(DeliveryLifecycle::with_pool_shard_amount(
            self.pool_shard_override.load(Ordering::Acquire),
            self.next_generation.fetch_add(1, Ordering::Relaxed),
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

struct DeliveryLifecycle {
    generation: u64,
    state: AtomicU8,
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
        Self::with_pool_shard_amount(0, 1)
    }

    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    fn with_pool_shard_amount(pool_shard_override: usize, generation: u64) -> Self {
        Self {
            generation,
            state: AtomicU8::new(GENERATION_OPEN),
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

    fn spawn<F>(
        self: &Arc<Self>,
        admission: TaskAdmission,
        kind: DeliveryTaskKind,
        future: F,
    ) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
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
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.counters.record_rejected(kind);
            return false;
        };

        let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let lifecycle = Arc::clone(self);
        let task = handle.spawn(async move {
            if start_rx.await.is_err() {
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
                self.counters.record_cancelled(kind);
            }
            return false;
        }
        if start_tx.send(()).is_err() {
            self.finish_task(task_id);
            self.counters.record_cancelled(kind);
            return false;
        }
        true
    }

    fn accepts(&self, admission: TaskAdmission) -> bool {
        match admission {
            TaskAdmission::External => self.accepting_external_tasks.load(Ordering::Acquire),
            TaskAdmission::Internal => self.accepting_internal_tasks.load(Ordering::Acquire),
        }
    }

    fn finish_task(&self, task_id: u64) {
        self.tasks.remove(&task_id);
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
        let mut cached_report = self.shutdown_report.lock().await;
        if let Some(report) = *cached_report {
            return report;
        }

        // Publish the draining state before closing admission so a serving
        // cycle that starts during this drain installs a fresh generation
        // instead of enqueueing into the one being closed here.
        self.state.store(GENERATION_DRAINING, Ordering::Release);
        self.accepting_external_tasks
            .store(false, Ordering::Release);
        let deadline = Instant::now() + timeout;

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
            rejected_tasks: self
                .counters
                .rejected_terminal
                .load(Ordering::Relaxed)
                .saturating_add(self.counters.rejected_mirror.load(Ordering::Relaxed))
                .saturating_add(
                    self.counters
                        .rejected_deadline_cleanup
                        .load(Ordering::Relaxed),
                ),
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
         # HELP ferrum_observability_delivery_active_workers Queue workers currently owned by the shutdown lifecycle.\n\
         # TYPE ferrum_observability_delivery_active_workers gauge\n\
         ferrum_observability_delivery_active_workers {active_workers}\n\
         # HELP ferrum_observability_delivery_rejected_tasks_total Delivery tasks rejected after lifecycle admission closed or without a runtime.\n\
         # TYPE ferrum_observability_delivery_rejected_tasks_total counter\n\
         ferrum_observability_delivery_rejected_tasks_total {}\n\
         # HELP ferrum_observability_delivery_cancelled_tasks_total Delivery tasks cancelled when the shutdown budget expired.\n\
         # TYPE ferrum_observability_delivery_cancelled_tasks_total counter\n\
         ferrum_observability_delivery_cancelled_tasks_total {}\n\
         # HELP ferrum_observability_delivery_lost_worker_records_total Queued records abandoned when worker drain exceeded the shutdown budget.\n\
         # TYPE ferrum_observability_delivery_lost_worker_records_total counter\n\
         ferrum_observability_delivery_lost_worker_records_total {}\n\
         # HELP ferrum_observability_delivery_drain_timeouts_total Observability shutdown drains that exhausted their shared deadline.\n\
         # TYPE ferrum_observability_delivery_drain_timeouts_total counter\n\
         ferrum_observability_delivery_drain_timeouts_total {}\n",
        report.rejected_tasks,
        report.cancelled_tasks,
        report.lost_worker_records,
        lifecycle.counters.timed_out_drains.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

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
}
