use std::future::Future;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::observability_delivery::DeliveryWorkerControl;

const DROP_WARN_EVERY: u64 = 100;
/// Hard ceiling for an admitted batch size across shared logging sinks.
///
/// Admission (`validate_batch_config` / `build_batch_config`) rejects values
/// outside `1..=MAX_BATCH_SIZE`. [`BatchingLogger::spawn`] still clamps as a
/// defense for programmatic `BatchConfig` construction.
pub const MAX_BATCH_SIZE: usize = 10_000;
/// Hard ceiling for an admitted channel capacity across shared logging sinks.
pub const MAX_BUFFER_CAPACITY: usize = 1_000_000;
/// Hard ceiling for admitted batch flush intervals.
///
/// Besides bounding operator mistakes, this keeps Tokio interval arithmetic
/// safely inside every supported platform's `Instant` range.
pub const MAX_BATCH_FLUSH_INTERVAL_MS: u64 = 600_000;
/// Hard ceiling for admitted `max_retries` (retries after the initial attempt).
pub const MAX_BATCH_RETRIES: u64 = 10;
/// Hard ceiling for admitted `retry_delay_ms` across shared logging sinks.
pub const MAX_BATCH_RETRY_DELAY_MS: u64 = 60_000;
const MAX_TOKIO_SLEEP_MS: u64 = i64::MAX as u64;
static JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);
static JITTER_SEED: LazyLock<u64> = LazyLock::new(|| {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ u64::from(std::process::id()) ^ (&JITTER_COUNTER as *const AtomicU64 as usize as u64)
});

/// Strategy for retrying a failed flush. The flush closure owns its own
/// status-code-aware logic (e.g. "don't retry 401/403, do retry 408/429") —
/// `BatchingLogger` enforces the attempt count and the inter-attempt delay.
///
/// The delay grows exponentially from `delay` (doubling each attempt), capped
/// at `max_delay`. When `jitter` is set, the computed delay is replaced with a
/// uniformly random value in `[0, computed_delay]` (full jitter) to avoid a
/// thundering-herd retry storm against a struggling backend. Callers that want
/// a constant delay set `max_delay == delay` and `jitter = false`; use
/// [`RetryPolicy::fixed`] for that. See finding #77.
#[derive(Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    /// Initial (and, for fixed policies, constant) inter-attempt delay.
    pub delay: Duration,
    /// Upper bound for the exponential backoff. Must be `>= delay`; if it is
    /// smaller it is treated as equal to `delay` (constant delay).
    pub max_delay: Duration,
    /// When true, apply full jitter to each backoff delay.
    pub jitter: bool,
}

impl RetryPolicy {
    /// A constant inter-attempt delay with no exponential growth and no jitter.
    /// This preserves the historical `RetryPolicy { max_attempts, delay }`
    /// behavior for callers that do not want backoff.
    pub fn fixed(max_attempts: u32, delay: Duration) -> Self {
        Self {
            max_attempts,
            delay,
            max_delay: delay,
            jitter: false,
        }
    }

    /// Compute the delay to sleep AFTER a failed attempt `attempt`
    /// (1-based: the delay following the first failure uses `attempt == 1`).
    ///
    /// Exponential backoff: `delay * 2^(attempt - 1)`, capped at `max_delay`.
    /// With `jitter`, returns a uniform random value in `[0, capped]` (full
    /// jitter). The jitter uses a lightweight counter-based PRNG — it does not
    /// need cryptographic quality — mirroring `crate::retry::retry_delay`.
    pub(crate) fn backoff_delay(&self, attempt: u32) -> Duration {
        let base_ms = self.delay.as_millis().min(u128::from(MAX_TOKIO_SLEEP_MS)) as u64;
        let cap_ms = self
            .max_delay
            .as_millis()
            .min(u128::from(MAX_TOKIO_SLEEP_MS))
            .max(u128::from(base_ms)) as u64;

        // delay * 2^(attempt-1), saturating, then capped at max_delay.
        let shift = attempt.saturating_sub(1).min(63);
        let grown = base_ms.saturating_mul(1u64 << shift);
        let capped = grown.min(cap_ms);

        let final_ms = if self.jitter && capped > 0 {
            let counter = JITTER_COUNTER
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(*JITTER_SEED);
            // LCG-style hash to spread values (same constants as crate::retry).
            let hash = counter
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Full jitter: uniform in [0, capped].
            hash % capped.saturating_add(1)
        } else {
            capped
        };

        Duration::from_millis(final_ms)
    }
}

#[derive(Clone, Copy)]
pub struct BatchConfig {
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub buffer_capacity: usize,
    pub retry: RetryPolicy,
    pub plugin_name: &'static str,
}

pub struct BatchingLogger<T: Send + 'static> {
    /// Pre-publication dormancy gate. [`Self::commit`] releases the flush
    /// worker; dropping this sender without commit makes the worker exit with
    /// no flush/network side effects.
    commit_tx: watch::Sender<bool>,
    committed: AtomicBool,
    sender: Option<mpsc::Sender<T>>,
    worker: Arc<DeliveryWorkerControl>,
    plugin_name: &'static str,
    dropped_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
    outstanding_count: Arc<AtomicUsize>,
    buffer_capacity: usize,
    hooks: LoggerHooks<T>,
}

/// Cloneable, lock-free admission surface shared with a [`BatchingLogger`].
///
/// Hot-path callers can hold this handle (for example behind
/// `ArcSwapOption`) without locking the worker owner. Closing admission is
/// the caller's responsibility: drop every handle, then
/// [`BatchingLogger::close_and_await`] the lifecycle owner.
#[derive(Clone)]
pub struct BatchingLoggerHandle<T: Send + 'static> {
    sender: mpsc::Sender<T>,
    worker: Arc<DeliveryWorkerControl>,
    plugin_name: &'static str,
    dropped_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
    outstanding_count: Arc<AtomicUsize>,
    buffer_capacity: usize,
    hooks: LoggerHooks<T>,
}

/// An atomically reserved queue slot for a record that will be constructed
/// later. Dropping an unused permit releases both the channel slot and the
/// logger's depth accounting.
pub struct BatchingLoggerPermit<T: Send + 'static> {
    permit: Option<mpsc::OwnedPermit<T>>,
    queue_depth: Arc<AtomicUsize>,
    outstanding_count: Arc<AtomicUsize>,
}

impl<T: Send + 'static> BatchingLoggerPermit<T> {
    pub fn send(mut self, item: T) {
        if let Some(permit) = self.permit.take() {
            permit.send(item);
        }
    }
}

impl<T: Send + 'static> Drop for BatchingLoggerPermit<T> {
    fn drop(&mut self) {
        if self.permit.is_some() {
            decrement_queue_depth(&self.queue_depth);
            decrement_queue_depth(&self.outstanding_count);
        }
    }
}

type FailedBatchHook<T> = Arc<dyn Fn(Vec<T>, String) + Send + Sync>;
type OverflowHook<T> = Arc<dyn Fn(T, &'static str) + Send + Sync>;
type HighWaterHook = Arc<dyn Fn(usize, usize) + Send + Sync>;

pub struct LoggerHooks<T: Send + 'static> {
    pub on_failed_batch: Option<FailedBatchHook<T>>,
    pub on_overflow: Option<OverflowHook<T>>,
    /// Called whenever the observed queue depth is above the configured
    /// high-water mark. This hook is independent of `on_overflow`.
    pub on_high_water: Option<HighWaterHook>,
    pub high_watermark_percent: u8,
}

impl<T: Send + 'static> Clone for LoggerHooks<T> {
    fn clone(&self) -> Self {
        Self {
            on_failed_batch: self.on_failed_batch.clone(),
            on_overflow: self.on_overflow.clone(),
            on_high_water: self.on_high_water.clone(),
            high_watermark_percent: self.high_watermark_percent,
        }
    }
}

impl<T: Send + 'static> Default for LoggerHooks<T> {
    fn default() -> Self {
        Self {
            on_failed_batch: None,
            on_overflow: None,
            on_high_water: None,
            high_watermark_percent: 80,
        }
    }
}

impl<T: Send + 'static> BatchingLogger<T> {
    /// Spawn the flush loop on the current runtime and return a handle that
    /// plugins hold in their `Arc<dyn Plugin>` state.
    ///
    /// The worker remains dormant until [`Self::commit`] (plugin-cache
    /// publication). Dropping an uncommitted logger cancels the worker with no
    /// flush side effects.
    ///
    /// `flush` is called with a non-empty `Vec<T>` whenever the batch is full
    /// OR the flush interval has elapsed with at least one buffered entry.
    ///
    /// If `flush` returns `Err`, the retry policy is applied. After the final
    /// attempt fails, the batch is dropped and a warning is logged.
    pub fn spawn<F, Fut>(cfg: BatchConfig, flush: F) -> Self
    where
        T: Clone,
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        Self::spawn_with_hooks(cfg, LoggerHooks::default(), flush)
    }

    /// Variant of [`Self::spawn`] for durable sinks that need to recover
    /// failed batches or overflow entries instead of dropping them.
    pub fn spawn_with_hooks<F, Fut>(cfg: BatchConfig, hooks: LoggerHooks<T>, flush: F) -> Self
    where
        T: Clone,
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let (commit_tx, commit_rx) = watch::channel(false);
        Self::spawn_with_hooks_on_commit_gate(cfg, hooks, commit_tx, commit_rx, flush)
    }

    /// Like [`Self::spawn_with_hooks`], but shares an external commit gate so
    /// sibling workers (spool replay, snapshot) wake on the same publication
    /// signal.
    pub fn spawn_with_hooks_on_commit_gate<F, Fut>(
        cfg: BatchConfig,
        hooks: LoggerHooks<T>,
        commit_tx: watch::Sender<bool>,
        commit_rx: watch::Receiver<bool>,
        flush: F,
    ) -> Self
    where
        T: Clone,
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let batch_size = cfg.batch_size.clamp(1, MAX_BATCH_SIZE);
        let buffer_capacity = cfg.buffer_capacity.clamp(1, MAX_BUFFER_CAPACITY);
        let flush_interval = if cfg.flush_interval.is_zero() {
            debug!(
                plugin = cfg.plugin_name,
                "{}: zero batch flush interval requested; clamping to 1ms", cfg.plugin_name,
            );
            Duration::from_millis(1)
        } else {
            cfg.flush_interval
        };
        let cfg = BatchConfig {
            batch_size,
            buffer_capacity,
            flush_interval,
            ..cfg
        };
        let plugin_name = cfg.plugin_name;
        let buffer_capacity = cfg.buffer_capacity;
        let (sender, receiver) = mpsc::channel(cfg.buffer_capacity);
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let worker_queue_depth = Arc::clone(&queue_depth);
        let outstanding_count = Arc::new(AtomicUsize::new(0));
        let worker_outstanding_count = Arc::clone(&outstanding_count);
        let pending_count = Arc::clone(&outstanding_count);
        let on_failed_batch = hooks.on_failed_batch.clone();
        let (worker_control, close_rx) = DeliveryWorkerControl::new(plugin_name, move || {
            pending_count.load(Ordering::Relaxed) as u64
        });
        let completion = worker_control.completion();
        let worker_drain_control = Arc::clone(&worker_control);
        let worker = tokio::spawn(async move {
            let mut completion = completion;
            if !wait_until_committed_or_closed(commit_rx, close_rx.clone()).await {
                // Staged generation was dropped/rejected before publication.
                // Discard the receiver without entering the flush loop so no
                // network or fallback side effects can run.
                drop(receiver);
                completion.complete();
                return;
            }
            run_flush_loop_with_hooks(
                cfg,
                receiver,
                FlushAccounting {
                    queue_depth: worker_queue_depth,
                    outstanding_count: worker_outstanding_count,
                },
                worker_drain_control,
                close_rx,
                flush,
                on_failed_batch,
            )
            .await;
            completion.complete();
        });
        if let Err(error) = worker_control.install_abort_handle(worker.abort_handle()) {
            warn!(plugin = plugin_name, "{plugin_name}: {error}");
            worker.abort();
        }
        drop(worker);
        crate::observability_delivery::register_worker(Arc::clone(&worker_control));

        Self {
            commit_tx,
            committed: AtomicBool::new(false),
            sender: Some(sender),
            worker: worker_control,
            plugin_name,
            dropped_count: Arc::new(AtomicU64::new(0)),
            queue_depth,
            outstanding_count,
            buffer_capacity,
            hooks,
        }
    }

    /// Release the pre-publication dormancy gate. Idempotent and infallible.
    pub fn commit(&self) {
        if self.committed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.commit_tx.send(true);
    }

    /// Whether [`Self::commit`] has already released this worker.
    #[allow(dead_code)] // External lifecycle tests observe pre/post-publication state.
    pub fn is_committed(&self) -> bool {
        self.committed.load(Ordering::Acquire)
    }

    /// Borrow the commit sender so sibling staged workers can subscribe to the
    /// same publication signal.
    pub fn commit_sender(&self) -> &watch::Sender<bool> {
        &self.commit_tx
    }

    /// Cloneable admission handle sharing this logger's channel. Returns
    /// `None` when admission was already closed on the lifecycle owner.
    pub fn handle(&self) -> Option<BatchingLoggerHandle<T>> {
        self.sender.as_ref().map(|sender| BatchingLoggerHandle {
            sender: sender.clone(),
            worker: Arc::clone(&self.worker),
            plugin_name: self.plugin_name,
            dropped_count: Arc::clone(&self.dropped_count),
            queue_depth: Arc::clone(&self.queue_depth),
            outstanding_count: Arc::clone(&self.outstanding_count),
            buffer_capacity: self.buffer_capacity,
            hooks: self.hooks.clone(),
        })
    }

    /// Close admission and await the flush worker so pending Ferrum-side
    /// batches finish before a downstream sink (for example librdkafka) is
    /// flushed. Exact-once: subsequent calls are no-ops.
    ///
    /// Uncommitted loggers abort instead of draining so a rejected staged
    /// generation cannot flush as a side effect of teardown.
    ///
    /// Published [`BatchingLoggerHandle`] clones may remain alive: worker
    /// admission closes first, then the receiver closes after in-progress
    /// enqueue attempts release their admission guards.
    pub async fn close_and_await(&mut self) -> bool {
        if !self.committed.load(Ordering::Acquire) {
            self.close_and_abort();
            return true;
        }
        drop(self.sender.take());
        self.worker.close_admission();
        self.worker.wait_finished().await
    }

    /// Close admission and cancel the flush worker when no asynchronous drain
    /// can be awaited. This is intentionally lossy; lifecycle owners must
    /// account the abandoned work before calling it.
    pub fn close_and_abort(&mut self) {
        drop(self.sender.take());
        self.worker.abort();
    }

    /// Non-blocking send. On full buffer, logs a warning once per N drops and
    /// silently drops intermediate entries so the hot path never blocks.
    pub fn try_send(&self, item: T) -> bool {
        let Some(_admission) = self.worker.try_admit() else {
            record_drop(
                &self.dropped_count,
                self.plugin_name,
                "worker unavailable during shutdown",
            );
            return false;
        };
        self.outstanding_count.fetch_add(1, Ordering::Relaxed);
        let Some(sender) = self.sender.as_ref() else {
            decrement_queue_depth(&self.outstanding_count);
            record_drop(
                &self.dropped_count,
                self.plugin_name,
                "worker unavailable during shutdown",
            );
            return false;
        };
        let depth = self.queue_depth.load(Ordering::Relaxed);
        if is_high_water(
            depth,
            self.buffer_capacity,
            self.hooks.high_watermark_percent,
        ) {
            if let Some(on_high_water) = self.hooks.on_high_water.as_ref() {
                on_high_water(depth, self.buffer_capacity);
            }
            if let Some(on_overflow) = self.hooks.on_overflow.as_ref() {
                decrement_queue_depth(&self.outstanding_count);
                on_overflow(item, "queue high water");
                return false;
            }
        }

        self.queue_depth.fetch_add(1, Ordering::Relaxed);
        match sender.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(item)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(&self.dropped_count, self.plugin_name, "buffer full");
                if let Some(on_overflow) = self.hooks.on_overflow.as_ref() {
                    on_overflow(item, "buffer full");
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(
                    &self.dropped_count,
                    self.plugin_name,
                    "worker unavailable during shutdown",
                );
                false
            }
        }
    }

    /// Atomically reserve one bounded-channel slot without constructing the
    /// item yet. This supports fail-closed plugins that must guarantee enqueue
    /// capacity before a response becomes immutable, while filling the record
    /// only after later validators determine the final status and body.
    pub fn try_reserve(&self) -> Option<BatchingLoggerPermit<T>> {
        let Some(_admission) = self.worker.try_admit() else {
            record_drop(
                &self.dropped_count,
                self.plugin_name,
                "worker unavailable while reserving a commit slot",
            );
            return None;
        };
        let Some(sender) = self.sender.as_ref() else {
            record_drop(
                &self.dropped_count,
                self.plugin_name,
                "worker unavailable while reserving a commit slot",
            );
            return None;
        };
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
        self.outstanding_count.fetch_add(1, Ordering::Relaxed);
        match sender.clone().try_reserve_owned() {
            Ok(permit) => Some(BatchingLoggerPermit {
                permit: Some(permit),
                queue_depth: Arc::clone(&self.queue_depth),
                outstanding_count: Arc::clone(&self.outstanding_count),
            }),
            Err(mpsc::error::TrySendError::Full(_sender)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(
                    &self.dropped_count,
                    self.plugin_name,
                    "buffer full while reserving a commit slot",
                );
                None
            }
            Err(mpsc::error::TrySendError::Closed(_sender)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(
                    &self.dropped_count,
                    self.plugin_name,
                    "worker unavailable while reserving a commit slot",
                );
                None
            }
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }

    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }
}

impl<T: Send + 'static> Drop for BatchingLogger<T> {
    fn drop(&mut self) {
        drop(self.sender.take());
        if self.committed.load(Ordering::Acquire) {
            // Reload retirement cannot await from Drop, so close the worker
            // and leave its completion ownership with the process registry.
            self.worker.close_admission();
        } else {
            // A rejected staged generation must never flush externally.
            self.worker.abort();
        }
    }
}

/// Lifecycle owner that stages a [`BatchingLogger`] from
/// [`crate::plugins::Plugin::start_background_tasks`] and releases it from
/// [`crate::plugins::Plugin::commit_background_tasks`] after PluginCache
/// atomically installs the generation.
///
/// Offline `ferrum-edge validate` and Admin admission construct plugins without
/// a Tokio runtime and without calling `start_background_tasks`, so validation
/// stays runtime-free and leaves no flush worker behind. Staged workers stay
/// dormant until [`Self::commit`]; dropping an uncommitted logger cancels them
/// with no flush side effects.
pub struct DeferredBatchingLogger<T: Send + 'static> {
    logger: OnceLock<BatchingLogger<T>>,
    start_lock: Mutex<()>,
}

impl<T: Send + 'static> Default for DeferredBatchingLogger<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + 'static> DeferredBatchingLogger<T> {
    pub fn new() -> Self {
        Self {
            logger: OnceLock::new(),
            start_lock: Mutex::new(()),
        }
    }

    #[allow(dead_code)] // External lifecycle tests observe staged activation.
    pub fn is_started(&self) -> bool {
        self.logger.get().is_some()
    }

    #[allow(dead_code)] // Test/support consumers inspect the staged logger directly.
    pub fn get(&self) -> Option<&BatchingLogger<T>> {
        self.logger.get()
    }

    /// Idempotent staging. Requires a Tokio runtime. The flush worker stays
    /// dormant until [`Self::commit`] after cache publication.
    pub fn start_with_hooks<F, Fut>(
        &self,
        plugin_name: &'static str,
        cfg: BatchConfig,
        hooks: LoggerHooks<T>,
        flush: F,
    ) -> Result<(), String>
    where
        T: Clone,
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        if self.logger.get().is_some() {
            return Ok(());
        }
        let _guard = self.start_lock.lock().map_err(|_| {
            format!("{plugin_name}: start lock poisoned; refusing to start batching worker")
        })?;
        if self.logger.get().is_some() {
            return Ok(());
        }
        let _runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            format!("{plugin_name}: start_background_tasks requires a Tokio runtime")
        })?;
        let logger = BatchingLogger::spawn_with_hooks(cfg, hooks, flush);
        match self.logger.set(logger) {
            Ok(()) => Ok(()),
            Err(mut logger) => {
                // Slot already occupied (should be unreachable under start_lock).
                // Abort the just-spawned worker so it cannot outlive this failure.
                logger.close_and_abort();
                Err(format!(
                    "{plugin_name}: batching worker already started; refusing duplicate activation"
                ))
            }
        }
    }

    /// Variant of [`Self::start_with_hooks`] with default logger hooks.
    pub fn start<F, Fut>(
        &self,
        plugin_name: &'static str,
        cfg: BatchConfig,
        flush: F,
    ) -> Result<(), String>
    where
        T: Clone,
        F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        self.start_with_hooks(plugin_name, cfg, LoggerHooks::default(), flush)
    }

    /// Release the staged flush worker after PluginCache publication.
    /// Idempotent; no-op when [`Self::start`] has not run.
    pub fn commit(&self) {
        if let Some(logger) = self.logger.get() {
            logger.commit();
        }
    }

    /// Whether the staged logger has been released by [`Self::commit`].
    #[allow(dead_code)] // External lifecycle tests observe pre/post-publication state.
    pub fn is_committed(&self) -> bool {
        self.logger.get().is_some_and(BatchingLogger::is_committed)
    }

    /// Non-blocking send. Returns `false` when the worker has not started yet
    /// or the underlying logger drops the entry. Queued items stay buffered
    /// until [`Self::commit`] releases the flush loop.
    pub fn try_send(&self, item: T) -> bool {
        match self.logger.get() {
            Some(logger) => logger.try_send(item),
            None => false,
        }
    }

    /// Reserve a queue slot when the worker is staged. Returns `None` when
    /// background staging has not run or the buffer is full/closed.
    pub fn try_reserve(&self) -> Option<BatchingLoggerPermit<T>> {
        self.logger.get().and_then(BatchingLogger::try_reserve)
    }
}

impl<T: Send + 'static> BatchingLoggerHandle<T> {
    /// Non-blocking send. On full buffer, logs a warning once per N drops and
    /// silently drops intermediate entries so the hot path never blocks.
    pub fn try_send(&self, item: T) -> bool {
        let Some(_admission) = self.worker.try_admit() else {
            record_drop(
                &self.dropped_count,
                self.plugin_name,
                "worker unavailable during shutdown",
            );
            return false;
        };
        self.outstanding_count.fetch_add(1, Ordering::Relaxed);
        let depth = self.queue_depth.load(Ordering::Relaxed);
        if is_high_water(
            depth,
            self.buffer_capacity,
            self.hooks.high_watermark_percent,
        ) {
            if let Some(on_high_water) = self.hooks.on_high_water.as_ref() {
                on_high_water(depth, self.buffer_capacity);
            }
            if let Some(on_overflow) = self.hooks.on_overflow.as_ref() {
                decrement_queue_depth(&self.outstanding_count);
                on_overflow(item, "queue high water");
                return false;
            }
        }

        self.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(item)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(&self.dropped_count, self.plugin_name, "buffer full");
                if let Some(on_overflow) = self.hooks.on_overflow.as_ref() {
                    on_overflow(item, "buffer full");
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(
                    &self.dropped_count,
                    self.plugin_name,
                    "worker unavailable during shutdown",
                );
                false
            }
        }
    }

    /// Atomically reserve one bounded-channel slot without constructing the
    /// item yet.
    pub fn try_reserve(&self) -> Option<BatchingLoggerPermit<T>> {
        let Some(_admission) = self.worker.try_admit() else {
            record_drop(
                &self.dropped_count,
                self.plugin_name,
                "worker unavailable while reserving a commit slot",
            );
            return None;
        };
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
        self.outstanding_count.fetch_add(1, Ordering::Relaxed);
        match self.sender.clone().try_reserve_owned() {
            Ok(permit) => Some(BatchingLoggerPermit {
                permit: Some(permit),
                queue_depth: Arc::clone(&self.queue_depth),
                outstanding_count: Arc::clone(&self.outstanding_count),
            }),
            Err(mpsc::error::TrySendError::Full(_sender)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(
                    &self.dropped_count,
                    self.plugin_name,
                    "buffer full while reserving a commit slot",
                );
                None
            }
            Err(mpsc::error::TrySendError::Closed(_sender)) => {
                decrement_queue_depth(&self.queue_depth);
                decrement_queue_depth(&self.outstanding_count);
                record_drop(
                    &self.dropped_count,
                    self.plugin_name,
                    "worker unavailable while reserving a commit slot",
                );
                None
            }
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }
}

fn is_high_water(depth: usize, buffer_capacity: usize, high_watermark_percent: u8) -> bool {
    depth.saturating_mul(100)
        >= buffer_capacity.saturating_mul(high_watermark_percent.max(1) as usize)
}

fn record_drop(dropped_count: &AtomicU64, plugin_name: &'static str, reason: &str) {
    let dropped = dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
    if dropped == 1 || dropped.is_multiple_of(DROP_WARN_EVERY) {
        warn!(
            plugin = plugin_name,
            "{}: dropping queued log entry because {} ({} dropped total; logging every {} drops)",
            plugin_name,
            reason,
            dropped,
            DROP_WARN_EVERY,
        );
    }
}

/// Wait until the owning cache generation is committed, or exit when the
/// staged generation is dropped without publication.
pub async fn wait_until_committed(mut commit_rx: watch::Receiver<bool>) -> bool {
    if *commit_rx.borrow() {
        return true;
    }
    while commit_rx.changed().await.is_ok() {
        if *commit_rx.borrow() {
            return true;
        }
    }
    false
}

pub async fn wait_until_committed_or_closed(
    mut commit_rx: watch::Receiver<bool>,
    mut close_rx: watch::Receiver<bool>,
) -> bool {
    loop {
        if *commit_rx.borrow() {
            return true;
        }
        if *close_rx.borrow() {
            return false;
        }
        tokio::select! {
            biased;
            changed = commit_rx.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
            changed = close_rx.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
        }
    }
}

struct FlushAccounting {
    queue_depth: Arc<AtomicUsize>,
    outstanding_count: Arc<AtomicUsize>,
}

async fn run_flush_loop_with_hooks<T, F, Fut>(
    cfg: BatchConfig,
    mut receiver: mpsc::Receiver<T>,
    accounting: FlushAccounting,
    worker: Arc<DeliveryWorkerControl>,
    mut close_rx: watch::Receiver<bool>,
    flush: F,
    on_failed_batch: Option<FailedBatchHook<T>>,
) where
    T: Send + Clone + 'static,
    F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    let mut buffer = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    let mut closing = *close_rx.borrow();
    if closing {
        worker.wait_for_admissions().await;
        receiver.close();
    }
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = close_rx.changed(), if !closing => {
                closing = true;
                worker.wait_for_admissions().await;
                receiver.close();
            }

            item = receiver.recv() => {
                match item {
                    Some(item) => {
                        decrement_queue_depth(&accounting.queue_depth);
                        buffer.push(item);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            let batch_len = batch.len();
                            flush_with_retry(&cfg, &flush, batch, on_failed_batch.as_ref()).await;
                            decrement_outstanding_by(&accounting.outstanding_count, batch_len);
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            let batch_len = batch.len();
                            flush_with_retry(&cfg, &flush, batch, on_failed_batch.as_ref()).await;
                            decrement_outstanding_by(&accounting.outstanding_count, batch_len);
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    let batch_len = batch.len();
                    flush_with_retry(&cfg, &flush, batch, on_failed_batch.as_ref()).await;
                    decrement_outstanding_by(&accounting.outstanding_count, batch_len);
                }
            }

        }
    }
}

fn decrement_queue_depth(queue_depth: &AtomicUsize) {
    let _ = queue_depth.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

fn decrement_outstanding_by(outstanding_count: &AtomicUsize, count: usize) {
    let _ = outstanding_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(count))
    });
}

async fn flush_with_retry<T, F, Fut>(
    cfg: &BatchConfig,
    flush: &F,
    batch: Vec<T>,
    on_failed_batch: Option<&FailedBatchHook<T>>,
) where
    T: Send + Clone + 'static,
    F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    let attempts = cfg.retry.max_attempts.max(1);
    let entry_count = batch.len();
    let mut final_batch = Some(batch);

    for attempt in 1..=attempts {
        // Reuse the owned batch on the final attempt so single-attempt plugins
        // avoid the clone entirely and retried batches only clone N-1 times.
        let keep_original_for_failure = attempt == attempts && on_failed_batch.is_some();
        let attempt_batch = if attempt < attempts || keep_original_for_failure {
            match final_batch.as_ref() {
                Some(batch) => batch.clone(),
                None => return,
            }
        } else {
            match final_batch.take() {
                Some(batch) => batch,
                None => return,
            }
        };

        match flush(attempt_batch).await {
            Ok(()) => return,
            Err(error) if attempt < attempts => {
                warn!(
                    plugin = cfg.plugin_name,
                    "{}: batch flush failed (attempt {}/{}): {}",
                    cfg.plugin_name,
                    attempt,
                    attempts,
                    error,
                );
                // Exponential backoff (capped, optionally jittered) so a
                // struggling backend is not hammered with a fixed-delay,
                // no-jitter retry storm (finding #77).
                tokio::time::sleep(cfg.retry.backoff_delay(attempt)).await;
            }
            Err(error) => {
                if let Some(on_failed_batch) = on_failed_batch {
                    warn!(
                        plugin = cfg.plugin_name,
                        "{}: handing failed batch to fallback after {} attempts ({} entries): {}",
                        cfg.plugin_name,
                        attempts,
                        entry_count,
                        error,
                    );
                    if let Some(batch) = final_batch.take() {
                        on_failed_batch(batch, error);
                    }
                } else {
                    warn!(
                        plugin = cfg.plugin_name,
                        "{}: batch discarded after {} attempts ({} entries lost): {}",
                        cfg.plugin_name,
                        attempts,
                        entry_count,
                        error,
                    );
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_policy_has_constant_delay_no_jitter() {
        let policy = RetryPolicy::fixed(5, Duration::from_millis(250));
        assert_eq!(policy.max_delay, Duration::from_millis(250));
        assert!(!policy.jitter);
        // No growth, no jitter: every attempt yields exactly the base delay.
        for attempt in 1..=5 {
            assert_eq!(policy.backoff_delay(attempt), Duration::from_millis(250));
        }
    }

    #[test]
    fn backoff_grows_exponentially_and_caps_at_max_delay() {
        let policy = RetryPolicy {
            max_attempts: 10,
            delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(1_000),
            jitter: false,
        };
        // 100 * 2^(attempt-1): 100, 200, 400, 800, then capped at 1000.
        assert_eq!(policy.backoff_delay(1), Duration::from_millis(100));
        assert_eq!(policy.backoff_delay(2), Duration::from_millis(200));
        assert_eq!(policy.backoff_delay(3), Duration::from_millis(400));
        assert_eq!(policy.backoff_delay(4), Duration::from_millis(800));
        // 100 * 2^4 = 1600 -> capped to 1000.
        assert_eq!(policy.backoff_delay(5), Duration::from_millis(1_000));
        assert_eq!(policy.backoff_delay(6), Duration::from_millis(1_000));
    }

    #[test]
    fn very_large_attempt_does_not_overflow_and_stays_capped() {
        let policy = RetryPolicy {
            max_attempts: u32::MAX,
            delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(5_000),
            jitter: false,
        };
        // The shift is clamped and the multiply saturates, so a huge attempt
        // index never panics and the result stays at the cap.
        assert_eq!(policy.backoff_delay(u32::MAX), Duration::from_millis(5_000));
        assert_eq!(
            policy.backoff_delay(1_000_000),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn jitter_stays_within_zero_and_capped_bound() {
        let policy = RetryPolicy {
            max_attempts: 10,
            delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(1_000),
            jitter: true,
        };
        // At attempt 5 the capped (pre-jitter) delay is 1000ms; full jitter must
        // produce a value in [0, 1000].
        for _ in 0..1_000 {
            let d = policy.backoff_delay(5);
            assert!(
                d <= Duration::from_millis(1_000),
                "jittered delay {d:?} exceeded cap"
            );
        }
        // Over many samples jitter must actually vary (not collapse to a constant).
        let samples: std::collections::HashSet<u128> = (0..256)
            .map(|_| policy.backoff_delay(5).as_millis())
            .collect();
        assert!(samples.len() > 1, "jitter produced no variation");
    }

    #[test]
    fn max_delay_below_initial_is_treated_as_constant() {
        // Defensive: if max_delay < delay, backoff_delay clamps the cap up to
        // the base so the delay never shrinks below the configured initial.
        let policy = RetryPolicy {
            max_attempts: 5,
            delay: Duration::from_millis(500),
            max_delay: Duration::from_millis(100),
            jitter: false,
        };
        assert_eq!(policy.backoff_delay(1), Duration::from_millis(500));
        assert_eq!(policy.backoff_delay(3), Duration::from_millis(500));
    }

    #[test]
    fn backoff_delay_is_capped_to_tokio_timer_range() {
        let policy = RetryPolicy {
            max_attempts: 2,
            delay: Duration::from_millis(u64::MAX),
            max_delay: Duration::from_millis(u64::MAX),
            jitter: false,
        };

        assert_eq!(
            policy.backoff_delay(1),
            Duration::from_millis(MAX_TOKIO_SLEEP_MS)
        );
    }
}
