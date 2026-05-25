use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, warn};

const DROP_WARN_EVERY: u64 = 100;
pub const MAX_BATCH_SIZE: usize = 10_000;
pub const MAX_BUFFER_CAPACITY: usize = 1_000_000;

/// Strategy for retrying a failed flush. The flush closure owns its own
/// status-code-aware logic (e.g. "don't retry 401/403, do retry 408/429") —
/// `BatchingLogger` just enforces attempt count and inter-attempt delay.
#[derive(Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub delay: Duration,
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
    sender: mpsc::Sender<T>,
    plugin_name: &'static str,
    dropped_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
    buffer_capacity: usize,
    hooks: LoggerHooks<T>,
}

type FailedBatchHook<T> = Arc<dyn Fn(Vec<T>, String) + Send + Sync>;
type OverflowHook<T> = Arc<dyn Fn(T, &'static str) + Send + Sync>;
type HighWaterHook = Arc<dyn Fn(usize, usize) + Send + Sync>;

#[derive(Clone)]
pub struct LoggerHooks<T: Send + 'static> {
    pub on_failed_batch: Option<FailedBatchHook<T>>,
    pub on_overflow: Option<OverflowHook<T>>,
    /// Called whenever the observed queue depth is above the configured
    /// high-water mark. This hook is independent of `on_overflow`.
    pub on_high_water: Option<HighWaterHook>,
    pub high_watermark_percent: u8,
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
        let (sender, receiver) = mpsc::channel(cfg.buffer_capacity);
        let queue_depth = Arc::new(AtomicUsize::new(0));
        tokio::spawn(run_flush_loop_with_hooks(
            cfg,
            receiver,
            Arc::clone(&queue_depth),
            flush,
            hooks.on_failed_batch.clone(),
        ));

        Self {
            sender,
            plugin_name: cfg.plugin_name,
            dropped_count: Arc::new(AtomicU64::new(0)),
            queue_depth,
            buffer_capacity: cfg.buffer_capacity,
            hooks,
        }
    }

    /// Non-blocking send. On full buffer, logs a warning once per N drops and
    /// silently drops intermediate entries so the hot path never blocks.
    pub fn try_send(&self, item: T) -> bool {
        let depth = self.queue_depth.load(Ordering::Relaxed);
        if self.is_high_water(depth) {
            if let Some(on_high_water) = self.hooks.on_high_water.as_ref() {
                on_high_water(depth, self.buffer_capacity);
            }
            if let Some(on_overflow) = self.hooks.on_overflow.as_ref() {
                on_overflow(item, "queue high water");
                return false;
            }
        }

        self.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(item)) => {
                decrement_queue_depth(&self.queue_depth);
                self.record_drop("buffer full");
                if let Some(on_overflow) = self.hooks.on_overflow.as_ref() {
                    on_overflow(item, "buffer full");
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                decrement_queue_depth(&self.queue_depth);
                self.record_drop("worker unavailable during shutdown");
                false
            }
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }

    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    fn is_high_water(&self, depth: usize) -> bool {
        depth.saturating_mul(100)
            >= self
                .buffer_capacity
                .saturating_mul(self.hooks.high_watermark_percent.max(1) as usize)
    }

    fn record_drop(&self, reason: &str) {
        let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(DROP_WARN_EVERY) {
            warn!(
                plugin = self.plugin_name,
                "{}: dropping queued log entry because {} ({} dropped total; logging every {} drops)",
                self.plugin_name,
                reason,
                dropped,
                DROP_WARN_EVERY,
            );
        }
    }
}

async fn run_flush_loop_with_hooks<T, F, Fut>(
    cfg: BatchConfig,
    mut receiver: mpsc::Receiver<T>,
    queue_depth: Arc<AtomicUsize>,
    flush: F,
    on_failed_batch: Option<FailedBatchHook<T>>,
) where
    T: Send + Clone + 'static,
    F: Fn(Vec<T>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    let mut buffer = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            item = receiver.recv() => {
                match item {
                    Some(item) => {
                        decrement_queue_depth(&queue_depth);
                        buffer.push(item);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            flush_with_retry(&cfg, &flush, batch, on_failed_batch.as_ref()).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            flush_with_retry(&cfg, &flush, batch, on_failed_batch.as_ref()).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    flush_with_retry(&cfg, &flush, batch, on_failed_batch.as_ref()).await;
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
                tokio::time::sleep(cfg.retry.delay).await;
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
