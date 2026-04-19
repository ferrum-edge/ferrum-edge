use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::warn;

const DROP_WARN_EVERY: u64 = 100;

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
        let batch_size = cfg.batch_size.max(1);
        let (sender, receiver) = mpsc::channel(cfg.buffer_capacity.max(1));
        tokio::spawn(run_flush_loop(
            BatchConfig { batch_size, ..cfg },
            receiver,
            flush,
        ));

        Self {
            sender,
            plugin_name: cfg.plugin_name,
            dropped_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Non-blocking send. On full buffer, logs a warning once per N drops and
    /// silently drops intermediate entries so the hot path never blocks.
    pub fn try_send(&self, item: T) {
        match self.sender.try_send(item) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => self.record_drop("buffer full"),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.record_drop("worker unavailable during shutdown")
            }
        }
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

async fn run_flush_loop<T, F, Fut>(cfg: BatchConfig, mut receiver: mpsc::Receiver<T>, flush: F)
where
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
                        buffer.push(item);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            flush_with_retry(&cfg, &flush, batch).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            flush_with_retry(&cfg, &flush, batch).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    flush_with_retry(&cfg, &flush, batch).await;
                }
            }
        }
    }
}

async fn flush_with_retry<T, F, Fut>(cfg: &BatchConfig, flush: &F, batch: Vec<T>)
where
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
        let attempt_batch = if attempt < attempts {
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
                warn!(
                    plugin = cfg.plugin_name,
                    "{}: batch discarded after {} attempts ({} entries lost): {}",
                    cfg.plugin_name,
                    attempts,
                    entry_count,
                    error,
                );
                return;
            }
        }
    }
}
