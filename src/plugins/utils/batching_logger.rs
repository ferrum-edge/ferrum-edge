use std::future::Future;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, warn};

const DROP_WARN_EVERY: u64 = 100;
pub const MAX_BATCH_SIZE: usize = 10_000;
pub const MAX_BUFFER_CAPACITY: usize = 1_000_000;
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
    sender: mpsc::Sender<T>,
    plugin_name: &'static str,
    dropped_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
    buffer_capacity: usize,
    hooks: LoggerHooks<T>,
}

/// An atomically reserved queue slot for a record that will be constructed
/// later. Dropping an unused permit releases both the channel slot and the
/// logger's depth accounting.
pub struct BatchingLoggerPermit<T: Send + 'static> {
    permit: Option<mpsc::OwnedPermit<T>>,
    queue_depth: Arc<AtomicUsize>,
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
        }
    }
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

    /// Atomically reserve one bounded-channel slot without constructing the
    /// item yet. This supports fail-closed plugins that must guarantee enqueue
    /// capacity before a response becomes immutable, while filling the record
    /// only after later validators determine the final status and body.
    pub fn try_reserve(&self) -> Option<BatchingLoggerPermit<T>> {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.sender.clone().try_reserve_owned() {
            Ok(permit) => Some(BatchingLoggerPermit {
                permit: Some(permit),
                queue_depth: Arc::clone(&self.queue_depth),
            }),
            Err(mpsc::error::TrySendError::Full(_sender)) => {
                decrement_queue_depth(&self.queue_depth);
                self.record_drop("buffer full while reserving a commit slot");
                None
            }
            Err(mpsc::error::TrySendError::Closed(_sender)) => {
                decrement_queue_depth(&self.queue_depth);
                self.record_drop("worker unavailable while reserving a commit slot");
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
