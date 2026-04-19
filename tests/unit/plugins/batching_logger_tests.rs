use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_edge::plugins::utils::{BatchConfig, BatchingLogger, RetryPolicy};
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct SharedGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

fn test_logger_config(
    plugin_name: &'static str,
    batch_size: usize,
    buffer_capacity: usize,
) -> BatchConfig {
    BatchConfig {
        batch_size,
        flush_interval: Duration::from_millis(25),
        buffer_capacity,
        retry: RetryPolicy {
            max_attempts: 3,
            delay: Duration::from_millis(10),
        },
        plugin_name,
    }
}

async fn wait_for_flush(notify: &Notify) {
    timeout(Duration::from_millis(250), notify.notified())
        .await
        .expect("flush did not occur in time");
}

#[tokio::test(flavor = "current_thread")]
async fn try_send_batch_threshold_triggers_flush() {
    let flushed = Arc::new(Mutex::new(Vec::<Vec<u32>>::new()));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let flushed_clone = Arc::clone(&flushed);

    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_threshold", 2, 8),
        move |batch| {
            let notify = Arc::clone(&notify_clone);
            let flushed = Arc::clone(&flushed_clone);
            async move {
                flushed.lock().unwrap().push(batch);
                notify.notify_one();
                Ok(())
            }
        },
    );

    logger.try_send(1);
    logger.try_send(2);

    wait_for_flush(&notify).await;
    assert_eq!(*flushed.lock().unwrap(), vec![vec![1, 2]]);
}

#[tokio::test(flavor = "current_thread")]
async fn interval_timer_flushes_partial_batch() {
    let flushed = Arc::new(Mutex::new(Vec::<Vec<u32>>::new()));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let flushed_clone = Arc::clone(&flushed);

    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_interval", 10, 8),
        move |batch| {
            let notify = Arc::clone(&notify_clone);
            let flushed = Arc::clone(&flushed_clone);
            async move {
                flushed.lock().unwrap().push(batch);
                notify.notify_one();
                Ok(())
            }
        },
    );

    logger.try_send(7);

    wait_for_flush(&notify).await;
    assert_eq!(*flushed.lock().unwrap(), vec![vec![7]]);
}

#[tokio::test(flavor = "current_thread")]
async fn retry_policy_retries_failed_flushes() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let attempts_clone = Arc::clone(&attempts);
    let notify_clone = Arc::clone(&notify);

    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_retry", 1, 8),
        move |batch: Vec<u32>| {
            let attempts = Arc::clone(&attempts_clone);
            let notify = Arc::clone(&notify_clone);
            async move {
                assert_eq!(batch, vec![9]);
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if attempt == 3 {
                    notify.notify_one();
                    Ok(())
                } else {
                    Err(format!("attempt {attempt} failed"))
                }
            }
        },
    );

    logger.try_send(9);

    wait_for_flush(&notify).await;
    assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_retries_log_and_drop_batch() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();

    let guard = tracing::subscriber::set_default(subscriber);
    {
        let notify = Arc::new(Notify::new());
        let notify_clone = Arc::clone(&notify);

        let logger = BatchingLogger::spawn(
            test_logger_config("batching_logger_exhausted", 1, 8),
            move |_batch: Vec<u32>| {
                let notify = Arc::clone(&notify_clone);
                async move {
                    notify.notify_one();
                    Err("always fails".to_string())
                }
            },
        );

        logger.try_send(1);
        wait_for_flush(&notify).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(guard);

    let logs = writer.contents();
    assert!(logs.contains("batching_logger_exhausted: batch discarded after 3 attempts"));
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_logger_drains_remaining_entries() {
    let flushed = Arc::new(Mutex::new(Vec::<Vec<u32>>::new()));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let flushed_clone = Arc::clone(&flushed);

    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_shutdown", 10, 8),
        move |batch| {
            let notify = Arc::clone(&notify_clone);
            let flushed = Arc::clone(&flushed_clone);
            async move {
                flushed.lock().unwrap().push(batch);
                notify.notify_one();
                Ok(())
            }
        },
    );

    logger.try_send(42);
    drop(logger);

    wait_for_flush(&notify).await;
    assert_eq!(*flushed.lock().unwrap(), vec![vec![42]]);
}

#[tokio::test(flavor = "current_thread")]
async fn full_channel_warns_once_per_rate_limit_window() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();

    let guard = tracing::subscriber::set_default(subscriber);
    {
        let logger = BatchingLogger::spawn(
            test_logger_config("batching_logger_drop", 10, 1),
            move |_batch: Vec<u32>| async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            },
        );

        logger.try_send(1);
        for value in 2..10 {
            logger.try_send(value);
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(guard);

    let logs = writer.contents();
    let occurrences = logs
        .matches("batching_logger_drop: dropping queued log entry because buffer full")
        .count();
    assert_eq!(occurrences, 1, "drop warnings should be rate-limited");
}

struct CloneTracked {
    value: u32,
    clone_count: Arc<AtomicUsize>,
}

impl CloneTracked {
    fn new(value: u32, clone_count: Arc<AtomicUsize>) -> Self {
        Self { value, clone_count }
    }
}

impl Clone for CloneTracked {
    fn clone(&self) -> Self {
        self.clone_count.fetch_add(1, Ordering::Relaxed);
        Self {
            value: self.value,
            clone_count: Arc::clone(&self.clone_count),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn single_attempt_flush_reuses_owned_batch_without_clone() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let clone_count_for_flush = Arc::clone(&clone_count);

    let logger = BatchingLogger::spawn(
        BatchConfig {
            retry: RetryPolicy {
                max_attempts: 1,
                delay: Duration::from_millis(0),
            },
            ..test_logger_config("batching_logger_single_attempt", 1, 8)
        },
        move |batch: Vec<CloneTracked>| {
            let notify = Arc::clone(&notify_clone);
            let clone_count = Arc::clone(&clone_count_for_flush);
            async move {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].value, 11);
                assert_eq!(clone_count.load(Ordering::Relaxed), 0);
                notify.notify_one();
                Ok(())
            }
        },
    );

    logger.try_send(CloneTracked::new(11, Arc::clone(&clone_count)));

    wait_for_flush(&notify).await;
    assert_eq!(clone_count.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn retries_clone_only_before_final_attempt() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let attempts_clone = Arc::clone(&attempts);

    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_clone_retries", 1, 8),
        move |batch: Vec<CloneTracked>| {
            let notify = Arc::clone(&notify_clone);
            let attempts = Arc::clone(&attempts_clone);
            async move {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].value, 22);
                let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                if attempt == 3 {
                    notify.notify_one();
                    Ok(())
                } else {
                    Err(format!("attempt {attempt} failed"))
                }
            }
        },
    );

    logger.try_send(CloneTracked::new(22, Arc::clone(&clone_count)));

    wait_for_flush(&notify).await;
    assert_eq!(attempts.load(Ordering::Relaxed), 3);
    assert_eq!(clone_count.load(Ordering::Relaxed), 2);
}
