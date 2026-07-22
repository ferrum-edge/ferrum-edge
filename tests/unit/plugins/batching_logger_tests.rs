use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_edge::plugins::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLogger, DeferredBatchingLogger, LoggerHooks,
    MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, RetryPolicy, build_batch_config,
    handle_http_batch_response, parse_custom_headers, parse_http_endpoint, validate_batch_config,
    wait_until_committed,
};
use serde_json::json;
use tokio::sync::{watch, Notify};
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
        retry: RetryPolicy::fixed(3, Duration::from_millis(10)),
        plugin_name,
    }
}

fn batch_defaults() -> BatchConfigDefaults {
    BatchConfigDefaults {
        batch_size_key: "batch_size",
        batch_size: 50,
        flush_interval_ms: 1000,
        min_flush_interval_ms: 100,
        buffer_capacity: 10_000,
        max_retries: 3,
        retry_delay_ms: 1000,
    }
}

async fn wait_for_flush(notify: &Notify) {
    timeout(Duration::from_millis(250), notify.notified())
        .await
        .expect("flush did not occur in time");
}

#[test]
fn build_batch_config_caps_unbounded_values() {
    let cfg = build_batch_config(
        &json!({
            "batch_size": u64::MAX,
            "buffer_capacity": u64::MAX,
            "max_retries": u64::MAX
        }),
        "batching_logger_bounds",
        batch_defaults(),
    );

    assert_eq!(cfg.batch_size, MAX_BATCH_SIZE);
    assert_eq!(cfg.buffer_capacity, MAX_BUFFER_CAPACITY);
    assert_eq!(cfg.retry.max_attempts, u32::MAX);
}

#[test]
fn build_batch_config_applies_defaults_and_lower_bounds() {
    let cfg = build_batch_config(
        &json!({
            "batch_size": 0,
            "buffer_capacity": 0,
            "flush_interval_ms": 1,
            "max_retries": 0,
            "retry_delay_ms": 0
        }),
        "batching_logger_bounds",
        batch_defaults(),
    );

    assert_eq!(cfg.batch_size, 1);
    assert_eq!(cfg.buffer_capacity, 1);
    assert_eq!(cfg.flush_interval, Duration::from_millis(100));
    assert_eq!(cfg.retry.max_attempts, 1);
    assert_eq!(cfg.retry.delay, Duration::from_millis(0));
    assert_eq!(cfg.plugin_name, "batching_logger_bounds");

    let default_cfg = build_batch_config(&json!({}), "batching_logger_defaults", batch_defaults());
    assert_eq!(default_cfg.batch_size, 50);
    assert_eq!(default_cfg.buffer_capacity, 10_000);
    assert_eq!(default_cfg.flush_interval, Duration::from_millis(1000));
    assert_eq!(default_cfg.retry.max_attempts, 4);
    assert_eq!(default_cfg.retry.delay, Duration::from_millis(1000));
}

#[test]
fn validate_batch_config_rejects_malformed_numeric_values() {
    for config in [
        json!({"batch_size": "many"}),
        json!({"flush_interval_ms": false}),
        json!({"buffer_capacity": -1}),
        json!({"max_retries": {}}),
        json!({"retry_delay_ms": []}),
    ] {
        assert!(
            validate_batch_config(&config, "batching_logger_bounds", batch_defaults()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[test]
fn parse_http_endpoint_accepts_http_https_host_forms() {
    let cases = [
        (
            json!({"endpoint_url": "http://logs.example.com/v1?tenant=edge#ignored"}),
            "http://logs.example.com/v1?tenant=edge#ignored",
            "logs.example.com",
        ),
        (
            json!({"endpoint_url": "https://[2001:db8::1]:9443/loki/api/v1/push"}),
            "https://[2001:db8::1]:9443/loki/api/v1/push",
            "2001:db8::1",
        ),
    ];

    // `Both` keeps this focused on host parsing rather than IP policy (one
    // case below is the IPv6 documentation range, which the policy treats as
    // private). IP-policy screening is covered by the log_helpers unit tests.
    for (config, expected_endpoint, expected_host) in cases {
        let (endpoint, host) = parse_http_endpoint(
            &config,
            "batching_logger_endpoint",
            &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        )
        .unwrap();
        assert_eq!(endpoint, expected_endpoint);
        assert_eq!(host, expected_host);
    }
}

#[test]
fn parse_http_endpoint_rejects_unusable_endpoint_forms() {
    for config in [
        json!({}),
        json!({"endpoint_url": ""}),
        json!({"endpoint_url": 42}),
        json!({"endpoint_url": "not a url"}),
        json!({"endpoint_url": "tcp://logs.example.com:9000"}),
        json!({"endpoint_url": "http:///logs"}),
    ] {
        assert!(
            parse_http_endpoint(
                &config,
                "batching_logger_endpoint",
                &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
            )
            .is_err(),
            "expected unusable endpoint to be rejected: {config}"
        );
    }
}

#[test]
fn parse_custom_headers_accepts_and_deduplicates_names() {
    let headers = parse_custom_headers(
        &json!({
            "custom_headers": {
                "X-Custom": "first",
                "x-custom": "second",
                "DD-API-KEY": "datadog"
            }
        }),
        "batching_logger_headers",
    )
    .unwrap();

    assert_eq!(headers.len(), 2);
    assert_eq!(
        headers
            .iter()
            .find(|(name, _)| name.as_str() == "x-custom")
            .and_then(|(_, value)| value.to_str().ok()),
        Some("second")
    );
    assert_eq!(
        headers
            .iter()
            .find(|(name, _)| name.as_str() == "dd-api-key")
            .and_then(|(_, value)| value.to_str().ok()),
        Some("datadog")
    );
}

#[test]
fn parse_custom_headers_rejects_invalid_shapes() {
    for (config, expected) in [
        (
            json!({"custom_headers": []}),
            "'custom_headers' must be an object",
        ),
        (
            json!({"custom_headers": {"X-Test": 1}}),
            "custom_headers['X-Test'] must be a string",
        ),
        (
            json!({"custom_headers": {"Bad Header": "value"}}),
            "invalid custom_headers name",
        ),
        (
            json!({"custom_headers": {"X-Test": "bad\u{0001}value"}}),
            "invalid custom_headers value",
        ),
    ] {
        let err = parse_custom_headers(&config, "batching_logger_headers")
            .expect_err("expected custom header config to be rejected");
        assert!(
            err.contains(expected),
            "error should include {expected:?}, got: {err}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn handle_http_batch_response_classifies_retryable_and_discarded_statuses() {
    for status in [
        reqwest::StatusCode::OK,
        reqwest::StatusCode::CREATED,
        reqwest::StatusCode::NO_CONTENT,
        reqwest::StatusCode::BAD_REQUEST,
        reqwest::StatusCode::UNAUTHORIZED,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
    ] {
        let response = http::Response::builder()
            .status(status)
            .body("")
            .unwrap()
            .into();
        assert!(
            handle_http_batch_response("batching_logger_http", 3, Ok(response))
                .await
                .is_ok(),
            "expected status {status} to be accepted or discarded without retry"
        );
    }

    for status in [
        reqwest::StatusCode::REQUEST_TIMEOUT,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        reqwest::StatusCode::BAD_GATEWAY,
    ] {
        let response = http::Response::builder()
            .status(status)
            .body("")
            .unwrap()
            .into();
        let err = handle_http_batch_response("batching_logger_http", 3, Ok(response))
            .await
            .expect_err("expected retryable status to be returned as an error");
        assert!(
            err.contains(&status.to_string()),
            "error should include retryable status {status}: {err}"
        );
        assert!(
            err.contains("response body drained"),
            "retryable errors should include the drain diagnostic: {err}"
        );
    }
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

    logger.commit();

    logger.try_send(1);
    logger.try_send(2);

    wait_for_flush(&notify).await;
    assert_eq!(*flushed.lock().unwrap(), vec![vec![1, 2]]);
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_slot_excludes_concurrent_reservation_until_send() {
    let flushed = Arc::new(Mutex::new(Vec::<Vec<u32>>::new()));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let flushed_clone = Arc::clone(&flushed);
    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_reserve", 1, 1),
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

    logger.commit();

    let permit = logger.try_reserve().expect("first slot must reserve");
    assert!(
        logger.try_reserve().is_none(),
        "a second response must not race into the reserved slot"
    );
    permit.send(7);
    wait_for_flush(&notify).await;
    assert_eq!(*flushed.lock().unwrap(), vec![vec![7]]);
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_unused_reservation_releases_capacity() {
    let logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_reserve_drop", 1, 1),
        move |_batch: Vec<u32>| async move { Ok(()) },
    );

    logger.commit();

    let permit = logger.try_reserve().expect("first slot must reserve");
    drop(permit);
    assert!(
        logger.try_reserve().is_some(),
        "dropping a non-emitting response permit must release its slot"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_batch_size_is_capped_before_flush_loop() {
    let flushed_len = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);
    let flushed_len_clone = Arc::clone(&flushed_len);

    let logger = BatchingLogger::spawn(
        BatchConfig {
            batch_size: MAX_BATCH_SIZE + 1024,
            flush_interval: Duration::from_secs(60),
            buffer_capacity: MAX_BATCH_SIZE + 16,
            retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
            plugin_name: "batching_logger_capped",
        },
        move |batch: Vec<usize>| {
            let notify = Arc::clone(&notify_clone);
            let flushed_len = Arc::clone(&flushed_len_clone);
            async move {
                flushed_len.store(batch.len(), Ordering::Relaxed);
                notify.notify_one();
                Ok(())
            }
        },
    );

    logger.commit();

    for value in 0..MAX_BATCH_SIZE {
        logger.try_send(value);
    }

    timeout(Duration::from_secs(1), notify.notified())
        .await
        .expect("capped batch did not flush");
    assert_eq!(flushed_len.load(Ordering::Relaxed), MAX_BATCH_SIZE);
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

    logger.commit();

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

    logger.commit();

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

        logger.commit();

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

    logger.commit();

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

        logger.commit();

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

#[tokio::test(flavor = "current_thread")]
async fn high_water_hook_fires_without_overflow_hook() {
    let high_water_hits = Arc::new(AtomicUsize::new(0));
    let high_water_hits_clone = Arc::clone(&high_water_hits);
    let logger = BatchingLogger::spawn_with_hooks(
        BatchConfig {
            batch_size: 10,
            flush_interval: Duration::from_secs(60),
            buffer_capacity: 1,
            retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
            plugin_name: "batching_logger_high_water",
        },
        LoggerHooks {
            on_high_water: Some(Arc::new(move |_, _| {
                high_water_hits_clone.fetch_add(1, Ordering::Relaxed);
            })),
            high_watermark_percent: 1,
            ..LoggerHooks::default()
        },
        move |_batch: Vec<u32>| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        },
    );

    logger.commit();

    assert!(logger.try_send(1));
    assert!(!logger.try_send(2));
    assert_eq!(high_water_hits.load(Ordering::Relaxed), 1);
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
            retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
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

    logger.commit();

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

    logger.commit();

    logger.try_send(CloneTracked::new(22, Arc::clone(&clone_count)));

    wait_for_flush(&notify).await;
    assert_eq!(attempts.load(Ordering::Relaxed), 3);
    assert_eq!(clone_count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn validate_plugin_config_with_policy_screens_literal_ip_endpoint() {
    // `http_logging`'s constructor spawns a batch-flush task, so this needs a
    // Tokio runtime — mirroring the async file/db config-load context.
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    use ferrum_edge::plugins::validate_plugin_config_with_policy;

    // A log sink pointed at the cloud-metadata address must be rejected at
    // config-load time under the production default policy (this is the
    // file/db pipeline path), even though the mode is `both`.
    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");
    let cfg = json!({ "endpoint_url": "http://169.254.169.254/ingest" });
    assert!(
        validate_plugin_config_with_policy("http_logging", &cfg, &default_policy).is_err(),
        "metadata endpoint must be rejected under the default policy"
    );

    // A loopback sink (local agent) still validates.
    let loopback = json!({ "endpoint_url": "http://127.0.0.1:9000/ingest" });
    assert!(
        validate_plugin_config_with_policy("http_logging", &loopback, &default_policy).is_ok(),
        "loopback sink must remain valid by default"
    );

    // The fully-unrestricted policy accepts the metadata endpoint (legacy posture).
    assert!(
        validate_plugin_config_with_policy(
            "http_logging",
            &cfg,
            &BackendEgressPolicy::unrestricted()
        )
        .is_ok()
    );
}

#[test]
fn deferred_batching_logger_default_is_unstarted() {
    let logger = DeferredBatchingLogger::<u32>::default();
    assert!(!logger.is_started());
    assert!(logger.get().is_none());
    assert!(!logger.try_send(1));
}

/// Uncommitted close must abort the dormant worker instead of draining it.
#[tokio::test]
async fn batching_logger_close_and_await_aborts_when_uncommitted() {
    let flushed = Arc::new(AtomicUsize::new(0));
    let flushed_cb = Arc::clone(&flushed);
    let mut logger = BatchingLogger::spawn(
        test_logger_config("batching_logger_uncommitted_close", 1, 8),
        move |batch: Vec<u32>| {
            flushed_cb.fetch_add(batch.len(), Ordering::SeqCst);
            async move { Ok(()) }
        },
    );
    assert!(logger.try_send(9));
    assert!(
        logger.close_and_await().await,
        "uncommitted close_and_await must abort and report success"
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        flushed.load(Ordering::SeqCst),
        0,
        "uncommitted close must not flush buffered entries"
    );
}

/// Deferred helpers expose the staged logger for lifecycle observers.
#[tokio::test]
async fn deferred_batching_logger_get_returns_staged_logger() {
    let deferred = DeferredBatchingLogger::<u32>::new();
    assert!(deferred.get().is_none());
    deferred
        .start(
            "deferred_batching_logger_get",
            test_logger_config("deferred_batching_logger_get", 1, 8),
            |_batch| async move { Ok(()) },
        )
        .expect("stage under tokio");
    let staged = deferred.get().expect("staged logger visible via get()");
    assert!(!staged.is_committed());
    assert!(deferred.try_send(3));
    deferred.commit();
    assert!(deferred.is_committed());
}

/// wait_until_committed ignores false notifications and returns false when the
/// commit gate is dropped without publication.
#[tokio::test]
async fn wait_until_committed_ignores_false_notifications_then_exits_on_drop() {
    let (tx, rx) = watch::channel(false);
    let waiter = tokio::spawn(async move { wait_until_committed(rx).await });
    // Allow the waiter to park on changed() before emitting a no-op false send.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    tx.send(false).expect("false notification");
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(tx);
    assert!(
        !waiter.await.expect("join waiter"),
        "dropping the commit gate without true must return false"
    );
}
