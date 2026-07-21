//! Runtime-free validation and deferred activation for worker-backed logging sinks
//! (issue #2616).
//!
//! Offline `ferrum-edge validate` constructs plugins without a Tokio runtime and
//! without calling `start_background_tasks`. These regressions prove that path
//! stays panic-free and side-effect-free, and that live construction still
//! activates workers through the shared plugin-cache lifecycle hook.

use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{
    Plugin, ai_transcript_audit::AiTranscriptAudit, api_chargeback_sink::ApiChargebackSink,
    http_logging::HttpLogging, kafka_logging::KafkaLogging, loki_logging::LokiLogging,
    statsd_logging::StatsdLogging, tcp_logging::TcpLogging, udp_logging::UdpLogging,
    validate_plugin_config, ws_logging::WsLogging,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn http_sink_config() -> Value {
    json!({"endpoint_url": "http://127.0.0.1:9/logs"})
}

fn tcp_sink_config() -> Value {
    json!({"host": "127.0.0.1", "port": 9})
}

fn udp_sink_config() -> Value {
    json!({"host": "127.0.0.1", "port": 9})
}

fn statsd_sink_config() -> Value {
    json!({"host": "127.0.0.1", "port": 8125})
}

fn loki_sink_config() -> Value {
    json!({"endpoint_url": "http://127.0.0.1:9/loki/api/v1/push"})
}

fn ws_sink_config() -> Value {
    json!({"endpoint_url": "ws://127.0.0.1:9/logs"})
}

fn kafka_sink_config() -> Value {
    json!({
        "broker_list": "127.0.0.1:9092",
        "topic": "ferrum-logs"
    })
}

fn chargeback_sink_config(tmp: &tempfile::TempDir) -> Value {
    json!({
        "mode": "per_event",
        "clickhouse": {
            "url": "http://127.0.0.1:8123",
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 1000
        },
        "batch": {"size": 2, "flush_interval_ms": 60000, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {
            "enabled": true,
            "dir": tmp.path().join("spool").to_string_lossy(),
            "max_bytes": 1_048_576,
            "replay_interval_secs": 3600,
            "compression": "none"
        },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "pricing_version": "test-v1",
        "currency": "USD"
    })
}

fn transcript_sink_config() -> Value {
    json!({
        "mode": "metadata_only",
        "sink": {
            "type": "http",
            "endpoint_url": "http://127.0.0.1:9/audit",
            "batch_size": 1,
            "flush_interval_ms": 100
        }
    })
}

#[test]
fn logging_sink_shared_validation_is_runtime_free() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases: Vec<(&str, Value)> = vec![
        ("http_logging", http_sink_config()),
        ("tcp_logging", tcp_sink_config()),
        ("udp_logging", udp_sink_config()),
        ("statsd_logging", statsd_sink_config()),
        ("loki_logging", loki_sink_config()),
        ("ws_logging", ws_sink_config()),
        ("kafka_logging", kafka_sink_config()),
        ("api_chargeback_sink", chargeback_sink_config(&tmp)),
        ("ai_transcript_audit", transcript_sink_config()),
    ];

    for (name, config) in cases {
        validate_plugin_config(name, &config).unwrap_or_else(|error| {
            panic!("{name}: runtime-free validate_plugin_config failed: {error}")
        });
    }

    // Spool directory must not be created by validation-only construction.
    assert!(
        !tmp.path().join("spool").exists(),
        "api_chargeback_sink validation must not create spool directories"
    );
}

#[test]
fn logging_sink_pure_constructors_leave_workers_unstarted() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let http = HttpLogging::new(&http_sink_config(), client()).expect("http");
    assert!(
        http.start_background_tasks().is_err(),
        "http_logging must refuse activation without a Tokio runtime"
    );

    let tcp = TcpLogging::new(&tcp_sink_config(), client()).expect("tcp");
    assert!(tcp.start_background_tasks().is_err());

    let udp = UdpLogging::new(&udp_sink_config(), client()).expect("udp");
    assert!(udp.start_background_tasks().is_err());

    let statsd = StatsdLogging::new(&statsd_sink_config(), client()).expect("statsd");
    assert!(statsd.start_background_tasks().is_err());

    let loki = LokiLogging::new(&loki_sink_config(), client()).expect("loki");
    assert!(loki.start_background_tasks().is_err());

    let ws = WsLogging::new(&ws_sink_config(), client()).expect("ws");
    assert!(ws.start_background_tasks().is_err());

    let kafka = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    assert!(kafka.start_background_tasks().is_err());
    let snap = kafka.snapshot();
    assert!(
        !snap.accepting,
        "kafka validation construction must not open admission"
    );

    let chargeback =
        ApiChargebackSink::new(&chargeback_sink_config(&tmp), client(), "default").expect("cb");
    assert!(chargeback.start_background_tasks().is_err());
    assert!(
        !tmp.path().join("spool").exists(),
        "chargeback pure construction must not create spool directories"
    );

    let transcript = AiTranscriptAudit::new(&transcript_sink_config(), client()).expect("audit");
    assert!(transcript.start_background_tasks().is_err());
}

#[tokio::test]
async fn logging_sink_live_construction_starts_workers_idempotently() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let http = HttpLogging::new(&http_sink_config(), client()).expect("http");
    http.start_background_tasks().expect("http start");
    http.start_background_tasks().expect("http start idempotent");

    let tcp = TcpLogging::new(&tcp_sink_config(), client()).expect("tcp");
    tcp.start_background_tasks().expect("tcp start");
    tcp.start_background_tasks().expect("tcp start idempotent");

    let udp = UdpLogging::new(&udp_sink_config(), client()).expect("udp");
    udp.start_background_tasks().expect("udp start");
    udp.start_background_tasks().expect("udp start idempotent");

    let statsd = StatsdLogging::new(&statsd_sink_config(), client()).expect("statsd");
    statsd.start_background_tasks().expect("statsd start");
    statsd
        .start_background_tasks()
        .expect("statsd start idempotent");

    let loki = LokiLogging::new(&loki_sink_config(), client()).expect("loki");
    loki.start_background_tasks().expect("loki start");
    loki.start_background_tasks().expect("loki start idempotent");

    let ws = WsLogging::new(&ws_sink_config(), client()).expect("ws");
    ws.start_background_tasks().expect("ws start");
    ws.start_background_tasks().expect("ws start idempotent");

    let kafka = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    kafka.start_background_tasks().expect("kafka start");
    kafka
        .start_background_tasks()
        .expect("kafka start idempotent");
    assert!(kafka.snapshot().accepting);
    kafka.finalize().await;

    // Chargeback with spool disabled avoids filesystem side effects in this
    // lifecycle proof; spool materialization is covered by dedicated tests.
    let chargeback_cfg = json!({
        "mode": "per_event",
        "clickhouse": {
            "url": "http://127.0.0.1:8123",
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 1000
        },
        "batch": {"size": 2, "flush_interval_ms": 60000, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {"enabled": false},
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "pricing_version": "test-v1",
        "currency": "USD"
    });
    let chargeback = ApiChargebackSink::new(&chargeback_cfg, client(), "default").expect("cb");
    chargeback
        .start_background_tasks()
        .expect("chargeback start");
    chargeback
        .start_background_tasks()
        .expect("chargeback start idempotent");
    let _ = tmp;

    let transcript = AiTranscriptAudit::new(&transcript_sink_config(), client()).expect("audit");
    transcript
        .start_background_tasks()
        .expect("transcript start");
    transcript
        .start_background_tasks()
        .expect("transcript start idempotent");
}

#[tokio::test]
async fn deferred_batching_logger_leaves_no_worker_when_never_started() {
    use ferrum_edge::plugins::utils::{BatchConfig, DeferredBatchingLogger, RetryPolicy};
    use std::time::Duration;

    let started = Arc::new(AtomicUsize::new(0));
    let logger = DeferredBatchingLogger::<u32>::new();
    assert!(!logger.is_started());
    assert!(!logger.try_send(1));
    assert!(logger.try_reserve().is_none());

    // Drop without start: no flush callback invocations.
    drop(logger);
    assert_eq!(started.load(Ordering::SeqCst), 0);

    let logger = DeferredBatchingLogger::<u32>::new();
    let started_cb = Arc::clone(&started);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = Arc::clone(&seen);
    logger
        .start(
            "deferred_batching_logger_test",
            BatchConfig {
                batch_size: 1,
                flush_interval: Duration::from_millis(50),
                buffer_capacity: 8,
                retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
                plugin_name: "deferred_batching_logger_test",
            },
            move |batch| {
                started_cb.fetch_add(1, Ordering::SeqCst);
                let seen_cb = Arc::clone(&seen_cb);
                async move {
                    seen_cb.lock().expect("lock").extend(batch);
                    Ok(())
                }
            },
        )
        .expect("start under tokio");
    assert!(logger.is_started());
    assert!(logger.try_send(7));
    for _ in 0..50 {
        if !seen.lock().expect("lock").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seen.lock().expect("lock").as_slice(), &[7]);
}
