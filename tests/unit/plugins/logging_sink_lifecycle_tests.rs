//! Runtime-free validation and deferred activation for worker-backed logging sinks
//! (issue #2616).
//!
//! Offline `ferrum-edge validate` loads a file-mode spec through
//! [`ferrum_edge::config::file_loader::load_config_from_file`] without a Tokio
//! runtime and without calling `start_background_tasks`. These regressions prove
//! that shared pipeline stays panic-free and side-effect-free, and that live
//! construction still activates workers through the shared plugin-cache lifecycle
//! hook.

use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::plugins::api_chargeback_sink::{self, ApiChargebackSink};
use ferrum_edge::plugins::kafka_logging::KafkaLogging;
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{
    Plugin, ai_transcript_audit::AiTranscriptAudit, http_logging::HttpLogging,
    loki_logging::LokiLogging, statsd_logging::StatsdLogging, tcp_logging::TcpLogging,
    udp_logging::UdpLogging, validate_plugin_config, ws_logging::WsLogging,
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

fn all_sink_cases(tmp: &tempfile::TempDir) -> Vec<(&'static str, Value)> {
    vec![
        ("http_logging", http_sink_config()),
        ("tcp_logging", tcp_sink_config()),
        ("udp_logging", udp_sink_config()),
        ("statsd_logging", statsd_sink_config()),
        ("loki_logging", loki_sink_config()),
        ("ws_logging", ws_sink_config()),
        ("kafka_logging", kafka_sink_config()),
        ("api_chargeback_sink", chargeback_sink_config(tmp)),
        ("ai_transcript_audit", transcript_sink_config()),
    ]
}

fn malformed_sink_cases() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "http_logging",
            json!({"endpoint_url": ""}),
            "endpoint_url",
        ),
        ("tcp_logging", json!({"host": "127.0.0.1"}), "port"),
        ("udp_logging", json!({"port": 9}), "host"),
        ("statsd_logging", json!({"host": ""}), "host"),
        (
            "loki_logging",
            json!({"endpoint_url": "not-a-url"}),
            "endpoint_url",
        ),
        (
            "ws_logging",
            json!({"endpoint_url": "http://127.0.0.1:9/logs"}),
            "ws://",
        ),
        (
            "kafka_logging",
            json!({"broker_list": "127.0.0.1:9092"}),
            "topic",
        ),
        (
            "api_chargeback_sink",
            json!({
                "mode": "per_event",
                "clickhouse": {
                    "url": "http://127.0.0.1:8123",
                    "database": "ferrum",
                    "table": "charges_raw",
                    "timeout_ms": 1000
                },
                "batch": {"size": 0, "flush_interval_ms": 60000, "buffer_capacity": 10},
                "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
                "spool": {"enabled": false},
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
                "pricing_version": "test-v1",
                "currency": "USD"
            }),
            "batch.size",
        ),
        (
            "ai_transcript_audit",
            json!({
                "mode": "metadata_only",
                "sink": {"type": "http"}
            }),
            "endpoint_url",
        ),
    ]
}

fn write_file_mode_spec(path: &std::path::Path, plugin_name: &str, config: &Value) {
    let spec = json!({
        "version": "1",
        "proxies": [{
            "id": "http",
            "listen_path": "/",
            "backend_host": "127.0.0.1",
            "backend_port": 9000
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": format!("{plugin_name}-plugin"),
            "plugin_name": plugin_name,
            "config": config,
            "scope": "global",
            "enabled": true
        }]
    });
    std::fs::write(path, serde_json::to_vec(&spec).expect("serialize spec"))
        .expect("write file-mode spec");
}

fn load_file_mode_spec(
    path: &std::path::Path,
) -> Result<ferrum_edge::config::types::GatewayConfig, anyhow::Error> {
    load_config_from_file(
        path.to_str().expect("utf-8 temp path"),
        30,
        &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        "ferrum",
    )
}

/// Same synchronous file validation pipeline used by `ferrum-edge validate`
/// (`execute_validate` → `load_config_from_file`), without launching the binary.
#[test]
fn file_mode_validate_pipeline_accepts_each_worker_backed_sink() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    let kafka_before = ferrum_edge::plugins::kafka_logging::snapshots().len();

    for (name, config) in all_sink_cases(&tmp) {
        let spec_path = tmp.path().join(format!("{name}-ok.json"));
        write_file_mode_spec(&spec_path, name, &config);
        load_file_mode_spec(&spec_path).unwrap_or_else(|error| {
            panic!("{name}: file-mode validate pipeline failed: {error}")
        });
    }

    assert!(
        !spool.exists(),
        "api_chargeback_sink file-mode validation must not create spool directories"
    );
    assert_eq!(
        ferrum_edge::plugins::kafka_logging::snapshots().len(),
        kafka_before,
        "file-mode validation must not register a Kafka generation"
    );
}

#[test]
fn file_mode_validate_pipeline_rejects_malformed_sink_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");

    for (name, config, needle) in malformed_sink_cases() {
        let spec_path = tmp.path().join(format!("{name}-bad.json"));
        write_file_mode_spec(&spec_path, name, &config);
        let error = load_file_mode_spec(&spec_path)
            .expect_err(&format!("{name}: expected structured validation failure"));
        let text = error.to_string();
        assert!(
            text.contains("plugin config error") || text.contains(needle),
            "{name}: expected structured plugin config error containing '{needle}', got: {text}"
        );
        assert!(
            text.contains(needle),
            "{name}: structured error should name the bad field/hint '{needle}', got: {text}"
        );
    }
}

#[test]
fn logging_sink_shared_validation_is_runtime_free() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for (name, config) in all_sink_cases(&tmp) {
        validate_plugin_config(name, &config).unwrap_or_else(|error| {
            panic!("{name}: runtime-free validate_plugin_config failed: {error}")
        });
    }

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
    assert_eq!(
        snap.generation_id, 0,
        "kafka validation construction must not allocate a live generation id"
    );
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

#[test]
fn kafka_validation_construction_does_not_register_generations() {
    let registered_before = ferrum_edge::plugins::kafka_logging::snapshots().len();
    for _ in 0..8 {
        let plugin = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
        assert_eq!(plugin.snapshot().generation_id, 0);
        assert!(!plugin.snapshot().accepting);
        drop(plugin);
    }
    assert_eq!(
        ferrum_edge::plugins::kafka_logging::snapshots().len(),
        registered_before,
        "validation-only kafka construction must not register generations"
    );
}

#[tokio::test]
async fn kafka_generation_id_allocated_only_on_activation() {
    let first = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    assert_eq!(first.snapshot().generation_id, 0);
    first
        .start_background_tasks()
        .expect("kafka start under tokio");
    let first_id = first.snapshot().generation_id;
    assert!(first_id >= 1, "activation must allocate a live generation id");
    assert!(first.snapshot().accepting);
    first.finalize().await;

    // Further validation-only construction still reports id 0.
    let pending = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    assert_eq!(pending.snapshot().generation_id, 0);

    let second = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    second
        .start_background_tasks()
        .expect("second kafka start");
    let second_id = second.snapshot().generation_id;
    assert!(
        second_id > first_id,
        "each successful activation must allocate a new generation id ({second_id} > {first_id})"
    );
    second.finalize().await;
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_lifecycle_secret)]
async fn chargeback_activation_failure_publishes_no_active_sink() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("missing-secret-spool");
    let cfg = json!({
        "mode": "per_event",
        "clickhouse": {
            "url": "https://127.0.0.1:8443",
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 1000,
            "password_ref": "FERRUM_CHARGEBACK_LIFECYCLE_MISSING_SECRET"
        },
        "batch": {"size": 2, "flush_interval_ms": 60000, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {
            "enabled": true,
            "dir": spool.to_string_lossy(),
            "max_bytes": 1_048_576,
            "replay_interval_secs": 3600,
            "compression": "none"
        },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "pricing_version": "test-v1",
        "currency": "USD"
    });

    // Pure construction succeeds (shape-only); secret materialization is deferred.
    let plugin = ApiChargebackSink::new(&cfg, client(), "default").expect("shape ok");
    assert!(!spool.exists(), "construction must not mkdir spool");

    let err = plugin
        .start_background_tasks()
        .expect_err("missing password_ref must fail activation");
    assert!(
        err.contains("password_ref") || err.contains("unset"),
        "activation error should name the secret failure: {err}"
    );
    assert!(
        !spool.exists(),
        "failed activation before spool setup must not create spool directories"
    );

    // Retryable: after the secret appears, start can succeed.
    // SAFETY: test-only env mutation for deferred secret activation.
    unsafe {
        std::env::set_var("FERRUM_CHARGEBACK_LIFECYCLE_MISSING_SECRET", "test-secret");
    }
    plugin
        .start_background_tasks()
        .expect("activation retries after secret is present");
    let status: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(
        status.get("enabled").and_then(Value::as_bool),
        Some(true),
        "successful activation must publish ACTIVE_SINK"
    );
    unsafe {
        std::env::remove_var("FERRUM_CHARGEBACK_LIFECYCLE_MISSING_SECRET");
    }
    drop(plugin);
    let status_after: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(
        status_after.get("enabled").and_then(Value::as_bool),
        Some(false),
        "drop must clear ACTIVE_SINK owned by this instance"
    );
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
    assert!(kafka.snapshot().generation_id >= 1);
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
