//! Runtime-free validation and deferred activation for worker-backed logging sinks
//! (issue #2616).
//!
//! Offline `ferrum-edge validate` loads a file-mode spec through
//! [`ferrum_edge::config::file_loader::load_config_from_file`] without a Tokio
//! runtime and without calling `start_background_tasks`. These regressions prove
//! that shared pipeline stays panic-free and side-effect-free. Live generations
//! stage workers in `start_background_tasks` and release them only from
//! `commit_background_tasks` after PluginCache publication — including proofs
//! that spool replay/snapshot stay dormant until commit and that staged drop
//! exits without flush side effects.

use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::plugins::api_chargeback_sink::{self, ApiChargebackSink};
use ferrum_edge::plugins::kafka_logging::KafkaLogging;
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{
    Plugin, PluginFailurePolicy, ai_transcript_audit::AiTranscriptAudit, http_logging::HttpLogging,
    loki_logging::LokiLogging, plugin_failure_policy, statsd_logging::StatsdLogging,
    tcp_logging::TcpLogging, udp_logging::UdpLogging, validate_plugin_config,
    ws_logging::WsLogging,
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
        ("http_logging", json!({"endpoint_url": ""}), "endpoint_url"),
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
        load_file_mode_spec(&spec_path)
            .unwrap_or_else(|error| panic!("{name}: file-mode validate pipeline failed: {error}"));
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

    // Constructors / validate_plugin_config must reject every malformed case
    // synchronously (runtime-free). This pins semantic validation in `new`
    // even when file-mode OptionalFailOpen soft-warns and omits the instance.
    for (name, config, needle) in malformed_sink_cases() {
        let error = validate_plugin_config(name, &config)
            .expect_err(&format!("{name}: expected constructor validation failure"));
        assert!(
            error.contains(needle),
            "{name}: validate_plugin_config should name the bad field/hint '{needle}', got: {error}"
        );
    }

    // KeepLastKnownGood sinks must also fail closed through the file-mode
    // load path used by `ferrum-edge validate`. OptionalFailOpen sinks warn
    // and omit rather than aborting the surrounding snapshot (docs/plugins.md).
    for (name, config, needle) in malformed_sink_cases() {
        if plugin_failure_policy(name) == Some(PluginFailurePolicy::OptionalFailOpen) {
            continue;
        }
        let spec_path = tmp.path().join(format!("{name}-bad.json"));
        write_file_mode_spec(&spec_path, name, &config);
        let error = load_file_mode_spec(&spec_path)
            .expect_err(&format!("{name}: expected structured validation failure"));
        let text = error.to_string();
        assert!(
            text.contains("plugin config error"),
            "{name}: expected the file-validation aggregate to report a plugin config error; direct validation above already pins field detail '{needle}', got: {text}"
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
    first.commit_background_tasks();
    let first_id = first.snapshot().generation_id;
    assert!(
        first_id >= 1,
        "activation must allocate a live generation id"
    );
    assert!(first.snapshot().accepting);
    first.finalize().await;

    // Further validation-only construction still reports id 0.
    let pending = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    assert_eq!(pending.snapshot().generation_id, 0);

    let second = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    second.start_background_tasks().expect("second kafka start");
    second.commit_background_tasks();
    let second_id = second.snapshot().generation_id;
    assert!(
        second_id > first_id,
        "each successful activation must allocate a new generation id ({second_id} > {first_id})"
    );
    second.finalize().await;
}

/// Process-global registration must wait for cache commit (issue #2616).
///
/// Assertions match the exact owned generation id so parallel suites that
/// register unrelated generations cannot false-pass or false-fail this proof.
#[tokio::test]
async fn kafka_generation_registers_only_after_commit() {
    let plugin = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    plugin
        .start_background_tasks()
        .expect("kafka start under tokio");
    let generation_id = plugin.snapshot().generation_id;
    assert!(
        generation_id >= 1,
        "start must allocate/own a live generation id"
    );
    assert!(
        plugin.snapshot().accepting,
        "start must open local admission before commit"
    );
    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "started but uncommitted generation {generation_id} must be absent from snapshots()"
    );

    plugin.commit_background_tasks();
    assert!(
        ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "commit must publish generation {generation_id} into snapshots()"
    );

    plugin.commit_background_tasks();
    let published = ferrum_edge::plugins::kafka_logging::snapshots()
        .iter()
        .filter(|snap| snap.generation_id == generation_id)
        .count();
    assert_eq!(
        published, 1,
        "repeated commit must remain idempotent for generation {generation_id}"
    );

    plugin.finalize().await;
    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "finalize must remove generation {generation_id} from snapshots()"
    );

    // Never-committed staged instance: start owns a generation locally, but
    // Drop must leave no process-global registration behind.
    let staged = KafkaLogging::new(&kafka_sink_config(), &client()).expect("staged kafka");
    staged.start_background_tasks().expect("staged kafka start");
    let staged_id = staged.snapshot().generation_id;
    assert!(staged_id >= 1 && staged_id != generation_id);
    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == staged_id),
        "uncommitted staged generation {staged_id} must stay out of snapshots()"
    );
    drop(staged);
    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == staged_id),
        "dropping an uncommitted generation must leave no snapshots() entry for {staged_id}"
    );
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
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
    assert!(
        !plugin.owns_active_sink(),
        "start must not publish ACTIVE_SINK before commit"
    );
    plugin.commit_background_tasks();
    assert!(
        plugin.owns_active_sink(),
        "successful commit must publish ACTIVE_SINK for this instance"
    );
    let status: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(
        status.get("enabled").and_then(Value::as_bool),
        Some(true),
        "successful activation must publish ACTIVE_SINK"
    );

    // A later staged generation may stage its owned workers before the cache
    // swap, but it must not displace diagnostics for the committed live sink.
    let mut staged_cfg = cfg.clone();
    staged_cfg["pricing_version"] = Value::String("staged-v2".to_string());
    let staged = ApiChargebackSink::new(&staged_cfg, client(), "default").expect("staged cb");
    staged
        .start_background_tasks()
        .expect("staged activation starts owned workers");
    let status_while_staged: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(
        status_while_staged
            .get("pricing_version")
            .and_then(Value::as_str),
        Some("test-v1"),
        "uncommitted staged activation must not replace the live sink"
    );
    drop(staged);
    let status_after_staged_drop: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(
        status_after_staged_drop
            .get("pricing_version")
            .and_then(Value::as_str),
        Some("test-v1"),
        "dropping a rejected staged sink must preserve live diagnostics"
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
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn logging_sink_live_construction_starts_workers_idempotently() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let http = HttpLogging::new(&http_sink_config(), client()).expect("http");
    http.start_background_tasks().expect("http start");
    http.commit_background_tasks();
    http.start_background_tasks()
        .expect("http start idempotent");
    http.commit_background_tasks();

    let tcp = TcpLogging::new(&tcp_sink_config(), client()).expect("tcp");
    tcp.start_background_tasks().expect("tcp start");
    tcp.commit_background_tasks();
    tcp.start_background_tasks().expect("tcp start idempotent");
    tcp.commit_background_tasks();

    let udp = UdpLogging::new(&udp_sink_config(), client()).expect("udp");
    udp.start_background_tasks().expect("udp start");
    udp.commit_background_tasks();
    udp.start_background_tasks().expect("udp start idempotent");
    udp.commit_background_tasks();

    let statsd = StatsdLogging::new(&statsd_sink_config(), client()).expect("statsd");
    statsd.start_background_tasks().expect("statsd start");
    statsd.commit_background_tasks();
    statsd
        .start_background_tasks()
        .expect("statsd start idempotent");
    statsd.commit_background_tasks();

    let loki = LokiLogging::new(&loki_sink_config(), client()).expect("loki");
    loki.start_background_tasks().expect("loki start");
    loki.commit_background_tasks();
    loki.start_background_tasks()
        .expect("loki start idempotent");
    loki.commit_background_tasks();

    let ws = WsLogging::new(&ws_sink_config(), client()).expect("ws");
    ws.start_background_tasks().expect("ws start");
    ws.commit_background_tasks();
    ws.start_background_tasks().expect("ws start idempotent");
    ws.commit_background_tasks();

    let kafka = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    kafka.start_background_tasks().expect("kafka start");
    kafka.commit_background_tasks();
    kafka
        .start_background_tasks()
        .expect("kafka start idempotent");
    kafka.commit_background_tasks();
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
    chargeback.commit_background_tasks();
    chargeback
        .start_background_tasks()
        .expect("chargeback start idempotent");
    chargeback.commit_background_tasks();
    let _ = tmp;

    let transcript = AiTranscriptAudit::new(&transcript_sink_config(), client()).expect("audit");
    transcript
        .start_background_tasks()
        .expect("transcript start");
    transcript.commit_background_tasks();
    transcript
        .start_background_tasks()
        .expect("transcript start idempotent");
    transcript.commit_background_tasks();
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
    assert!(!logger.is_committed());
    assert!(logger.try_send(7));
    // Staged but uncommitted: the flush callback must stay dormant.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        seen.lock().expect("lock").is_empty(),
        "flush must not run before commit"
    );
    logger.commit();
    assert!(logger.is_committed());
    for _ in 0..50 {
        if !seen.lock().expect("lock").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seen.lock().expect("lock").as_slice(), &[7]);
}

#[tokio::test]
async fn deferred_batching_logger_staged_drop_exits_without_flush() {
    use ferrum_edge::plugins::utils::{BatchConfig, DeferredBatchingLogger, RetryPolicy};
    use std::time::Duration;

    let flushed = Arc::new(AtomicUsize::new(0));
    let logger = DeferredBatchingLogger::<u32>::new();
    let flushed_cb = Arc::clone(&flushed);
    logger
        .start(
            "deferred_batching_logger_drop_test",
            BatchConfig {
                batch_size: 1,
                flush_interval: Duration::from_millis(10),
                buffer_capacity: 8,
                retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
                plugin_name: "deferred_batching_logger_drop_test",
            },
            move |batch| {
                flushed_cb.fetch_add(batch.len(), Ordering::SeqCst);
                async move { Ok(()) }
            },
        )
        .expect("stage under tokio");
    assert!(logger.try_send(9));
    drop(logger);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        flushed.load(Ordering::SeqCst),
        0,
        "dropping an uncommitted staged logger must not flush"
    );
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_spool_replay_and_snapshot_stay_dormant_until_commit() {
    use std::fs;
    use std::time::Duration;

    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("spool");
    // Pin node id so the planted replay candidate lands in the owned tree.
    // SAFETY: serial test-only env mutation.
    unsafe {
        std::env::set_var("FERRUM_NODE_ID", "lifecycle-spool-node");
    }

    let cfg = json!({
        "mode": "snapshot",
        "clickhouse": {
            "url": "http://127.0.0.1:9",
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 200
        },
        "batch": {"size": 10, "flush_interval_ms": 60000, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {
            "enabled": true,
            "dir": spool_dir.to_string_lossy(),
            "max_bytes": 1_048_576,
            "replay_interval_secs": 1,
            "compression": "none"
        },
        "snapshot": {
            "interval_secs": 1,
            "cleanup_interval_secs": 3600,
            "stale_entry_ttl_secs": 3600
        },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "pricing_version": "test-v1",
        "currency": "USD"
    });

    let plugin = ApiChargebackSink::new(&cfg, client(), "default").expect("chargeback");

    // Plant an invalid-UTF8 replay candidate and a crash-left temp before
    // staging. A candidate-generation SpoolManager must neither quarantine the
    // former nor reconcile/delete the latter before cache publication.
    let planted = spool_dir
        .join("lifecycle-spool-node")
        .join("20200101")
        .join("planted.ndjson");
    fs::create_dir_all(planted.parent().expect("parent")).expect("mkdir day dir");
    fs::write(&planted, [0xff, 0xfe, 0xfd]).expect("write corrupt spool bytes");
    let stale_tmp = planted.with_file_name("crash-left.ndjson.tmp");
    fs::write(&stale_tmp, b"partial").expect("write stale temp bytes");
    let planted_bytes = fs::metadata(&planted).expect("meta").len();

    plugin
        .start_background_tasks()
        .expect("stage chargeback with spool+snapshot");
    assert!(
        stale_tmp.exists(),
        "staging must not reconcile stale spool files before commit"
    );

    // Give both interval timers a chance to fire if they were not gated.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        planted.exists(),
        "spool replayer must not consume files before commit"
    );
    assert!(
        !planted.with_file_name("planted.ndjson.corrupt").exists(),
        "spool replayer must not quarantine files before commit"
    );
    assert_eq!(
        fs::metadata(&planted).expect("meta").len(),
        planted_bytes,
        "spool file must remain untouched before commit"
    );
    // ACTIVE_SINK is process-global; assert instance ownership rather than
    // global emptiness so parallel non-lifecycle suite members cannot flake
    // this dormancy proof. Publication must wait for commit.
    assert!(
        !plugin.owns_active_sink(),
        "ACTIVE_SINK must stay unpublished for this staged instance before commit"
    );

    // Drop without commit: workers must exit without spool side effects.
    drop(plugin);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        planted.exists(),
        "dropping an uncommitted chargeback sink must not replay/delete spool files"
    );
    assert!(
        !planted.with_file_name("planted.ndjson.corrupt").exists(),
        "dropping an uncommitted chargeback sink must not quarantine spool files"
    );
    assert!(
        stale_tmp.exists(),
        "dropping an uncommitted chargeback sink must not reconcile stale spool files"
    );
    unsafe {
        std::env::remove_var("FERRUM_NODE_ID");
    }
}
