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

use ferrum_edge::_test_support::{
    api_chargeback_sink_emit_snapshot_tick_for_test,
    api_chargeback_sink_finalize_snapshot_for_test,
    api_chargeback_sink_finalize_with_held_admission_for_test,
    api_chargeback_sink_snapshot_finalized_for_test,
    api_chargeback_sink_snapshot_generation_registered_for_test,
};
use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::plugins::api_chargeback_sink::{self, ApiChargebackSink};
use ferrum_edge::plugins::kafka_logging::KafkaLogging;
use ferrum_edge::plugins::utils::PluginHttpClient;
use ferrum_edge::plugins::{
    Plugin, PluginFailurePolicy, WsDisconnectContext, ai_transcript_audit::AiTranscriptAudit,
    http_logging::HttpLogging, loki_logging::LokiLogging, plugin_failure_policy,
    statsd_logging::StatsdLogging, tcp_logging::TcpLogging, udp_logging::UdpLogging,
    validate_plugin_config, ws_logging::WsLogging,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

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

const KAFKA_VALIDATION_PROBE_MAX_ENTRY_BYTES: u64 = 12_347;
const KAFKA_VALIDATION_PROBE_BUFFER_MAX_BYTES: u64 = 7_654_321;

fn kafka_validation_probe_config() -> Value {
    json!({
        "broker_list": "127.0.0.1:9092",
        "topic": "ferrum-validation-probe",
        "max_entry_bytes": KAFKA_VALIDATION_PROBE_MAX_ENTRY_BYTES,
        "buffer_max_bytes": KAFKA_VALIDATION_PROBE_BUFFER_MAX_BYTES
    })
}

fn kafka_validation_probe_is_registered() -> bool {
    ferrum_edge::plugins::kafka_logging::snapshots()
        .iter()
        .any(|snapshot| {
            snapshot.max_entry_bytes == KAFKA_VALIDATION_PROBE_MAX_ENTRY_BYTES
                && snapshot.buffer_max_bytes == KAFKA_VALIDATION_PROBE_BUFFER_MAX_BYTES
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

fn chargeback_snapshot_sink_config(spool_dir: &Path) -> Value {
    json!({
        "mode": "snapshot",
        "clickhouse": {
            "url": "http://127.0.0.1:9",
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 50
        },
        "batch": {"size": 1, "flush_interval_ms": 60000, "buffer_capacity": 1},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {
            "enabled": true,
            "dir": spool_dir.to_string_lossy(),
            "max_bytes": 1_048_576,
            "replay_interval_secs": 3600,
            "compression": "none"
        },
        "snapshot": {
            "interval_secs": 3600,
            "cleanup_interval_secs": 3600,
            "stale_entry_ttl_secs": 7200
        },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "pricing_version": "snapshot-lifecycle-v1",
        "currency": "USD"
    })
}

fn chargeback_spool_rows(root: &Path) -> Vec<Value> {
    fn visit(path: &Path, rows: &mut Vec<Value>) {
        if path.is_dir() {
            let entries = std::fs::read_dir(path).expect("read spool directory");
            for entry in entries {
                visit(&entry.expect("spool directory entry").path(), rows);
            }
            return;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("ndjson") {
            return;
        }
        let body = std::fs::read_to_string(path).expect("read spool file");
        rows.extend(
            body.lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("valid spooled JSONEachRow")),
        );
    }

    let mut rows = Vec::new();
    if root.exists() {
        visit(root, &mut rows);
    }
    rows
}

fn transcript_sink_config() -> Value {
    json!({
        "mode": "metadata_only",
        "sink": {
            "type": "http",
            "endpoint_url": "https://127.0.0.1:9/audit",
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
        ("kafka_logging", kafka_validation_probe_config()),
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
        "expected_resource_counts": {
            "proxies": 1,
            "consumers": 0,
            "upstreams": 0,
            "plugin_configs": 1
        },
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
    assert!(
        !kafka_validation_probe_is_registered(),
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
    for _ in 0..8 {
        let plugin = KafkaLogging::new(&kafka_validation_probe_config(), &client())
            .expect("kafka validation probe");
        assert_eq!(plugin.snapshot().generation_id, 0);
        assert!(!plugin.snapshot().accepting);
        drop(plugin);
    }
    assert!(
        !kafka_validation_probe_is_registered(),
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
        "start must not publish ACTIVE_SINKS before commit"
    );
    plugin.commit_background_tasks();
    assert!(
        plugin.owns_active_sink(),
        "successful commit must publish ACTIVE_SINKS for this instance"
    );
    let status: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(
        status.get("enabled").and_then(Value::as_bool),
        Some(true),
        "successful activation must publish ACTIVE_SINKS"
    );
    assert_eq!(status["instance_count"], 1);
    let instance = &status["instances"][0];
    assert_eq!(instance["batch"]["size"], 2);
    assert_eq!(instance["batch"]["flush_interval_ms"], 60_000);
    assert_eq!(instance["retry"]["max_attempts"], 1);
    assert_eq!(instance["retry"]["initial_delay_ms"], 1);
    assert_eq!(instance["retry"]["max_delay_ms"], 1);
    assert_eq!(instance["retry"]["jitter"], false);
    assert_eq!(instance["pricing_version"], "test-v1");

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
    assert_eq!(status_while_staged["instance_count"], 1);
    assert_eq!(
        status_while_staged["instances"][0]["pricing_version"].as_str(),
        Some("test-v1"),
        "uncommitted staged activation must not replace the live sink"
    );
    drop(staged);
    let status_after_staged_drop: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status json");
    assert_eq!(status_after_staged_drop["instance_count"], 1);
    assert_eq!(
        status_after_staged_drop["instances"][0]["pricing_version"].as_str(),
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
        "drop must clear ACTIVE_SINKS owned by this instance"
    );
    assert_eq!(status_after["instance_count"], 0);
    assert!(
        status_after["instances"]
            .as_array()
            .is_some_and(|instances| instances.is_empty())
    );
    assert_eq!(status_after["totals"]["export"]["events_enqueued_total"], 0);
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
    // ACTIVE_SINKS is process-global; assert instance ownership rather than
    // global emptiness so parallel non-lifecycle suite members cannot flake
    // this dormancy proof. Publication must wait for commit.
    assert!(
        !plugin.owns_active_sink(),
        "ACTIVE_SINKS must stay unpublished for this staged instance before commit"
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_staged_admission_covers_cache_publish_commit_gap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("publish-gap-spool");
    let plugin = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("snapshot sink");
    plugin
        .start_background_tasks()
        .expect("stage snapshot sink");

    // PluginCache publishes the staged graph immediately before invoking
    // commit_background_tasks. A concurrent reader may call the hook in that
    // interval, but no external worker or spool replay may start yet.
    plugin.log(&create_test_transaction_summary()).await;
    assert_eq!(
        chargeback_spool_rows(&spool_dir).len(),
        0,
        "staged admission must remain memory-only before commit"
    );

    plugin.commit_background_tasks();
    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&plugin).await,
        Some(true)
    );
    let rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["call_count"], 1);
    drop(plugin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_reload_before_first_tick_spools_old_generation_delta() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("reload-spool");
    let cfg = chargeback_snapshot_sink_config(&spool_dir);
    let old =
        ApiChargebackSink::new_with_config_id(&cfg, client(), "default", Some("snapshot-reload"))
            .expect("old generation");
    old.start_background_tasks().expect("start old generation");
    old.commit_background_tasks();
    old.log(&create_test_transaction_summary()).await;

    let replacement =
        ApiChargebackSink::new_with_config_id(&cfg, client(), "default", Some("snapshot-reload"))
            .expect("replacement generation");
    replacement
        .start_background_tasks()
        .expect("start replacement generation");
    replacement.commit_background_tasks();
    assert!(replacement.owns_active_sink());

    drop(old);

    let rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(
        rows.len(),
        1,
        "dropping the superseded generation before its first timer tick must durably spool one delta"
    );
    assert_eq!(rows[0]["call_count"], 1);
    assert_eq!(rows[0]["consumer_id"], "testuser");
    assert!(
        replacement.owns_active_sink(),
        "old-generation finalization must not clear the accepted replacement"
    );
    drop(replacement);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_graceful_shutdown_is_durable_idempotent_and_stops_admission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("shutdown-spool");
    let plugin = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;

    api_chargeback_sink::finalize_all_snapshot_generations().await;
    assert_eq!(
        api_chargeback_sink_snapshot_finalized_for_test(&plugin),
        Some(true)
    );
    assert_eq!(
        api_chargeback_sink_snapshot_generation_registered_for_test(&plugin),
        Some(false)
    );
    let first_rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(first_rows.len(), 1);
    assert_eq!(first_rows[0]["call_count"], 1);

    plugin.log(&create_test_transaction_summary()).await;
    api_chargeback_sink::finalize_all_snapshot_generations().await;
    assert_eq!(
        chargeback_spool_rows(&spool_dir).len(),
        1,
        "repeat shutdown and post-shutdown hooks must not duplicate or admit charges"
    );
    drop(plugin);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_finalization_deadline_bounds_in_flight_admission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("bounded-finalization-spool");
    let plugin = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;

    let started = std::time::Instant::now();
    assert_eq!(
        api_chargeback_sink_finalize_with_held_admission_for_test(
            &plugin,
            Duration::from_millis(10),
        )
        .await,
        Some(false),
        "an entered record hook must not make the finalization deadline unbounded"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the configured finalization deadline must be observed promptly"
    );
    assert_eq!(
        api_chargeback_sink_snapshot_generation_registered_for_test(&plugin),
        Some(true),
        "a timed-out finalizer must retain the generation for a later retry"
    );

    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&plugin).await,
        Some(true),
        "finalization must recover after the in-flight hook exits"
    );
    let rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["call_count"], 1);
    drop(plugin);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_tick_racing_finalization_advances_exactly_one_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("tick-first-spool");
    let tick_first = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("tick-first sink");
    tick_first
        .start_background_tasks()
        .expect("start tick-first sink");
    tick_first.commit_background_tasks();
    tick_first.log(&create_test_transaction_summary()).await;

    assert_eq!(
        api_chargeback_sink_emit_snapshot_tick_for_test(&tick_first),
        Some(Ok(1))
    );
    let tick_rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(
        tick_rows.len(),
        1,
        "a periodic tick must durably spool before advancing its baseline"
    );
    assert_eq!(tick_rows[0]["call_count"], 1);
    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&tick_first).await,
        Some(true)
    );
    assert_eq!(
        api_chargeback_sink_emit_snapshot_tick_for_test(&tick_first),
        Some(Ok(0)),
        "a timer delta published before shutdown must leave no duplicate final delta"
    );
    drop(tick_first);

    let spool_dir = tmp.path().join("final-first-spool");
    let final_first = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("final-first sink");
    final_first
        .start_background_tasks()
        .expect("start final-first sink");
    final_first.commit_background_tasks();
    final_first.log(&create_test_transaction_summary()).await;

    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&final_first).await,
        Some(true)
    );
    assert_eq!(
        api_chargeback_sink_emit_snapshot_tick_for_test(&final_first),
        Some(Ok(0)),
        "a final spool handoff must publish the baseline before a racing tick can emit"
    );
    let rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["call_count"], 1);
    drop(final_first);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_final_handoff_bypasses_full_queue_and_clickhouse_outage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("queue-pressure-spool");
    let plugin = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    for index in 0..8 {
        let mut summary = create_test_transaction_summary();
        summary.consumer_username = Some(format!("queued-{index}"));
        plugin.log(&summary).await;
    }
    assert_eq!(
        api_chargeback_sink_emit_snapshot_tick_for_test(&plugin),
        Some(Ok(8)),
        "the periodic path should contend for the one-entry logger queue"
    );

    let mut final_summary = create_test_transaction_summary();
    final_summary.consumer_username = Some("final-direct-spool".to_string());
    plugin.log(&final_summary).await;
    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&plugin).await,
        Some(true),
        "final handoff must bypass the saturated logger and unavailable endpoint"
    );
    let final_rows = chargeback_spool_rows(&spool_dir)
        .into_iter()
        .filter(|row| row["consumer_id"] == "final-direct-spool")
        .collect::<Vec<_>>();
    assert_eq!(
        final_rows.len(),
        1,
        "the post-tick delta must enter the spool exactly once"
    );
    assert_eq!(final_rows[0]["call_count"], 1);
    drop(plugin);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_spool_failure_retains_generation_for_bounded_retry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool_dir = tmp.path().join("blocked-spool");
    std::fs::write(&spool_dir, b"not a directory").expect("plant blocking file");
    let plugin = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&spool_dir),
        client(),
        "default",
    )
    .expect("snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();
    plugin.log(&create_test_transaction_summary()).await;

    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&plugin).await,
        Some(false),
        "unwritable spool must report an incomplete handoff"
    );
    assert_eq!(
        api_chargeback_sink_snapshot_finalized_for_test(&plugin),
        Some(false)
    );
    assert_eq!(
        api_chargeback_sink_snapshot_generation_registered_for_test(&plugin),
        Some(true),
        "failed handoff must retain the accumulator in the global lifecycle registry"
    );
    let failed_status: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("failed status");
    assert_eq!(failed_status["snapshot_finalizations_pending"], 1);
    assert!(
        api_chargeback_sink::render_prometheus()
            .contains("chargeback_sink_snapshot_finalizations_pending 1")
    );

    std::fs::remove_file(&spool_dir).expect("remove blocking file");
    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&plugin).await,
        Some(true),
        "a later bounded retry must durably hand off the retained delta"
    );
    assert_eq!(
        api_chargeback_sink_snapshot_generation_registered_for_test(&plugin),
        Some(false)
    );
    let recovered_status: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("recovered status");
    assert_eq!(recovered_status["snapshot_finalizations_pending"], 0);
    let rows = chargeback_spool_rows(&spool_dir);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["call_count"], 1);
    drop(plugin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_snapshot_later_reload_retries_older_retained_generation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let retained_spool = tmp.path().join("retained-spool");
    std::fs::write(&retained_spool, b"not a directory").expect("plant blocking file");
    let retained = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&retained_spool),
        client(),
        "default",
    )
    .expect("retained snapshot sink");
    retained
        .start_background_tasks()
        .expect("start retained snapshot sink");
    retained.commit_background_tasks();
    retained.log(&create_test_transaction_summary()).await;
    assert_eq!(
        api_chargeback_sink_finalize_snapshot_for_test(&retained).await,
        Some(false)
    );

    std::fs::remove_file(&retained_spool).expect("restore retained spool path");
    let replacement_spool = tmp.path().join("replacement-spool");
    let replacement = ApiChargebackSink::new(
        &chargeback_snapshot_sink_config(&replacement_spool),
        client(),
        "default",
    )
    .expect("replacement snapshot sink");
    replacement
        .start_background_tasks()
        .expect("start replacement snapshot sink");
    replacement.commit_background_tasks();

    // Production reload disposal runs on the multi-threaded gateway runtime.
    // Retiring the replacement must retry all older closed generations within
    // the same bounded drain instead of leaving them parked until shutdown.
    drop(replacement);
    assert_eq!(
        api_chargeback_sink_snapshot_generation_registered_for_test(&retained),
        Some(false)
    );
    let rows = chargeback_spool_rows(&retained_spool);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["call_count"], 1);
    drop(retained);
}

fn test_ws_disconnect_context() -> WsDisconnectContext {
    WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "proxy-ws".to_string(),
        proxy_name: Some("websocket-proxy".to_string()),
        connection_id: 1,
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend.local/chat".to_string(),
        listen_port: 8080,
        duration_ms: 250.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 8,
        bytes_backend_to_client: 8,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: Some("alice".to_string()),
        auth_method: None,
        metadata: HashMap::new(),
        proxy_lifecycle_generation: None,
    }
}

/// Pre-start admission must drop rather than panic or enqueue (issue #2616).
#[tokio::test]
async fn ws_logging_drops_queued_entries_before_start() {
    let plugin = WsLogging::new(&ws_sink_config(), client()).expect("ws");
    plugin.log(&create_test_transaction_summary()).await;
    plugin
        .on_stream_disconnect(&create_test_stream_transaction_summary())
        .await;
    plugin.on_ws_disconnect(&test_ws_disconnect_context()).await;
}

/// Staged WS workers must exit the flush loop when dropped without commit.
#[tokio::test]
async fn ws_logging_staged_drop_exits_flush_loop_without_commit() {
    let plugin = WsLogging::new(&ws_sink_config(), client()).expect("ws");
    plugin.start_background_tasks().expect("stage ws worker");
    // Do not commit — Drop closes the commit gate so flush_loop returns early.
    drop(plugin);
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Never-started chargeback instances keep diagnostics/admission closed.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_pre_start_commit_and_enqueue_are_noops() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let plugin =
        ApiChargebackSink::new(&chargeback_sink_config(&tmp), client(), "default").expect("cb");
    assert!(
        !plugin.owns_active_sink(),
        "validation/construction objects must not own ACTIVE_SINKS"
    );
    plugin.commit_background_tasks();
    assert!(
        !plugin.owns_active_sink(),
        "commit before start must remain a no-op"
    );
    plugin.log(&create_test_transaction_summary()).await;
    assert!(
        !tmp.path().join("spool").exists(),
        "pre-start enqueue must not create spool state"
    );
}

#[test]
fn chargeback_rejects_empty_and_nul_spool_dir_shape() {
    let mut empty = chargeback_sink_config(&tempfile::tempdir().expect("tempdir"));
    empty["spool"]["dir"] = json!("");
    let err = ApiChargebackSink::new(&empty, client(), "default")
        .err()
        .expect("empty spool.dir must fail shape validation");
    assert!(
        err.contains("spool.dir") && err.contains("empty"),
        "expected empty spool.dir error, got: {err}"
    );

    let mut nul = chargeback_sink_config(&tempfile::tempdir().expect("tempdir"));
    nul["spool"]["dir"] = json!("spool\u{0000}dir");
    let err = ApiChargebackSink::new(&nul, client(), "default")
        .err()
        .expect("NUL spool.dir must fail shape validation");
    assert!(
        err.contains("spool.dir") && err.contains("NUL"),
        "expected NUL spool.dir error, got: {err}"
    );
}

/// Kafka finalize/commit before activation must stay silent no-ops.
#[tokio::test]
async fn kafka_finalize_and_commit_before_start_are_noops() {
    let plugin = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    assert_eq!(plugin.snapshot().generation_id, 0);
    plugin.commit_background_tasks();
    plugin.finalize().await;
    assert_eq!(plugin.snapshot().generation_id, 0);
    assert!(!plugin.snapshot().accepting);
}

/// Dropping a started generation off-runtime must close admission without
/// requiring a Tokio context (reload/abandoned-instance path).
#[tokio::test]
async fn kafka_drop_without_runtime_closes_uncommitted_generation() {
    let plugin = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    plugin
        .start_background_tasks()
        .expect("kafka start under tokio");
    let generation_id = plugin.snapshot().generation_id;
    assert!(generation_id >= 1);
    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "uncommitted generation must stay unpublished"
    );

    std::thread::spawn(move || drop(plugin))
        .join()
        .expect("join kafka drop thread");

    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "no-runtime Drop must unregister generation {generation_id}"
    );
}

/// Multi-thread Drop finalizes an un-finalized live generation in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kafka_drop_on_multi_thread_runtime_finalizes_generation() {
    let plugin = KafkaLogging::new(&kafka_sink_config(), &client()).expect("kafka");
    plugin
        .start_background_tasks()
        .expect("kafka start under tokio");
    plugin.commit_background_tasks();
    let generation_id = plugin.snapshot().generation_id;
    assert!(
        ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "commit must publish generation {generation_id}"
    );

    drop(plugin);

    assert!(
        !ferrum_edge::plugins::kafka_logging::snapshots()
            .iter()
            .any(|snap| snap.generation_id == generation_id),
        "multi-thread Drop must finalize and unregister generation {generation_id}"
    );
}

/// Producer construction failures during start restore pending activation so
/// retries remain possible and secrets stay out of the error string.
#[tokio::test]
async fn kafka_start_restores_pending_when_producer_create_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing_cert = tmp.path().join("missing-client.pem");
    let missing_key = tmp.path().join("missing-client.key");
    let cfg = json!({
        "broker_list": "127.0.0.1:9092",
        "topic": "ferrum-logs",
        "security_protocol": "ssl",
        "ssl_no_verify": true,
        "ssl_certificate_location": missing_cert.to_string_lossy(),
        "ssl_key_location": missing_key.to_string_lossy(),
    });

    let plugin = match KafkaLogging::new(&cfg, &client()) {
        Ok(plugin) => plugin,
        Err(error) => {
            // Native config validation may reject missing material before start,
            // and librdkafka versions disagree on whether the rejection names a
            // TLS property or reports the bounded client-config category. Either
            // way, preserve the fail-closed/redacted construction contract. Builds
            // that defer the rejection continue below to exercise activate/restore.
            assert!(
                error.contains("failed to validate Kafka producer config"),
                "construction failure must retain the bounded validation context: {error}"
            );
            assert!(
                !error.contains(missing_cert.to_string_lossy().as_ref())
                    && !error.contains(missing_key.to_string_lossy().as_ref()),
                "construction failure must not echo TLS material paths: {error}"
            );
            return;
        }
    };

    let err = plugin
        .start_background_tasks()
        .expect_err("missing client cert/key must fail producer create");
    assert!(
        err.contains("failed to create Kafka producer"),
        "activate must classify producer create failure without echoing paths: {err}"
    );
    assert!(
        !err.contains(missing_cert.to_string_lossy().as_ref()),
        "error must not echo certificate path: {err}"
    );

    // Pending activation must be restored so a later start can retry.
    let retry_err = plugin.start_background_tasks();
    assert!(
        retry_err.is_err(),
        "restored pending activation must remain retryable (still missing material)"
    );
}

fn chargeback_sink_config_for_id(tmp: &tempfile::TempDir, id: &str) -> Value {
    let mut cfg = chargeback_sink_config(tmp);
    cfg["spool"]["dir"] = json!(tmp.path().join(format!("spool-{id}")).to_string_lossy());
    cfg["pricing_version"] = json!(format!("pricing-{id}"));
    cfg["clickhouse"]["table"] = json!(format!("charges_{id}"));
    cfg
}

fn status_instance_ids(status: &Value) -> Vec<(String, u64)> {
    status["instances"]
        .as_array()
        .expect("instances array")
        .iter()
        .map(|instance| {
            (
                instance["plugin_config_id"]
                    .as_str()
                    .expect("plugin_config_id")
                    .to_string(),
                instance["generation"].as_u64().expect("generation"),
            )
        })
        .collect()
}

/// Two accepted sinks must coexist in status/metrics with deterministic ordering.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_two_accepted_instances_render_deterministically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "alpha"),
        client(),
        "default",
        Some("sink-alpha"),
    )
    .expect("alpha");
    let b = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "bravo"),
        client(),
        "default",
        Some("sink-bravo"),
    )
    .expect("bravo");

    a.start_background_tasks().expect("start alpha");
    b.start_background_tasks().expect("start bravo");
    assert!(!a.owns_active_sink());
    assert!(!b.owns_active_sink());

    // Commit bravo first; ordering must still sort by plugin_config_id.
    b.commit_background_tasks();
    a.commit_background_tasks();
    assert!(a.owns_active_sink());
    assert!(b.owns_active_sink());

    let status: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(status["enabled"], true);
    assert_eq!(status["instance_count"], 2);
    let ids = status_instance_ids(&status);
    assert_eq!(
        ids.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        vec!["sink-alpha", "sink-bravo"],
        "instances must render in ascending plugin_config_id order: {ids:?}"
    );
    assert_eq!(status["instances"][0]["pricing_version"], "pricing-alpha");
    assert_eq!(status["instances"][1]["pricing_version"], "pricing-bravo");
    assert_eq!(
        status["instances"][0]["clickhouse"]["table"],
        "charges_alpha"
    );
    assert_eq!(
        status["instances"][1]["clickhouse"]["table"],
        "charges_bravo"
    );

    let gen_a = a.active_generation().expect("alpha generation");
    let gen_b = b.active_generation().expect("bravo generation");
    assert_ne!(gen_a, gen_b);

    let prom = api_chargeback_sink::render_prometheus();
    assert!(
        prom.lines()
            .any(|line| line == "chargeback_sink_events_enqueued_total 0"),
        "missing process-wide aggregate counter:\n{prom}"
    );
    assert!(
        !prom.contains("plugin_config_id=") && !prom.contains("generation="),
        "generation labels would create reload-driven time-series churn:\n{prom}"
    );

    drop(a);
    drop(b);
}

/// Dropping either accepted instance removes only that exact ID/generation.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_removing_either_instance_preserves_sibling() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let first = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "one"),
        client(),
        "default",
        Some("sink-one"),
    )
    .expect("one");
    let second = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "two"),
        client(),
        "default",
        Some("sink-two"),
    )
    .expect("two");
    first.start_background_tasks().expect("start one");
    second.start_background_tasks().expect("start two");
    first.commit_background_tasks();
    second.commit_background_tasks();

    let gen_one = first.active_generation().expect("gen one");
    let gen_two = second.active_generation().expect("gen two");

    drop(first);
    let after_first: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(after_first["instance_count"], 1);
    assert_eq!(after_first["instances"][0]["plugin_config_id"], "sink-two");
    assert_eq!(after_first["instances"][0]["generation"], gen_two);
    assert!(
        second.owns_active_sink(),
        "sibling must keep its exact published generation"
    );
    assert!(
        !api_chargeback_sink::render_prometheus().is_empty(),
        "the surviving sibling must keep aggregate metrics enabled"
    );

    // Recreate first with a new generation; dropping second must leave the new first.
    let first_again = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "one"),
        client(),
        "default",
        Some("sink-one"),
    )
    .expect("one again");
    first_again
        .start_background_tasks()
        .expect("start one again");
    first_again.commit_background_tasks();
    let gen_one_again = first_again.active_generation().expect("gen one again");
    assert_ne!(gen_one_again, gen_one);

    drop(second);
    let after_second: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(after_second["instance_count"], 1);
    assert_eq!(after_second["instances"][0]["plugin_config_id"], "sink-one");
    assert_eq!(after_second["instances"][0]["generation"], gen_one_again);
    drop(first_again);
}

/// A newly accepted generation replaces the prior view for the same stable ID,
/// and dropping the old in-flight generation must not clear the replacement.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_replacement_generation_is_current_and_exact_drop_safe() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let old = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "old"),
        client(),
        "default",
        Some("sink-reload"),
    )
    .expect("old generation");
    old.start_background_tasks().expect("start old generation");
    old.commit_background_tasks();
    let old_generation = old.active_generation().expect("old generation id");

    let new = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "new"),
        client(),
        "default",
        Some("sink-reload"),
    )
    .expect("new generation");
    new.start_background_tasks().expect("start new generation");
    new.commit_background_tasks();
    let new_generation = new.active_generation().expect("new generation id");
    assert_ne!(old_generation, new_generation);

    let current: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(current["instance_count"], 1);
    assert_eq!(current["instances"][0]["plugin_config_id"], "sink-reload");
    assert_eq!(current["instances"][0]["generation"], new_generation);
    assert_eq!(current["instances"][0]["pricing_version"], "pricing-new");

    drop(old);
    let after_old_drop: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(after_old_drop["instance_count"], 1);
    assert_eq!(
        after_old_drop["instances"][0]["generation"], new_generation,
        "dropping the superseded runtime must not clear the accepted replacement"
    );

    drop(new);
}

/// Admin/config validation throwaways must not mutate a live accepted view.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_validation_while_live_sink_preserves_status() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let live = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "live"),
        client(),
        "default",
        Some("sink-live"),
    )
    .expect("live");
    live.start_background_tasks().expect("start live");
    live.commit_background_tasks();
    let live_gen = live.active_generation().expect("live gen");

    let before: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(before["instance_count"], 1);
    assert_eq!(before["instances"][0]["generation"], live_gen);

    // Shape-only validation constructs and drops without start/commit.
    let throwaway = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "validate"),
        client(),
        "default",
        Some("sink-validate"),
    )
    .expect("validation construct");
    assert!(!throwaway.owns_active_sink());
    drop(throwaway);

    let after_validate: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(after_validate, before);

    // validate_plugin_config also constructs+drops through the shared pipeline.
    ferrum_edge::plugins::validate_plugin_config(
        "api_chargeback_sink",
        &chargeback_sink_config_for_id(&tmp, "pipeline"),
    )
    .expect("pipeline validation");
    let after_pipeline: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(after_pipeline["instance_count"], 1);
    assert_eq!(
        after_pipeline["instances"][0]["plugin_config_id"],
        "sink-live"
    );
    assert_eq!(after_pipeline["instances"][0]["generation"], live_gen);

    drop(live);
}

/// Rejected staged reload must not publish or clear sibling accepted sinks.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_rejected_reload_after_staging_preserves_live() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let live = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "accepted"),
        client(),
        "default",
        Some("sink-accepted"),
    )
    .expect("accepted");
    live.start_background_tasks().expect("start accepted");
    live.commit_background_tasks();
    let live_gen = live.active_generation().expect("live gen");

    let staged = ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config_for_id(&tmp, "rejected"),
        client(),
        "default",
        Some("sink-rejected"),
    )
    .expect("rejected candidate");
    staged
        .start_background_tasks()
        .expect("stage rejected candidate");
    assert!(
        !staged.owns_active_sink(),
        "staged candidate must stay unpublished before commit"
    );
    let status_while_staged: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(status_while_staged["instance_count"], 1);
    assert_eq!(
        status_while_staged["instances"][0]["plugin_config_id"],
        "sink-accepted"
    );
    assert_eq!(status_while_staged["instances"][0]["generation"], live_gen);

    // Simulate cache rejecting the staged generation: drop without commit.
    drop(staged);
    let after_reject: Value =
        serde_json::from_str(&api_chargeback_sink::render_status_json()).expect("status");
    assert_eq!(after_reject["instance_count"], 1);
    assert_eq!(
        after_reject["instances"][0]["plugin_config_id"],
        "sink-accepted"
    );
    assert_eq!(after_reject["instances"][0]["generation"], live_gen);
    assert!(live.owns_active_sink());

    drop(live);
}

#[test]
fn chargeback_rejects_blank_plugin_config_id() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let err = match ApiChargebackSink::new_with_config_id(
        &chargeback_sink_config(&tmp),
        client(),
        "default",
        Some("   "),
    ) {
        Ok(_) => panic!("blank plugin config id must fail closed"),
        Err(error) => error,
    };
    assert!(
        err.contains("plugin config id") && err.contains("non-empty"),
        "unexpected error: {err}"
    );
}
