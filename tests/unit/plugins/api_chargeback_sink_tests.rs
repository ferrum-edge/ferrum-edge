use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ferrum_edge::plugins::api_chargeback_sink::{
    ApiChargebackSink, ApiChargebackSinkConfig, ChargeEvent, PEER_REPUBLISH_MARKER,
    QuotaEvictionReport, SnapshotAccumulator, SpoolCompression, SpoolFinalOwnership, SpoolFsFault,
    SpoolManager, SpoolOwnerSpec, SpoolSettings, SpoolWriteHookPoint,
    classify_clickhouse_acknowledgement_for_tests, classify_clickhouse_http_status_for_tests,
    clickhouse_insert_url_for_tests, compact_recovery_probe_for_tests, decode_spool_file_for_tests,
    encode_spool_bytes_for_tests, encode_spool_bytes_without_content_size_for_tests, new_ulid,
    probe_charge_body_materialization_for_tests, probe_compact_recovery_retry_for_tests,
    render_prometheus, render_status_json, replay_spool_once_for_tests,
    replay_spool_once_with_batch_size_for_tests, replay_spool_once_with_ceiling_for_tests,
    serialize_json_each_row, set_spool_write_hook_for_tests, spool_artifact_byte_limit_for_tests,
    spool_claim_lease_secs_for_tests, spool_decompression_limit_for_tests,
    spool_index_entry_bytes_for_tests, spool_replay_peak_bytes_for_tests,
    spool_split_worklist_max_entries_for_tests, write_private_file_atomically_for_tests,
    write_private_file_atomically_with_fault_for_tests,
};
use ferrum_edge::plugins::chargeback::pricing::{ChargeComputation, MAX_UNIT_PRICE, PricingConfig};
use ferrum_edge::plugins::utils::byte_budget::RetainedByteCeiling;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, REQUEST_ID_METADATA_KEY, TransactionSummary, WsDisconnectContext,
};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn valid_config(spool_dir: &Path) -> Value {
    json!({
        "mode": "per_event",
        "clickhouse": {
            "url": "http://localhost:8123",
            "database": "ferrum",
            "table": "charges_raw",
            "timeout_ms": 1000
        },
        "batch": {"size": 2, "flush_interval_ms": 60000, "buffer_capacity": 10},
        "retry": {"max_attempts": 1, "initial_delay_ms": 1, "max_delay_ms": 1, "jitter": false},
        "spool": {
            "enabled": true,
            "dir": spool_dir.to_string_lossy().to_string(),
            "max_bytes": 1048576,
            "replay_interval_secs": 3600,
            "compression": "none"
        },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "bandwidth_pricing": {"price_per_byte_sent": 0.000001, "price_per_byte_received": 0.000002},
        "stream_connection_pricing": {"price_per_connection": 0.1},
        "pricing_version": "test-v1",
        "currency": "USD"
    })
}

fn sample_event(id: &str) -> ChargeEvent {
    ChargeEvent {
        event_id: id.to_string(),
        received_at: 1_774_000_000_000_000_000,
        node_id: "node-a".to_string(),
        namespace: "ferrum".to_string(),
        consumer_id: "alice".to_string(),
        consumer_name: None,
        proxy_id: "proxy-a".to_string(),
        proxy_name: "Payments".to_string(),
        route_id: None,
        status_code: 200,
        http_status_code: Some(200),
        grpc_status: None,
        protocol: "http".to_string(),
        call_count: 1,
        charge_call: 0.01,
        bytes_sent: 100,
        bytes_received: 200,
        charge_bytes_sent: 0.0001,
        charge_bytes_received: 0.0004,
        charge_total: 0.0105,
        currency: "USD".to_string(),
        pricing_version: "test-v1".to_string(),
        request_id: Some("req-1".to_string()),
        trace_id: None,
        snapshot_id: None,
    }
}

fn grpc_summary(proxy_id: &str, grpc_status: &str) -> TransactionSummary {
    let mut summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        consumer_username: Some("alice".to_string()),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some("gRPC API".to_string()),
        response_status_code: 200,
        ..TransactionSummary::default()
    };
    summary
        .metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    summary
        .metadata
        .insert("grpc_status".to_string(), grpc_status.to_string());
    summary
}

fn http_summary_with_dims(
    proxy_id: &str,
    proxy_name: &str,
    route_id: Option<&str>,
    consumer_name: Option<&str>,
    protocol: &str,
    status: u16,
) -> TransactionSummary {
    let mut summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        consumer_username: Some("alice".to_string()),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some(proxy_name.to_string()),
        response_status_code: status,
        ..TransactionSummary::default()
    };
    if protocol != "http" {
        summary
            .metadata
            .insert("request_protocol".to_string(), protocol.to_string());
    }
    if let Some(route_id) = route_id {
        summary
            .metadata
            .insert("route_id".to_string(), route_id.to_string());
    }
    if let Some(consumer_name) = consumer_name {
        summary
            .metadata
            .insert("consumer_name".to_string(), consumer_name.to_string());
    }
    summary
}

fn unit_call_charge(price: f64) -> ChargeComputation {
    ChargeComputation {
        call_count: 1,
        charge_call: price,
        charge_total: price,
        ..ChargeComputation::default()
    }
}

fn snapshot_test_config() -> ApiChargebackSinkConfig {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    config
}

async fn wait_for_requests(server: &MockServer, at_least: usize) -> Vec<wiremock::Request> {
    for _ in 0..40 {
        if let Some(requests) = server.received_requests().await
            && requests.len() >= at_least
        {
            return requests;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("mock server did not receive {at_least} request(s)");
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn grpc_per_event_exports_billable_and_raw_terminal_statuses() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(server.uri());
    config["batch"]["size"] = json!(1);
    config["pricing_tiers"] = json!([
        {"status_codes": [200], "price_per_call": 0.01},
        {"status_codes": [503], "price_per_call": 0.09}
    ]);
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin.start_background_tasks().expect("chargeback start");

    plugin.commit_background_tasks();
    plugin.log(&grpc_summary("grpc-ok", "0")).await;
    plugin.log(&grpc_summary("grpc-unavailable", "14")).await;

    let requests = wait_for_requests(&server, 2).await;
    let mut events: Vec<Value> = requests
        .iter()
        .map(|request| request.body_json().expect("charge event JSON"))
        .collect();
    events.sort_by_key(|event| event["status_code"].as_u64());

    assert_eq!(events[0]["status_code"], 200);
    assert_eq!(events[0]["http_status_code"], 200);
    assert_eq!(events[0]["grpc_status"], 0);
    assert!((events[0]["charge_call"].as_f64().unwrap() - 0.01).abs() < 1e-12);

    assert_eq!(events[1]["status_code"], 503);
    assert_eq!(events[1]["http_status_code"], 200);
    assert_eq!(events[1]["grpc_status"], 14);
    assert!((events[1]["charge_call"].as_f64().unwrap() - 0.09).abs() < 1e-12);
}

#[test]
fn grpc_snapshot_keeps_terminal_statuses_that_share_a_billing_bucket_separate() {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    let accumulator = SnapshotAccumulator::new();
    let charge = ChargeComputation {
        call_count: 1,
        charge_call: 0.08,
        charge_total: 0.08,
        ..ChargeComputation::default()
    };

    accumulator.record_http_for_test(&grpc_summary("grpc-shared-500", "2"), "alice", charge);
    accumulator.record_http_for_test(&grpc_summary("grpc-shared-500", "13"), "alice", charge);

    let mut events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-grpc")
        .unwrap();
    events.sort_by_key(|event| event.grpc_status);
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.status_code == 500 && event.http_status_code == Some(200))
    );
    assert_eq!(events[0].grpc_status, Some(2));
    assert_eq!(events[1].grpc_status, Some(13));
}

#[test]
fn grpc_snapshot_bounds_non_standard_terminal_status_cardinality() {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    let accumulator = SnapshotAccumulator::new();
    let charge = ChargeComputation {
        call_count: 1,
        charge_call: 0.08,
        charge_total: 0.08,
        ..ChargeComputation::default()
    };

    accumulator.record_http_for_test(&grpc_summary("grpc-nonstandard", "17"), "alice", charge);
    accumulator.record_http_for_test(&grpc_summary("grpc-nonstandard", "18"), "alice", charge);

    let events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-grpc")
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status_code, 500);
    assert_eq!(events[0].http_status_code, Some(200));
    assert_eq!(events[0].grpc_status, Some(u32::MAX));
    assert_eq!(events[0].call_count, 2);
}

#[tokio::test]
async fn config_validation_accepts_valid_config() {
    let temp = tempfile::tempdir().unwrap();
    let plugin = ApiChargebackSink::new(
        &valid_config(temp.path()),
        PluginHttpClient::default(),
        "ferrum",
    )
    .unwrap();

    assert_eq!(plugin.name(), "api_chargeback_sink");
    assert_eq!(plugin.priority(), 9351);
}

#[tokio::test]
async fn config_validation_rejects_bad_shapes() {
    let temp = tempfile::tempdir().unwrap();
    for config in [
        json!(null),
        json!({"clickhouse": {"url": "tcp://localhost:9000"}}),
        json!({"clickhouse": {"url": "http://user:pass@localhost:8123"}}),
        json!({"clickhouse": {"url": "http://localhost:8123"}, "batch": {"size": 0}}),
        json!({"clickhouse": {"url": "http://localhost:8123"}, "batch": {"buffer_capacity": 0}}),
        json!({"clickhouse": {"url": "http://localhost:8123"}, "snapshot": {"interval_secs": 0}}),
        json!({"clickhouse": {"url": "http://localhost:8123"}, "schema": {}}),
        {
            let mut cfg = valid_config(temp.path());
            cfg["unexpected"] = json!(true);
            cfg
        },
    ] {
        assert!(
            ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").is_err(),
            "expected config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn config_validation_rejects_batch_and_retry_clamp_candidates() {
    let temp = tempfile::tempdir().unwrap();
    for (path, value) in [
        ("batch.size", json!(10_001)),
        ("batch.size", json!(100_000)),
        ("batch.buffer_capacity", json!(1_000_001)),
        ("batch.flush_interval_ms", json!(600_001)),
        ("retry.max_attempts", json!(0)),
        ("retry.max_attempts", json!(33)),
        ("retry.max_attempts", json!(4_294_967_295u64)),
        ("retry.initial_delay_ms", json!(60_001)),
        ("retry.max_delay_ms", json!(60_001)),
    ] {
        let mut config = valid_config(temp.path());
        match path {
            "batch.size" => config["batch"]["size"] = value.clone(),
            "batch.buffer_capacity" => config["batch"]["buffer_capacity"] = value.clone(),
            "batch.flush_interval_ms" => config["batch"]["flush_interval_ms"] = value.clone(),
            "retry.max_attempts" => config["retry"]["max_attempts"] = value.clone(),
            "retry.initial_delay_ms" => config["retry"]["initial_delay_ms"] = value.clone(),
            "retry.max_delay_ms" => {
                config["retry"]["initial_delay_ms"] = json!(0);
                config["retry"]["max_delay_ms"] = value.clone();
            }
            _ => unreachable!(),
        }
        let err = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum")
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {path}={value}"));
        assert!(
            err.contains(path),
            "expected field-specific error for {path}={value}, got {err}"
        );
    }

    let mut ok = valid_config(temp.path());
    ok["batch"]["size"] = json!(10_000);
    ok["batch"]["buffer_capacity"] = json!(1);
    ok["batch"]["flush_interval_ms"] = json!(600_000);
    ok["retry"]["max_attempts"] = json!(1);
    assert!(
        ApiChargebackSink::new(&ok, PluginHttpClient::default(), "ferrum").is_ok(),
        "valid batch/retry boundaries must be admitted"
    );

    let mut ok_max = valid_config(temp.path());
    ok_max["retry"]["max_attempts"] = json!(32);
    ok_max["retry"]["initial_delay_ms"] = json!(0);
    ok_max["retry"]["max_delay_ms"] = json!(0);
    assert!(
        ApiChargebackSink::new(&ok_max, PluginHttpClient::default(), "ferrum").is_ok(),
        "max_attempts=32 with zero delays must be admitted"
    );

    // Exact worst-case cumulative budget boundary: 10 sleeps × 60000 ms = 600000.
    let mut exact_budget = valid_config(temp.path());
    exact_budget["retry"] = json!({
        "max_attempts": 11,
        "initial_delay_ms": 60_000,
        "max_delay_ms": 60_000,
        "jitter": false
    });
    assert!(
        ApiChargebackSink::new(&exact_budget, PluginHttpClient::default(), "ferrum").is_ok(),
        "exact 600000 ms cumulative delay budget must be admitted"
    );

    // One inter-attempt sleep over the budget: 11 × 60000 = 660000.
    let mut over_budget = valid_config(temp.path());
    over_budget["retry"] = json!({
        "max_attempts": 12,
        "initial_delay_ms": 60_000,
        "max_delay_ms": 60_000,
        "jitter": false
    });
    let over_err = ApiChargebackSink::new(&over_budget, PluginHttpClient::default(), "ferrum")
        .err()
        .expect("one-over cumulative delay budget must be rejected");
    assert!(
        over_err.contains("600000")
            && (over_err.contains("retry.max_attempts")
                || over_err.contains("retry.initial_delay_ms")
                || over_err.contains("retry.max_delay_ms")),
        "over-budget error must name the budget and retry fields; got {over_err}"
    );

    let mut delay_ceiling = valid_config(temp.path());
    delay_ceiling["retry"]["max_attempts"] = json!(2);
    delay_ceiling["retry"]["initial_delay_ms"] = json!(60_000);
    delay_ceiling["retry"]["max_delay_ms"] = json!(60_000);
    assert!(
        ApiChargebackSink::new(&delay_ceiling, PluginHttpClient::default(), "ferrum").is_ok(),
        "individual delay ceiling of 60000 ms must be admitted"
    );
}

#[tokio::test]
async fn config_validation_rejects_snapshot_without_spool() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["mode"] = json!("snapshot");
    config["spool"]["enabled"] = json!(false);

    let error = match ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum") {
        Ok(_) => panic!("snapshot mode without spool should be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("snapshot mode requires spool.enabled=true"));
}

#[test]
fn maximum_prices_remain_finite_in_per_event_and_snapshot_exports() {
    let config = json!({
        "pricing_tiers": [{"status_codes": [200], "price_per_call": MAX_UNIT_PRICE}],
        "bandwidth_pricing": {
            "price_per_byte_sent": MAX_UNIT_PRICE,
            "price_per_byte_received": MAX_UNIT_PRICE
        },
        "stream_connection_pricing": {"price_per_connection": MAX_UNIT_PRICE}
    });
    let pricing = PricingConfig::from_config(&config, "api_chargeback_sink").unwrap();

    let http_charge = pricing
        .compute_http(200, u64::MAX, u64::MAX)
        .expect("maximum HTTP prices should produce a charge");
    let stream_charge = pricing
        .compute_stream(u64::MAX, u64::MAX)
        .expect("maximum stream prices should produce a charge");
    for charge in [http_charge, stream_charge] {
        assert!(charge.charge_call.is_finite());
        assert!(charge.charge_bytes_sent.is_finite());
        assert!(charge.charge_bytes_received.is_finite());
        assert!(charge.charge_total.is_finite());
    }

    let mut per_event = sample_event("maximum-price-per-event");
    per_event.call_count = u64::from(http_charge.call_count);
    per_event.charge_call = http_charge.charge_call;
    per_event.bytes_sent = http_charge.bytes_sent;
    per_event.bytes_received = http_charge.bytes_received;
    per_event.charge_bytes_sent = http_charge.charge_bytes_sent;
    per_event.charge_bytes_received = http_charge.charge_bytes_received;
    per_event.charge_total = http_charge.charge_total;
    let per_event_json: Value =
        serde_json::from_str(&serialize_json_each_row(std::slice::from_ref(&per_event)).unwrap())
            .unwrap();
    for field in [
        "charge_call",
        "charge_bytes_sent",
        "charge_bytes_received",
        "charge_total",
    ] {
        assert!(
            per_event_json[field]
                .as_f64()
                .is_some_and(|value| value.is_finite()),
            "per-event {field} must serialize as a finite JSON number"
        );
    }

    let mut snapshot_config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    snapshot_config.currency = "USD".to_string();
    snapshot_config.pricing_version = "maximum-price".to_string();
    let accumulator = SnapshotAccumulator::new();
    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        http_charge,
    );
    let events = accumulator
        .compute_deltas(
            &snapshot_config,
            "node-a",
            1_774_000_000_000_000_000,
            "maximum-price-snapshot",
        )
        .unwrap();
    assert_eq!(events.len(), 1);
    let snapshot_json: Value =
        serde_json::from_str(&serialize_json_each_row(&events).unwrap()).unwrap();
    for field in [
        "charge_call",
        "charge_bytes_sent",
        "charge_bytes_received",
        "charge_total",
    ] {
        assert!(
            snapshot_json[field]
                .as_f64()
                .is_some_and(|value| value.is_finite()),
            "snapshot {field} must serialize as a finite JSON number"
        );
    }
}

#[test]
fn sink_rejects_above_maximum_prices_in_both_export_modes() {
    let temp = tempfile::tempdir().unwrap();
    let above_maximum = f64::from_bits(MAX_UNIT_PRICE.to_bits() + 1);

    for mode in ["per_event", "snapshot"] {
        for field in [
            "price_per_call",
            "price_per_byte_sent",
            "price_per_byte_received",
            "price_per_connection",
        ] {
            let mut config = valid_config(temp.path());
            config["mode"] = json!(mode);
            match field {
                "price_per_call" => {
                    config["pricing_tiers"][0]["price_per_call"] = json!(above_maximum);
                }
                "price_per_byte_sent" => {
                    config["bandwidth_pricing"]["price_per_byte_sent"] = json!(above_maximum);
                }
                "price_per_byte_received" => {
                    config["bandwidth_pricing"]["price_per_byte_received"] = json!(above_maximum);
                }
                "price_per_connection" => {
                    config["stream_connection_pricing"]["price_per_connection"] =
                        json!(above_maximum);
                }
                _ => unreachable!(),
            }

            let error = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum")
                .err()
                .unwrap_or_else(|| panic!("{mode} should reject {field} above MAX_UNIT_PRICE"));
            assert!(
                error.contains(field) && error.contains("no greater than"),
                "unexpected {mode} rejection for {field}: {error}"
            );
        }
    }
}

#[tokio::test]
async fn password_ref_requires_https_clickhouse_url() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!("http://localhost:8123");
    config["clickhouse"]["password_ref"] = json!("FERRUM_CLICKHOUSE_PASSWORD");

    let error = match ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum") {
        Ok(_) => panic!("password_ref over http should be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("password_ref requires clickhouse.url to use https://"));
}

#[tokio::test]
async fn password_ref_rejects_disabled_tls_verification() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!("https://localhost:8443");
    config["clickhouse"]["password_ref"] = json!("FERRUM_CLICKHOUSE_PASSWORD");
    config["clickhouse"]["tls"] = json!({ "insecure_skip_verify": true });

    let error = match ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum") {
        Ok(_) => panic!("password_ref with insecure_skip_verify should be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("password_ref cannot be used when ClickHouse TLS"));
}

/// Issue #2627: OpenAPI must reject the same required/cross-field failures the
/// constructor rejects, and admit each minimal valid pricing shape.
#[tokio::test]
async fn openapi_schema_matches_runtime_admission_boundaries() {
    use ferrum_edge::plugins::validate_plugin_config;

    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let sink_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/ApiChargebackSinkConfig",
        "components": spec["components"].clone()
    });
    let sink_validator = jsonschema::draft202012::options()
        .build(&sink_schema)
        .expect("ApiChargebackSinkConfig schema compiles");
    let plugin_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/PluginConfig",
        "components": spec["components"].clone()
    });
    let plugin_validator = jsonschema::draft202012::options()
        .build(&plugin_schema)
        .expect("PluginConfig schema compiles");

    // Disable the default on-disk spool so runtime admission does not depend on
    // creating /var/lib/ferrum/chargeback-spool in the unit-test environment.
    let minimal_pricing_shapes = [
        json!({
            "clickhouse": { "url": "https://clickhouse.example:8443" },
            "spool": { "enabled": false },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
        }),
        json!({
            "clickhouse": { "url": "https://clickhouse.example:8443" },
            "spool": { "enabled": false },
            "bandwidth_pricing": {"price_per_byte_sent": 0.000001}
        }),
        json!({
            "clickhouse": { "url": "https://clickhouse.example:8443" },
            "spool": { "enabled": false },
            "bandwidth_pricing": {"price_per_byte_received": 0.000002}
        }),
        json!({
            "clickhouse": { "url": "https://clickhouse.example:8443" },
            "spool": { "enabled": false },
            "stream_connection_pricing": {"price_per_connection": 0.1}
        }),
        json!({
            "clickhouse": {
                "url": "http://clickhouse.example:8123",
                "password_ref": "   "
            },
            "spool": { "enabled": false },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
        }),
        json!({
            "clickhouse": { "url": "HTTPS://clickhouse.example:8443" },
            "spool": { "enabled": false },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
        }),
    ];
    for config in &minimal_pricing_shapes {
        assert!(
            sink_validator.validate(config).is_ok(),
            "minimal pricing shape should be schema-valid: {config}"
        );
        assert!(
            validate_plugin_config("api_chargeback_sink", config).is_ok(),
            "minimal pricing shape should pass runtime admission: {config}"
        );
    }

    let missing_config_entry = json!({
        "plugin_name": "api_chargeback_sink",
        "scope": "global",
        "enabled": true
    });
    assert!(
        plugin_validator.validate(&missing_config_entry).is_err(),
        "PluginConfig must require config for api_chargeback_sink"
    );
    let complete_entry = json!({
        "plugin_name": "api_chargeback_sink",
        "scope": "global",
        "enabled": true,
        "config": {
            "clickhouse": { "url": "https://clickhouse.example:8443" },
            "spool": { "enabled": false },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
        }
    });
    assert!(
        plugin_validator.validate(&complete_entry).is_ok(),
        "PluginConfig must accept a runtime-valid api_chargeback_sink entry"
    );

    let schema_and_runtime_invalid = [
        (
            "missing clickhouse",
            json!({
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
        ("empty config object", json!({})),
        (
            "clickhouse without pricing",
            json!({
                "clickhouse": { "url": "https://clickhouse.example:8443" },
                "spool": { "enabled": false }
            }),
        ),
        (
            "zero-only bandwidth pricing",
            json!({
                "clickhouse": { "url": "https://clickhouse.example:8443" },
                "spool": { "enabled": false },
                "bandwidth_pricing": {
                    "price_per_byte_sent": 0.0,
                    "price_per_byte_received": 0.0
                }
            }),
        ),
        (
            "zero-only stream pricing",
            json!({
                "clickhouse": { "url": "https://clickhouse.example:8443" },
                "spool": { "enabled": false },
                "stream_connection_pricing": { "price_per_connection": 0.0 }
            }),
        ),
        (
            "snapshot without spool",
            json!({
                "mode": "snapshot",
                "spool": { "enabled": false },
                "clickhouse": { "url": "https://clickhouse.example:8443" },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
        (
            "password_ref over http",
            json!({
                "clickhouse": {
                    "url": "http://clickhouse.example:8123",
                    "password_ref": "FERRUM_CLICKHOUSE_PASSWORD"
                },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
        (
            "password_ref with insecure_skip_verify",
            json!({
                "clickhouse": {
                    "url": "https://clickhouse.example:8443",
                    "password_ref": "FERRUM_CLICKHOUSE_PASSWORD",
                    "tls": { "insecure_skip_verify": true }
                },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
        (
            "password_ref with verify_hostname disabled",
            json!({
                "clickhouse": {
                    "url": "https://clickhouse.example:8443",
                    "password_ref": "FERRUM_CLICKHOUSE_PASSWORD",
                    "tls": { "verify_hostname": false }
                },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
        (
            "url with user-info",
            json!({
                "clickhouse": { "url": "https://user:pass@clickhouse.example:8443" },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
        (
            "url without host",
            json!({
                "clickhouse": { "url": "https://?query=1" },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]
            }),
        ),
    ];
    for (label, config) in schema_and_runtime_invalid {
        assert!(
            sink_validator.validate(&config).is_err(),
            "{label} must be schema-invalid: {config}"
        );
        assert!(
            validate_plugin_config("api_chargeback_sink", &config).is_err(),
            "{label} must be runtime-rejected: {config}"
        );
    }

    // OpenAPI cannot express max_delay_ms >= initial_delay_ms or the cumulative
    // inter-attempt delay budget; document and cover both layers so inverted /
    // over-budget retry bounds stay constructor-gated. Individual delay maxima
    // are schema-enforced at 60000 ms.
    for (label, config) in [
        (
            "initial_delay_ms over individual ceiling",
            json!({
                "clickhouse": { "url": "https://clickhouse.example:8443" },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
                "retry": { "initial_delay_ms": 60_001, "max_delay_ms": 60_001 }
            }),
        ),
        (
            "max_delay_ms over individual ceiling",
            json!({
                "clickhouse": { "url": "https://clickhouse.example:8443" },
                "spool": { "enabled": false },
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
                "retry": { "initial_delay_ms": 0, "max_delay_ms": 60_001 }
            }),
        ),
    ] {
        assert!(
            sink_validator.validate(&config).is_err(),
            "{label} must be schema-invalid: {config}"
        );
        assert!(
            validate_plugin_config("api_chargeback_sink", &config).is_err(),
            "{label} must be runtime-rejected: {config}"
        );
    }

    let inverted_retry = json!({
        "clickhouse": { "url": "https://clickhouse.example:8443" },
        "spool": { "enabled": false },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "retry": {
            "initial_delay_ms": 1000,
            "max_delay_ms": 100
        }
    });
    assert!(
        sink_validator.validate(&inverted_retry).is_ok(),
        "inverted retry bounds remain schema-admitted when OpenAPI cannot compare fields"
    );
    let retry_err = validate_plugin_config("api_chargeback_sink", &inverted_retry)
        .expect_err("inverted retry bounds must fail runtime admission");
    assert!(
        retry_err.contains("retry.max_delay_ms must be >= retry.initial_delay_ms"),
        "unexpected retry admission error: {retry_err}"
    );

    let over_budget = json!({
        "clickhouse": { "url": "https://clickhouse.example:8443" },
        "spool": { "enabled": false },
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "retry": {
            "max_attempts": 12,
            "initial_delay_ms": 60_000,
            "max_delay_ms": 60_000,
            "jitter": false
        }
    });
    assert!(
        sink_validator.validate(&over_budget).is_ok(),
        "cumulative delay budget remains schema-admitted when OpenAPI cannot compute the schedule"
    );
    let budget_err = validate_plugin_config("api_chargeback_sink", &over_budget)
        .expect_err("over-budget retry must fail runtime admission");
    assert!(
        budget_err.contains("600000"),
        "unexpected cumulative budget error: {budget_err}"
    );
}

#[tokio::test]
async fn password_ref_must_use_ferrum_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    // https so the prefix check is reached rather than the https-required guard.
    config["clickhouse"]["url"] = json!("https://localhost:8123");
    config["clickhouse"]["password_ref"] = json!("PATH");

    let error = match ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum") {
        Ok(_) => panic!("non-FERRUM password_ref should be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("password_ref must reference a FERRUM_*"));
}

#[tokio::test]
async fn rejects_clickhouse_identifier_injection() {
    let temp = tempfile::tempdir().unwrap();
    for bad in [
        "charges_raw; DROP TABLE x",
        "charges raw",
        "charges`raw",
        "charges_raw FORMAT TSV",
    ] {
        let mut config = valid_config(temp.path());
        config["clickhouse"]["table"] = json!(bad);
        let error = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum")
            .err()
            .unwrap_or_else(|| panic!("table '{bad}' should be rejected"));
        assert!(
            error.contains("may only contain"),
            "unexpected error for table '{bad}': {error}"
        );
    }
}

#[test]
fn json_each_row_serialization_is_line_delimited_and_omits_none() {
    let events = vec![sample_event("evt-1"), sample_event("evt-2")];
    let body = serialize_json_each_row(&events).unwrap();

    assert!(!body.ends_with('\n'));
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["event_id"], "evt-1");
    assert_eq!(first["status_code"], 200);
    assert_eq!(first["http_status_code"], 200);
    assert!(first.get("consumer_name").is_none());
    assert!(first.get("grpc_status").is_none());
    assert!(first.get("trace_id").is_none());
}

#[test]
fn json_each_row_rejects_non_finite_monetary_fields() {
    let mut event = sample_event("non-finite-event");
    event.charge_total = f64::INFINITY;

    let error = serialize_json_each_row(std::slice::from_ref(&event)).unwrap_err();
    assert!(error.contains("charge_total"), "unexpected error: {error}");
    assert!(error.contains("non-finite"), "unexpected error: {error}");
}

#[test]
fn snapshot_delta_rejects_non_finite_state_instead_of_substituting_zero() {
    let config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    let accumulator = SnapshotAccumulator::new();
    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        ChargeComputation {
            call_count: 1,
            charge_call: f64::INFINITY,
            charge_total: f64::INFINITY,
            ..ChargeComputation::default()
        },
    );

    let error = accumulator
        .compute_deltas(&config, "node-a", 100, "non-finite-snapshot")
        .unwrap_err();
    assert!(error.contains("charge_call"), "unexpected error: {error}");
    assert!(error.contains("non-finite"), "unexpected error: {error}");
}

#[test]
fn snapshot_delta_computation_tracks_last_emitted_totals() {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.snapshot.emit_zero_deltas = false;
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    let accumulator = SnapshotAccumulator::new();

    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        ChargeComputation {
            call_count: 3,
            charge_call: 0.03,
            bytes_sent: 100,
            bytes_received: 200,
            charge_bytes_sent: 0.1,
            charge_bytes_received: 0.2,
            charge_total: 0.33,
        },
    );
    let first = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-1")
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].call_count, 3);
    assert_eq!(first[0].bytes_received, 200);

    let second = accumulator
        .compute_deltas(&config, "node-a", 200, "snap-2")
        .unwrap();
    assert!(second.is_empty());

    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        ChargeComputation {
            call_count: 2,
            charge_call: 0.02,
            bytes_sent: 50,
            bytes_received: 25,
            charge_bytes_sent: 0.05,
            charge_bytes_received: 0.025,
            charge_total: 0.095,
        },
    );
    let third = accumulator
        .compute_deltas(&config, "node-a", 300, "snap-3")
        .unwrap();
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].call_count, 2);
    assert_eq!(third[0].bytes_sent, 50);

    config.snapshot.emit_zero_deltas = true;
    let zero = accumulator
        .compute_deltas(&config, "node-a", 400, "snap-4")
        .unwrap();
    assert_eq!(zero.len(), 1);
    assert_eq!(zero[0].call_count, 0);
    assert_eq!(zero[0].snapshot_id.as_deref(), Some("snap-4"));
}

fn encoded_event_len(event: &ChargeEvent, compression: SpoolCompression) -> u64 {
    let body = serialize_json_each_row(std::slice::from_ref(event)).unwrap();
    encode_spool_bytes_for_tests(body.as_bytes(), compression)
        .unwrap()
        .len() as u64
}

fn spool_settings(dir: &Path, max_bytes: u64) -> SpoolSettings {
    SpoolSettings {
        enabled: true,
        dir: dir.to_path_buf(),
        max_bytes,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    }
}

/// Owner identity matching `SpoolManager::for_tests`.
fn test_owner_spec(node_id: &str) -> SpoolOwnerSpec<'_> {
    SpoolOwnerSpec {
        node_id,
        plugin_config_id: "test-plugin",
        ferrum_namespace: "ferrum",
        destination_endpoint: "http://127.0.0.1:8123",
        database: "ferrum",
        table: "charges_raw",
    }
}

fn default_test_namespace_root(spool_dir: &Path) -> std::path::PathBuf {
    SpoolManager::namespace_root_path_for_tests(spool_dir, &test_owner_spec("node-a")).unwrap()
}

fn default_test_owner_tag() -> String {
    SpoolManager::owner_tag_of_spec_for_tests(&test_owner_spec("node-a"))
}

/// Durable spool file name for the default test owner.
fn owned_data_name(ulid: &str) -> String {
    format!("{ulid}.{}.ndjson", default_test_owner_tag())
}

fn find_spool_namespace_root(spool_dir: &Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![spool_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("spool.meta.json") {
                return path.parent().map(|p| p.to_path_buf());
            }
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    None
}

fn disk_owned_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name == "spool.meta.json" {
                continue;
            }
            let is_temp = name.ends_with(".tmp")
                && (name.contains(".write-")
                    || name.ends_with(".ndjson.tmp")
                    || name.ends_with(".ndjson.zst.tmp")
                    || name.ends_with(".rejected.meta.tmp"));
            let owned = name.ends_with(".inflight")
                || is_temp
                || name.ends_with(".ndjson.corrupt")
                || name.ends_with(".ndjson.zst.corrupt")
                || name.ends_with(".ndjson.rejected.meta")
                || name.ends_with(".ndjson.zst.rejected.meta")
                || ((name.ends_with(".ndjson.zst") || name.ends_with(".ndjson"))
                    && !name.ends_with(".tmp")
                    && !name.ends_with(".corrupt")
                    && !name.ends_with(".rejected")
                    && !name.ends_with(".meta")
                    && !name.ends_with(".inflight"));
            if owned {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

#[test]
fn spool_write_round_trip_and_oldest_eviction() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-001");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    assert_eq!(
        encoded_len,
        encoded_event_len(&sample_event("evt-002"), SpoolCompression::None),
        "fixture event ids must encode to equal sizes"
    );
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();

    let first = spool.write_events(std::slice::from_ref(&event)).unwrap();
    let decoded = decode_spool_file_for_tests(&first).unwrap();
    assert_eq!(
        decoded,
        serialize_json_each_row(std::slice::from_ref(&event)).unwrap()
    );

    let second = spool.write_events(&[sample_event("evt-002")]).unwrap();
    assert!(second.exists());
    assert!(
        !first.exists(),
        "oldest spool file should be evicted before second write"
    );
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
    assert_eq!(
        stats.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        "status bytes must match on-disk owned usage"
    );
}

#[test]
fn spool_rejects_empty_spool_oversized_batch() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-oversized");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len.saturating_sub(1).max(1),
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let err = spool
        .write_events(std::slice::from_ref(&event))
        .expect_err("one-byte-over batch must be rejected on an empty spool");
    assert!(
        err.contains("exceeds spool.max_bytes")
            || err.contains("cannot fit within spool.max_bytes"),
        "unexpected error: {err}"
    );
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
    assert_eq!(
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        0
    );
}

#[test]
fn spool_admits_exact_fit_and_rejects_one_byte_over_with_resident_file() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-ex-1");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    assert_eq!(
        encoded_len,
        encoded_event_len(&sample_event("evt-ex-2"), SpoolCompression::None)
    );
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let path = spool.write_events(std::slice::from_ref(&event)).unwrap();
    assert!(path.exists());
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
    assert_eq!(
        stats.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path()))
    );

    // With the resident file still present, a second write of the same size must
    // evict first (exact fit after eviction), not exceed the ceiling.
    let second = spool.write_events(&[sample_event("evt-ex-2")]).unwrap();
    assert!(second.exists());
    assert!(!path.exists());
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
}

#[test]
fn spool_quota_uses_compressed_encoded_size() {
    let temp = tempfile::tempdir().unwrap();
    // Pad the event id so the uncompressed body is large enough that zstd
    // typically changes the on-disk size versus the raw JSONEachRow bytes.
    let event = sample_event(&format!("evt-zstd-{}", "x".repeat(2048)));
    let encoded_len = encoded_event_len(&event, SpoolCompression::Zstd);
    let uncompressed_len = encoded_event_len(&event, SpoolCompression::None);
    assert_ne!(
        encoded_len, uncompressed_len,
        "fixture should produce a distinct compressed size so quota uses encoded bytes"
    );

    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::Zstd,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let path = spool.write_events(std::slice::from_ref(&event)).unwrap();
    assert!(path.exists());
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
    assert_eq!(
        stats.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path()))
    );

    // Using the uncompressed length as the ceiling must not be how admission
    // decides: when compressed size exceeds an artificially smaller budget,
    // the write is rejected.
    let over = SpoolSettings {
        enabled: true,
        dir: temp.path().join("over"),
        max_bytes: encoded_len.saturating_sub(1).max(1),
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::Zstd,
    };
    let over_spool = SpoolManager::for_tests(over, "node-a").unwrap();
    let err = over_spool
        .write_events(std::slice::from_ref(&event))
        .expect_err("compressed one-byte-over must reject");
    assert!(err.contains("exceeds spool.max_bytes") || err.contains("cannot fit"));
}

#[test]
fn spool_accounts_corrupt_files_toward_quota_and_can_evict_them() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-after-corrupt");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let corrupt_dir = default_test_namespace_root(temp.path()).join("20260524");
    fs::create_dir_all(&corrupt_dir).unwrap();
    let corrupt = corrupt_dir.join("00000000000000000000000000.ndjson.corrupt");
    fs::write(&corrupt, vec![0u8; encoded_len as usize]).unwrap();

    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let before = spool.scan_stats().unwrap();
    assert_eq!(before.files, 1);
    assert_eq!(before.bytes, encoded_len);
    assert_eq!(
        before.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path()))
    );

    let written = spool.write_events(std::slice::from_ref(&event)).unwrap();
    assert!(written.exists());
    assert!(
        !corrupt.exists(),
        "oldest owned corrupt file must be evictable to admit a new write"
    );
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
}

#[test]
fn spool_reconciles_stale_tmp_files_at_startup() {
    let temp = tempfile::tempdir().unwrap();
    let day = default_test_namespace_root(temp.path()).join("20260524");
    fs::create_dir_all(&day).unwrap();
    let stale_tmp = day.join("00000000000000000000000001.ndjson.tmp");
    fs::write(&stale_tmp, vec![0u8; 4096]).unwrap();

    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 1024 * 1024,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    assert!(
        !stale_tmp.exists(),
        "startup must delete crash-left spool temp files"
    );
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
    assert_eq!(
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        0
    );
}

#[test]
fn spool_counts_tmp_files_toward_quota_before_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-tmp-budget");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let day = default_test_namespace_root(temp.path()).join("20260524");
    fs::create_dir_all(&day).unwrap();
    let stale_tmp = day.join("00000000000000000000000001.ndjson.tmp");
    fs::write(&stale_tmp, vec![0u8; encoded_len as usize]).unwrap();

    // Construct without going through for_tests' reconcile by using a second
    // manager after manually recreating a temp that appears between scans:
    // first manager cleans startup temps; then plant a temp and assert accounting
    // via scan_stats before the next write admission path removes oldest owned.
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    assert!(
        !stale_tmp.exists(),
        "startup reconcile should clear planted tmp"
    );

    fs::write(&stale_tmp, vec![0u8; encoded_len as usize]).unwrap();
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
    assert_eq!(
        stats.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path()))
    );

    let written = spool.write_events(std::slice::from_ref(&event)).unwrap();
    assert!(written.exists());
    assert!(
        !stale_tmp.exists(),
        "admission eviction must drop owned temp files when they block the ceiling"
    );
    let after = spool.scan_stats().unwrap();
    assert_eq!(after.files, 1);
    assert_eq!(after.bytes, encoded_len);
}

#[test]
fn quota_eviction_reclaims_multiple_files_in_one_inventory_pass() {
    let temp = tempfile::tempdir().unwrap();
    let file_len = 64u64;
    let file_count = 10u64;
    // Keep room for two resident files after reclaim; admitting one more
    // file_len requires deleting eight oldest files from one snapshot.
    let max_bytes = file_len.saturating_mul(3);
    let settings = spool_settings(temp.path(), max_bytes);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let mut planted = Vec::new();
    for index in 0..file_count {
        let path = day.join(owned_data_name(&format!(
            "000000000000000000000000{index:02}"
        )));
        fs::write(&path, vec![b'x'; file_len as usize]).unwrap();
        planted.push(path);
    }
    let before = spool.scan_stats().unwrap();
    assert_eq!(before.files, file_count);
    assert_eq!(before.bytes, file_len.saturating_mul(file_count));

    let report = spool
        .evict_until_can_admit_for_tests(file_len)
        .expect("multi-file reclaim must succeed from one inventory");
    assert_eq!(
        report,
        QuotaEvictionReport {
            inventory_passes: 1,
            files_inventoried: file_count,
            bytes_before: file_len.saturating_mul(file_count),
            files_deleted: 8,
            bytes_freed: file_len.saturating_mul(8),
        },
        "eviction must inventory/sort once and delete enough files in that pass"
    );

    for (index, path) in planted.iter().enumerate() {
        if index < 8 {
            assert!(
                !path.exists(),
                "oldest planted file {index} must be reclaimed"
            );
        } else {
            assert!(
                path.exists(),
                "newest planted file {index} must be retained"
            );
        }
    }
    let after = spool.scan_stats().unwrap();
    assert_eq!(after.files, 2);
    assert_eq!(after.bytes, file_len.saturating_mul(2));
    assert!(
        after.bytes.saturating_add(file_len) <= max_bytes,
        "remaining owned bytes must leave room for the incoming batch"
    );
}

#[test]
fn quota_eviction_large_file_count_still_uses_one_planning_pass() {
    let temp = tempfile::tempdir().unwrap();
    let file_len = 32u64;
    // Large enough to prove reclaim work is not O(K) inventory passes, small
    // enough for deterministic CI unit coverage (not a local benchmark).
    let file_count = 1_024u64;
    let max_bytes = file_len.saturating_mul(4);
    // remaining + incoming <= max_bytes => remaining <= 3 * file_len.
    let retain_after = 3u64;
    let expected_deleted = file_count.saturating_sub(retain_after);
    let settings = spool_settings(temp.path(), max_bytes);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    for index in 0..file_count {
        let path = day.join(owned_data_name(&format!(
            "01ARZ3NDEKTSV4RRFFQ69G{index:05}"
        )));
        fs::write(&path, vec![b'y'; file_len as usize]).unwrap();
    }

    let report = spool
        .evict_until_can_admit_for_tests(file_len)
        .expect("large spool reclaim must succeed");
    assert_eq!(
        report.inventory_passes, 1,
        "large file-count eviction must still be one inventory/sort planning pass"
    );
    assert_eq!(report.files_inventoried, file_count);
    assert_eq!(report.bytes_before, file_len.saturating_mul(file_count));
    assert_eq!(report.files_deleted, expected_deleted);
    assert_eq!(
        report.bytes_freed,
        file_len.saturating_mul(expected_deleted)
    );

    let after = spool.scan_stats().unwrap();
    assert_eq!(after.files, retain_after);
    assert_eq!(after.bytes, file_len.saturating_mul(retain_after));
    assert!(
        after.bytes.saturating_add(file_len) <= max_bytes,
        "post-eviction usage must admit the planned incoming batch"
    );
}

/// Lexicographically ordered owned data-file name for quota-eviction fixtures.
fn planted_spool_name(index: u64) -> String {
    owned_data_name(&format!("000000000000000000000000{index:02}"))
}

/// Clears the process-global spool write hook even if the test panics.
struct ClearSpoolWriteHookGuard;

impl Drop for ClearSpoolWriteHookGuard {
    fn drop(&mut self) {
        set_spool_write_hook_for_tests(None);
    }
}

/// A peer sharing the volume removes a selected candidate and replaces it with
/// files the stale snapshot never saw.
///
/// Crediting the vanished candidate's snapshot size would let admission stop
/// early with the peer's replacement bytes unaccounted, leaving on-disk usage
/// above `spool.max_bytes`. The eviction must instead refresh the inventory and
/// keep reclaiming until the *observed* tree leaves room.
#[test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
fn quota_eviction_refreshes_inventory_when_a_candidate_disappears() {
    let temp = tempfile::tempdir().unwrap();
    let file_len = 64u64;
    let file_count = 10u64;
    let max_bytes = file_len.saturating_mul(3);
    let settings = spool_settings(temp.path(), max_bytes);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let mut planted = Vec::new();
    for index in 0..file_count {
        let path = day.join(planted_spool_name(index));
        fs::write(&path, vec![b'x'; file_len as usize]).unwrap();
        planted.push(path);
    }
    // Sort after every planted name, so the peer replacements are the newest
    // entries and are only reclaimed after the originals.
    let peers: Vec<_> = [50u64, 51u64]
        .into_iter()
        .map(|index| day.join(planted_spool_name(index)))
        .collect();

    let _clear_hook = ClearSpoolWriteHookGuard;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let vanishing = planted[0].clone();
    let peers_for_hook = peers.clone();
    let hook_root = spool.namespace_root_for_tests().to_path_buf();
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, namespace_root| {
        if point != SpoolWriteHookPoint::QuotaInventoryTaken {
            return;
        }
        // The hook slot is process-global and the test binary runs in parallel:
        // a concurrent test's eviction must not consume this test's one-shot
        // mutation or inflate its pass accounting.
        if namespace_root != hook_root.as_path() {
            return;
        }
        if calls_for_hook.fetch_add(1, Ordering::SeqCst) != 0 {
            return;
        }
        // The first snapshot is already taken: unlink the oldest candidate and
        // add two files that snapshot can never account for.
        fs::remove_file(&vanishing).expect("peer removes the selected candidate");
        for peer in &peers_for_hook {
            fs::write(peer, vec![b'p'; file_len as usize]).expect("peer writes a replacement");
        }
    })));

    let report = spool
        .evict_until_can_admit_for_tests(file_len)
        .expect("eviction must refresh and succeed rather than fail closed");
    set_spool_write_hook_for_tests(None);

    assert_eq!(
        report,
        QuotaEvictionReport {
            // One stale pass plus the refreshed pass that actually decides.
            inventory_passes: 2,
            // 10 in the stale snapshot, then 9 survivors + 2 peer replacements.
            files_inventoried: 21,
            bytes_before: file_len.saturating_mul(file_count),
            // Only files this call actually unlinked; the vanished candidate is
            // never counted as reclaimed work.
            files_deleted: 9,
            bytes_freed: file_len.saturating_mul(9),
        },
        "a disappearing candidate must force a refreshed inventory, not a stale byte credit"
    );

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "exactly the stale pass and the refreshed pass may plan deletions"
    );
    for path in &planted {
        assert!(!path.exists(), "every original must be reclaimed or gone");
    }
    for peer in &peers {
        assert!(
            peer.exists(),
            "newest peer replacements must be retained, not over-evicted"
        );
    }
    let after = spool.scan_stats().unwrap();
    assert_eq!(after.files, 2);
    assert_eq!(after.bytes, file_len.saturating_mul(2));
    assert_eq!(
        after.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path()))
    );
    // The load-bearing invariant: crediting the vanished candidate would have
    // stopped eviction with 4 files (256 bytes) resident and admitted anyway.
    assert!(
        after.bytes.saturating_add(file_len) <= max_bytes,
        "admission must never leave on-disk owned usage above spool.max_bytes"
    );
}

/// A namespace that keeps mutating under eviction must fail closed rather than
/// admit on numbers no pass ever observed as consistent.
#[test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
fn quota_eviction_fails_closed_when_the_inventory_never_stabilizes() {
    let temp = tempfile::tempdir().unwrap();
    let file_len = 64u64;
    let file_count = 10u64;
    let max_bytes = file_len.saturating_mul(3);
    let settings = spool_settings(temp.path(), max_bytes);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let mut planted = Vec::new();
    for index in 0..file_count {
        let path = day.join(planted_spool_name(index));
        fs::write(&path, vec![b'x'; file_len as usize]).unwrap();
        planted.push(path);
    }

    let _clear_hook = ClearSpoolWriteHookGuard;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let day_for_hook = day.clone();
    let hook_root = spool.namespace_root_for_tests().to_path_buf();
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, namespace_root| {
        if point != SpoolWriteHookPoint::QuotaInventoryTaken {
            return;
        }
        // The hook slot is process-global and the test binary runs in parallel:
        // a concurrent test's eviction must not advance this test's generation
        // counter, which is what bounds the asserted pass budget.
        if namespace_root != hook_root.as_path() {
            return;
        }
        // Replace the whole observed generation on every pass. Deleting a
        // guessed planted filename was ordering-sensitive: if that path was
        // not the next eviction candidate, the old fixture could shrink below
        // the quota and legitimately admit instead of exercising the bounded
        // stale-inventory refusal.
        let generation = calls_for_hook.fetch_add(1, Ordering::SeqCst) as u64;
        for entry in fs::read_dir(&day_for_hook).expect("peer inventories current generation") {
            let path = entry.expect("peer reads generation entry").path();
            if path.is_file() {
                fs::remove_file(path).expect("peer replaces current generation");
            }
        }
        let replacement_base = 1_000u64.saturating_add(generation.saturating_mul(file_count));
        for offset in 0..file_count {
            let path =
                day_for_hook.join(planted_spool_name(replacement_base.saturating_add(offset)));
            fs::write(path, vec![b'x'; file_len as usize])
                .expect("peer writes replacement generation");
        }
    })));

    let error = spool
        .evict_until_can_admit_for_tests(file_len)
        .expect_err("a perpetually mutating namespace must refuse admission");
    set_spool_write_hook_for_tests(None);

    assert!(
        error.contains("spool changed concurrently during 8 quota inventory passes"),
        "refusal must name the bounded pass budget: {error}"
    );
    assert!(
        error.contains("refusing to admit encoded batch (64 bytes)"),
        "refusal must name the batch it declined: {error}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        8,
        "refresh must be bounded at 8 inventory passes, not unbounded"
    );
    // Eviction itself unlinked nothing from any snapshot: it broke to refresh
    // on every pass and then declined. The peer's final complete generation
    // remains, so capacity never happened to fall below the quota mid-test.
    for path in &planted {
        assert!(
            !path.exists(),
            "the peer must replace the planted generation"
        );
    }
    let after = spool.scan_stats().unwrap();
    assert_eq!(after.files, file_count);
    assert_eq!(after.bytes, file_len.saturating_mul(file_count));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_spool_writes_do_not_fail_during_eviction() {
    let temp = tempfile::tempdir().unwrap();
    let probe = sample_event("evt-00");
    let encoded_len = encoded_event_len(&probe, SpoolCompression::None);
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: encoded_len,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = Arc::new(SpoolManager::for_tests(settings, "node-a").unwrap());
    let mut handles = Vec::new();
    for idx in 0..24 {
        let spool = Arc::clone(&spool);
        handles.push(tokio::task::spawn_blocking(move || {
            spool.write_events(&[sample_event(&format!("evt-{idx:02}"))])
        }));
    }

    for handle in handles {
        handle.await.unwrap().unwrap();
    }
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, encoded_len);
    assert_eq!(
        stats.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        "status bytes must match on-disk owned usage after concurrent writes"
    );
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn prometheus_counts_quarantined_owned_spool_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(server.uri());
    let corrupt_bytes = 256u64;
    let byte_line = format!("chargeback_sink_spool_bytes {corrupt_bytes}\n");

    // ACTIVE_SINKS is process-global; retry briefly if a parallel sink test races
    // the published runtime between construction and scrape.
    let mut matched_prom = None;
    let mut held_plugin = None;
    for _ in 0..20 {
        let plugin =
            ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
        plugin.start_background_tasks().expect("chargeback start");
        plugin.commit_background_tasks();
        // Committed spool preparation is intentionally asynchronous: the
        // replayer wakes on the publication gate and creates/probes live
        // storage on its first tick. Validation and pre-commit staging must
        // not create this directory.
        let mut namespace_root = None;
        for _ in 0..200 {
            namespace_root = find_spool_namespace_root(temp.path());
            if namespace_root.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let namespace_root = namespace_root
            .expect("committed spool should create a managed namespace with spool.meta.json");
        let day = namespace_root.join("20260524");
        fs::create_dir_all(&day).unwrap();
        let corrupt = day.join("00000000000000000000000000.ndjson.corrupt");
        fs::write(&corrupt, vec![0u8; corrupt_bytes as usize]).unwrap();

        let prom = render_prometheus();
        if prom.contains(&byte_line) {
            matched_prom = Some(prom);
            held_plugin = Some(plugin);
            break;
        }
        drop(plugin);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let prom = matched_prom.expect(
        "ACTIVE_SINKS never observed this sink's quarantined owned bytes in prometheus output",
    );
    assert!(
        prom.contains(
            "# HELP chargeback_sink_spool_bytes Chargeback sink on-disk owned spool bytes (active, temp, corrupt, and dead-lettered files)."
        ),
        "prometheus HELP must describe the owned-byte ceiling contract"
    );
    assert!(
        prom.contains(
            "# HELP chargeback_sink_spool_files Chargeback sink on-disk owned spool file count (active, temp, corrupt, and dead-lettered files)."
        ),
        "prometheus HELP must describe owned file accounting"
    );
    assert!(
        prom.contains("chargeback_sink_spool_files 1\n"),
        "prometheus must count quarantined files toward spool.files; got:\n{prom}"
    );
    assert!(
        prom.contains("chargeback_sink_spool_available 1\n"),
        "prepared committed spool must report available; got:\n{prom}"
    );
    assert!(
        prom.contains("chargeback_sink_spool_prepare_failures_total 0\n"),
        "healthy committed spool must have no preparation failures; got:\n{prom}"
    );
    assert_eq!(
        disk_owned_bytes(temp.path()),
        corrupt_bytes,
        "on-disk owned usage must include the planted .corrupt file"
    );
    drop(held_plugin);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn committed_unusable_spool_latches_status_and_metric_failure() {
    let temp = tempfile::tempdir().unwrap();
    let blocked = temp.path().join("not-a-directory");
    fs::write(&blocked, b"file blocks spool directory creation").unwrap();
    let config = valid_config(&blocked);
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();

    plugin
        .start_background_tasks()
        .expect("stage chargeback sink");
    plugin.commit_background_tasks();

    let mut status = Value::Null;
    for _ in 0..200 {
        status = serde_json::from_str(&render_status_json()).expect("status json");
        if status["instances"][0]["spool"]["prepare_failures_total"]
            .as_u64()
            .is_some_and(|failures| failures > 0)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(status["enabled"], true);
    assert_eq!(status["instance_count"], 1);
    assert_eq!(status["instances"][0]["spool"]["enabled"], true);
    assert_eq!(status["instances"][0]["spool"]["available"], false);
    assert!(
        status["instances"][0]["spool"]["prepare_failures_total"]
            .as_u64()
            .is_some_and(|failures| failures > 0),
        "committed unusable spool must retain operational failure evidence: {status}"
    );
    assert_eq!(status["totals"]["spool"]["available"], false);
    assert!(
        status["totals"]["spool"]["prepare_failures_total"]
            .as_u64()
            .is_some_and(|failures| failures > 0)
    );

    let prometheus = render_prometheus();
    assert!(prometheus.contains("chargeback_sink_spool_available 0\n"));
    let failures = prometheus
        .lines()
        .find_map(|line| {
            line.strip_prefix("chargeback_sink_spool_prepare_failures_total ")
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or(0);
    assert!(
        failures > 0,
        "missing persistent failure counter:\n{prometheus}"
    );
}

#[cfg(unix)]
#[test]
fn spool_reconcile_fails_closed_when_stale_tmp_cannot_be_removed() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let day = default_test_namespace_root(temp.path()).join("20260524");
    fs::create_dir_all(&day).unwrap();
    let stale_tmp = day.join("00000000000000000000000001.ndjson.tmp");
    fs::write(&stale_tmp, vec![0u8; 128]).unwrap();

    // Remove directory write bits so unlink of the planted temp fails. Startup
    // must fail closed rather than ignore an undeletable owned temp.
    let mut perms = fs::metadata(&day).unwrap().permissions();
    perms.set_mode(0o555);
    fs::set_permissions(&day, perms).unwrap();

    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 1024 * 1024,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let err = match SpoolManager::for_tests(settings, "node-a") {
        Ok(_) => panic!("undeletable stale tmp must fail spool startup"),
        Err(err) => err,
    };
    assert!(
        err.contains("failed to remove stale spool temp file"),
        "unexpected error: {err}"
    );
    assert!(
        stale_tmp.exists(),
        "fail-closed reconcile must leave the undeletable temp in place"
    );

    // Restore writability so TempDir cleanup can succeed.
    let mut perms = fs::metadata(&day).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&day, perms).unwrap();
}

#[test]
fn failed_atomic_spool_write_removes_tmp_and_does_not_publish() {
    let temp = tempfile::tempdir().unwrap();
    let final_path = temp.path().join("batch.ndjson");
    let tmp_path = temp.path().join("batch.ndjson.tmp");
    // Block rename so the write path reaches the error-cleanup branch after the
    // temp body has already been created.
    fs::create_dir(&final_path).unwrap();

    let err = write_private_file_atomically_for_tests(
        &tmp_path,
        &final_path,
        b"{\"ok\":true}\n",
        SpoolFinalOwnership::Unique,
    )
    .expect_err("rename onto a directory must fail the atomic publish");
    assert!(
        err.contains("failed to rename spool temp file"),
        "unexpected error: {err}"
    );
    assert!(
        !tmp_path.exists(),
        "failed atomic write must delete the leftover *.tmp so it cannot evade quota"
    );
    assert!(
        final_path.is_dir(),
        "failed publish must not replace the blocking path with a data file"
    );
}

#[tokio::test]
async fn replay_quarantines_corrupt_spool_file_and_continues() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 1024 * 1024,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let corrupt_dir = default_test_namespace_root(temp.path()).join("20260524");
    fs::create_dir_all(&corrupt_dir).unwrap();
    let corrupt_name = owned_data_name("00000000000000000000000000");
    let corrupt = corrupt_dir.join(&corrupt_name);
    fs::write(&corrupt, [0xff, 0xfe, 0xfd]).unwrap();
    let valid = spool.write_events(&[sample_event("evt-good")]).unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();

    assert!(
        !valid.exists(),
        "valid spool file should replay and be removed"
    );
    assert!(
        corrupt
            .with_file_name(format!("{corrupt_name}.corrupt"))
            .exists(),
        "corrupt spool file should be quarantined under its durable data name"
    );
    let requests = wait_for_requests(&server, 1).await;
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8(requests[0].body.clone()).unwrap();
    assert!(body.contains("evt-good"));
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn websocket_disconnect_exports_bandwidth_charge() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(server.uri());
    config["batch"]["size"] = json!(1);
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin.start_background_tasks().expect("chargeback start");
    plugin.commit_background_tasks();
    assert!(plugin.requires_ws_disconnect_hooks());

    plugin
        .on_ws_disconnect(&WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: "ws-proxy".to_string(),
            proxy_lifecycle_generation: None,
            proxy_name: Some("WS Proxy".to_string()),
            client_ip: "127.0.0.1".to_string(),
            backend_target: "http://127.0.0.1:9000/ws".to_string(),
            listen_port: 8000,
            duration_ms: 10.0,
            frames_client_to_backend: 1,
            frames_backend_to_client: 1,
            bytes_client_to_backend: 300,
            bytes_backend_to_client: 400,
            timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
            timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
            direction: None,
            io_side: None,
            error_class: None,
            consumer_username: Some("alice".to_string()),
            auth_method: None,
            connection_id: 0,
            metadata: Default::default(),
        })
        .await;

    let requests = wait_for_requests(&server, 1).await;
    let body: Value = requests[0].body_json().unwrap();
    assert_eq!(body["protocol"], "ws");
    assert_eq!(body["bytes_sent"], 300);
    assert_eq!(body["bytes_received"], 400);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn connect_method_is_not_classified_as_websocket() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(server.uri());
    config["batch"]["size"] = json!(1);
    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin.start_background_tasks().expect("chargeback start");

    plugin.commit_background_tasks();
    plugin
        .log(&TransactionSummary {
            namespace: "ferrum".to_string(),
            consumer_username: Some("alice".to_string()),
            http_method: "CONNECT".to_string(),
            proxy_id: Some("proxy-a".to_string()),
            proxy_name: Some("Proxy A".to_string()),
            response_status_code: 200,
            bytes_sent: 10,
            bytes_received: 20,
            ..TransactionSummary::default()
        })
        .await;

    let requests = wait_for_requests(&server, 1).await;
    let body: Value = requests[0].body_json().unwrap();
    assert_eq!(body["protocol"], "http");
    assert_eq!(body["status_code"], 200);
    assert_eq!(body["http_status_code"], 200);
    assert!(body.get("grpc_status").is_none());
}

#[test]
fn snapshot_cleanup_removes_idle_entries_and_last_emitted() {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    let accumulator = SnapshotAccumulator::new();
    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        ChargeComputation {
            call_count: 1,
            charge_call: 0.01,
            bytes_sent: 10,
            bytes_received: 20,
            charge_bytes_sent: 0.01,
            charge_bytes_received: 0.02,
            charge_total: 0.04,
        },
    );
    assert_eq!(
        accumulator
            .compute_deltas(&config, "node-a", 100, "snap-1")
            .unwrap()
            .len(),
        1
    );

    assert_eq!(accumulator.cleanup_stale_for_tests(0), 1);
    assert!(
        accumulator
            .compute_deltas(&config, "node-a", 200, "snap-2")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn snapshot_cleanup_preserves_unrelated_key_and_new_generation_baseline() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    let charge = unit_call_charge(0.01);

    accumulator.record_for_test(
        "ferrum", "alice", "proxy-a", "Payments", 200, "http", charge,
    );
    accumulator.record_for_test("ferrum", "bob", "proxy-b", "Billing", 200, "http", charge);
    assert_eq!(
        accumulator
            .compute_deltas(&config, "node-a", 100, "snap-1")
            .unwrap()
            .len(),
        2
    );

    // Evict both idle identities, then re-record only alice. Cleanup of the
    // old alice generation must not strip bob's already-removed baseline in a
    // way that breaks alice's fresh generation, and alice must emit a full
    // restart total (not a residual against an orphaned baseline).
    assert_eq!(accumulator.cleanup_stale_for_tests(0), 2);

    accumulator.record_for_test(
        "ferrum", "alice", "proxy-a", "Payments", 200, "http", charge,
    );
    let restarted = accumulator
        .compute_deltas(&config, "node-a", 200, "snap-2")
        .unwrap();
    assert_eq!(restarted.len(), 1);
    assert_eq!(restarted[0].consumer_id, "alice");
    assert_eq!(restarted[0].call_count, 1);
}

#[test]
fn snapshot_record_emit_cleanup_stress_around_ttl_boundary() {
    let config = Arc::new(snapshot_test_config());
    let accumulator = Arc::new(SnapshotAccumulator::new());
    let stop = Arc::new(AtomicBool::new(false));
    let emitted_calls = Arc::new(AtomicU64::new(0));
    let recorded_calls = Arc::new(AtomicU64::new(0));
    let emitter_iterations = Arc::new(AtomicU64::new(0));
    let cleaner_iterations = Arc::new(AtomicU64::new(0));
    let start = Arc::new(Barrier::new(4));

    let record_acc = Arc::clone(&accumulator);
    let record_stop = Arc::clone(&stop);
    let record_start = Arc::clone(&start);
    let record_calls = Arc::clone(&recorded_calls);
    let recorder = thread::spawn(move || {
        record_start.wait();
        let mut i = 0u64;
        while !record_stop.load(Ordering::Relaxed) {
            let consumer = if i.is_multiple_of(2) { "alice" } else { "bob" };
            record_acc.record_for_test(
                "ferrum",
                consumer,
                "proxy-a",
                "Payments",
                200,
                "http",
                unit_call_charge(0.01),
            );
            record_calls.fetch_add(1, Ordering::Relaxed);
            i = i.wrapping_add(1);
        }
    });

    let emit_acc = Arc::clone(&accumulator);
    let emit_cfg = Arc::clone(&config);
    let emit_stop = Arc::clone(&stop);
    let emit_start = Arc::clone(&start);
    let emit_calls = Arc::clone(&emitted_calls);
    let emit_iterations = Arc::clone(&emitter_iterations);
    let emitter = thread::spawn(move || {
        emit_start.wait();
        let mut snap = 0u64;
        while !emit_stop.load(Ordering::Relaxed) {
            snap += 1;
            let events = emit_acc
                .compute_deltas(&emit_cfg, "node-a", snap as i64, &format!("stress-{snap}"))
                .expect("delta arithmetic must stay finite under stress");
            let calls: u64 = events.iter().map(|event| event.call_count).sum();
            emit_calls.fetch_add(calls, Ordering::Relaxed);
            emit_iterations.fetch_add(1, Ordering::Relaxed);
        }
    });

    let cleanup_acc = Arc::clone(&accumulator);
    let cleanup_stop = Arc::clone(&stop);
    let cleanup_start = Arc::clone(&start);
    let cleanup_iterations = Arc::clone(&cleaner_iterations);
    let cleaner = thread::spawn(move || {
        cleanup_start.wait();
        while !cleanup_stop.load(Ordering::Relaxed) {
            let _ = cleanup_acc.cleanup_stale_for_tests(0);
            cleanup_iterations.fetch_add(1, Ordering::Relaxed);
        }
    });

    start.wait();
    thread::sleep(Duration::from_millis(150));
    stop.store(true, Ordering::Relaxed);
    recorder.join().expect("recorder");
    emitter.join().expect("emitter");
    cleaner.join().expect("cleaner");

    // Drain whatever survived concurrent cleanup.
    let final_events = accumulator
        .compute_deltas(&config, "node-a", 9_999, "stress-final")
        .expect("final delta");
    let final_calls: u64 = final_events.iter().map(|event| event.call_count).sum();
    emitted_calls.fetch_add(final_calls, Ordering::Relaxed);

    let recorded = recorded_calls.load(Ordering::Relaxed);
    let emitted = emitted_calls.load(Ordering::Relaxed);
    assert!(recorded > 0, "stress recorder must make progress");
    assert!(
        emitter_iterations.load(Ordering::Relaxed) > 0,
        "stress emitter must make progress"
    );
    assert!(
        cleaner_iterations.load(Ordering::Relaxed) > 0,
        "stress cleaner must make progress"
    );
    assert!(
        emitted <= recorded,
        "emitted calls ({emitted}) must not exceed recorded calls ({recorded})"
    );
}

#[test]
fn snapshot_keeps_distinct_routes_that_share_consumer_proxy_status() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    let charge = unit_call_charge(0.01);

    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy-a", "Payments", Some("route-a"), None, "http", 200),
        "alice",
        charge,
    );
    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy-a", "Payments", Some("route-b"), None, "http", 200),
        "alice",
        charge,
    );

    let mut events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-routes")
        .unwrap();
    events.sort_by(|left, right| left.route_id.cmp(&right.route_id));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].route_id.as_deref(), Some("route-a"));
    assert_eq!(events[0].call_count, 1);
    assert_eq!(events[1].route_id.as_deref(), Some("route-b"));
    assert_eq!(events[1].call_count, 1);
    assert!(events.iter().all(|event| {
        event.consumer_id == "alice"
            && event.proxy_id == "proxy-a"
            && event.proxy_name == "Payments"
            && event.status_code == 200
            && event.protocol == "http"
    }));
}

#[test]
fn snapshot_identity_is_not_ambiguous_when_dimensions_contain_delimiters() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    let charge = unit_call_charge(0.01);

    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy", "name|route", Some("tail"), None, "http", 200),
        "alice",
        charge,
    );
    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy", "name", Some("route|tail"), None, "http", 200),
        "alice",
        charge,
    );

    let mut events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-delimiters")
        .unwrap();
    events.sort_by(|left, right| left.proxy_name.cmp(&right.proxy_name));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].proxy_name, "name");
    assert_eq!(events[0].route_id.as_deref(), Some("route|tail"));
    assert_eq!(events[1].proxy_name, "name|route");
    assert_eq!(events[1].route_id.as_deref(), Some("tail"));
    assert!(events.iter().all(|event| event.call_count == 1));
}

#[test]
fn snapshot_preserves_display_name_changes_as_separate_identities() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    let charge = unit_call_charge(0.01);

    accumulator.record_http_for_test(
        &http_summary_with_dims(
            "proxy-a",
            "Payments",
            Some("route-a"),
            Some("Alice"),
            "http",
            200,
        ),
        "alice",
        charge,
    );
    accumulator.record_http_for_test(
        &http_summary_with_dims(
            "proxy-a",
            "Payments v2",
            Some("route-a"),
            Some("Alice Example"),
            "http",
            200,
        ),
        "alice",
        charge,
    );

    let mut events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-names")
        .unwrap();
    events.sort_by(|left, right| {
        (
            left.consumer_name.as_deref().unwrap_or(""),
            left.proxy_name.as_str(),
        )
            .cmp(&(
                right.consumer_name.as_deref().unwrap_or(""),
                right.proxy_name.as_str(),
            ))
    });
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].consumer_name.as_deref(), Some("Alice"));
    assert_eq!(events[0].proxy_name, "Payments");
    assert_eq!(events[0].call_count, 1);
    assert_eq!(events[1].consumer_name.as_deref(), Some("Alice Example"));
    assert_eq!(events[1].proxy_name, "Payments v2");
    assert_eq!(events[1].call_count, 1);
    assert!(
        events.iter().all(
            |event| event.route_id.as_deref() == Some("route-a") && event.proxy_id == "proxy-a"
        )
    );

    // Additional traffic under the new names must delta only that identity.
    accumulator.record_http_for_test(
        &http_summary_with_dims(
            "proxy-a",
            "Payments v2",
            Some("route-a"),
            Some("Alice Example"),
            "http",
            200,
        ),
        "alice",
        charge,
    );
    let second = accumulator
        .compute_deltas(&config, "node-a", 200, "snap-names-2")
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].consumer_name.as_deref(), Some("Alice Example"));
    assert_eq!(second[0].proxy_name, "Payments v2");
    assert_eq!(second[0].call_count, 1);
}

#[test]
fn snapshot_keeps_supported_protocols_that_share_proxy_status_separate() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    let charge = unit_call_charge(0.01);

    // Same consumer/proxy/route/billable+raw status — only protocol differs.
    // These would collapse into one mislabeled aggregate if protocol were
    // omitted from the snapshot identity (issue #2583).
    for protocol in ["http", "http2", "http3"] {
        accumulator.record_http_for_test(
            &http_summary_with_dims("proxy-a", "Payments", Some("route-a"), None, protocol, 200),
            "alice",
            charge,
        );
    }

    let mut events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-protocols")
        .unwrap();
    events.sort_by(|left, right| left.protocol.cmp(&right.protocol));
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].protocol, "http");
    assert_eq!(events[1].protocol, "http2");
    assert_eq!(events[2].protocol, "http3");
    assert!(events.iter().all(|event| {
        event.call_count == 1
            && event.status_code == 200
            && event.http_status_code == Some(200)
            && event.grpc_status.is_none()
            && event.route_id.as_deref() == Some("route-a")
            && event.proxy_id == "proxy-a"
    }));
}

#[test]
fn snapshot_delta_and_stale_cleanup_share_revised_route_identity() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    let charge = unit_call_charge(0.01);

    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy-a", "Payments", Some("route-a"), None, "http", 200),
        "alice",
        charge,
    );
    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy-a", "Payments", Some("route-b"), None, "http", 200),
        "alice",
        charge,
    );
    assert_eq!(
        accumulator
            .compute_deltas(&config, "node-a", 100, "snap-1")
            .unwrap()
            .len(),
        2
    );

    // Only route-a receives more traffic before cleanup.
    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy-a", "Payments", Some("route-a"), None, "http", 200),
        "alice",
        charge,
    );
    let delta = accumulator
        .compute_deltas(&config, "node-a", 200, "snap-2")
        .unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].route_id.as_deref(), Some("route-a"));
    assert_eq!(delta[0].call_count, 1);

    assert_eq!(accumulator.cleanup_stale_for_tests(0), 2);
    assert!(
        accumulator
            .compute_deltas(&config, "node-a", 300, "snap-3")
            .unwrap()
            .is_empty(),
        "stale cleanup must drop entries and last-emitted for every revised identity"
    );

    // Re-recording after cleanup starts fresh (full totals, not residual deltas).
    accumulator.record_http_for_test(
        &http_summary_with_dims("proxy-a", "Payments", Some("route-a"), None, "http", 200),
        "alice",
        charge,
    );
    let restarted = accumulator
        .compute_deltas(&config, "node-a", 400, "snap-4")
        .unwrap();
    assert_eq!(restarted.len(), 1);
    assert_eq!(restarted[0].route_id.as_deref(), Some("route-a"));
    assert_eq!(restarted[0].call_count, 1);
}

#[test]
fn generated_ulids_are_lexicographically_monotonic() {
    let mut previous = new_ulid();
    for _ in 0..256 {
        let next = new_ulid();
        assert!(next > previous, "{next} should sort after {previous}");
        previous = next;
    }
}

#[test]
fn clickhouse_status_classification_distinguishes_permanent_and_retryable() {
    assert_eq!(classify_clickhouse_http_status_for_tests(200), "delivered");
    assert_eq!(classify_clickhouse_http_status_for_tests(204), "delivered");
    assert_eq!(classify_clickhouse_http_status_for_tests(400), "permanent");
    assert_eq!(classify_clickhouse_http_status_for_tests(401), "retryable");
    assert_eq!(classify_clickhouse_http_status_for_tests(403), "retryable");
    assert_eq!(classify_clickhouse_http_status_for_tests(408), "retryable");
    assert_eq!(
        classify_clickhouse_http_status_for_tests(413),
        "payload_too_large"
    );
    assert_eq!(classify_clickhouse_http_status_for_tests(429), "retryable");
    assert_eq!(classify_clickhouse_http_status_for_tests(500), "retryable");
    assert_eq!(classify_clickhouse_http_status_for_tests(503), "retryable");
    assert_eq!(classify_clickhouse_http_status_for_tests(302), "retryable");
}

#[test]
fn clickhouse_acknowledgement_requires_complete_empty_success_body() {
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(200, Some(b""), false),
        "delivered"
    );
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(204, Some(b""), false),
        "delivered"
    );
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(
            200,
            Some(b"Code: 60. DB::Exception: Table ferrum.charges_raw does not exist"),
            false
        ),
        "permanent"
    );
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(200, Some(b""), true),
        "permanent"
    );
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(200, Some(b"progress-ok"), false),
        "retryable"
    );
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(200, None, false),
        "retryable"
    );
    assert_eq!(
        classify_clickhouse_acknowledgement_for_tests(400, Some(b""), false),
        "permanent"
    );
}

#[test]
fn durable_config_rejects_wait_for_async_insert_zero_without_lossy_opt_in() {
    use ferrum_edge::plugins::validate_plugin_config;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["insert_query_params"] = json!({
        "async_insert": "1",
        "wait_for_async_insert": "0"
    });
    let err = validate_plugin_config("api_chargeback_sink", &config)
        .expect_err("wait_for_async_insert=0 must be rejected in durable mode");
    assert!(
        err.contains("wait_for_async_insert"),
        "error should name the setting: {err}"
    );
    assert!(
        err.contains("allow_lossy_async_insert"),
        "error should name the lossy opt-in: {err}"
    );
    assert!(
        !err.contains("password") && !err.contains("charge_total"),
        "validation errors must stay free of secrets and charge fields: {err}"
    );

    for falsy in ["false", "FALSE", "no", "off", " 0 "] {
        config["clickhouse"]["insert_query_params"] = json!({
            "async_insert": "1",
            "wait_for_async_insert": falsy
        });
        assert!(
            validate_plugin_config("api_chargeback_sink", &config).is_err(),
            "falsy wait_for_async_insert={falsy:?} must be rejected"
        );
    }

    config["clickhouse"]["insert_query_params"] = json!({
        "async_insert": "1",
        "wait_for_async_insert": "1"
    });
    assert!(
        validate_plugin_config("api_chargeback_sink", &config).is_ok(),
        "wait_for_async_insert=1 must remain valid"
    );

    config["clickhouse"]["insert_query_params"] = json!({
        "async_insert": "1",
        "wait_for_async_insert": "0"
    });
    config["clickhouse"]["allow_lossy_async_insert"] = json!(true);
    assert!(
        validate_plugin_config("api_chargeback_sink", &config).is_ok(),
        "explicit allow_lossy_async_insert must permit wait_for_async_insert=0"
    );

    config["clickhouse"]["allow_lossy_async_insert_typo"] = json!(true);
    let unknown = validate_plugin_config("api_chargeback_sink", &config)
        .expect_err("unknown clickhouse keys must stay rejected");
    assert!(
        unknown.contains("unknown field") || unknown.contains("allow_lossy_async_insert_typo"),
        "unknown-key rejection must mention the field: {unknown}"
    );
}

#[test]
fn durable_async_insert_pins_persistence_wait_when_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["insert_query_params"] = json!({"async_insert": "1"});
    let config: ApiChargebackSinkConfig = serde_json::from_value(config).unwrap();
    let url = url::Url::parse(&clickhouse_insert_url_for_tests(&config).unwrap()).unwrap();
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

    assert_eq!(params.get("async_insert").map(String::as_str), Some("1"));
    assert_eq!(
        params.get("wait_for_async_insert").map(String::as_str),
        Some("1"),
        "durable async inserts must not inherit a potentially lossy server-profile default"
    );
}

fn test_spool(temp: &tempfile::TempDir) -> SpoolManager {
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 1024 * 1024,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    SpoolManager::for_tests(settings, "node-a").unwrap()
}

async fn mount_status_sequence(server: &MockServer, statuses: &[u16]) {
    let statuses = statuses.to_vec();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_mock = Arc::clone(&calls);
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            let idx = calls_for_mock.fetch_add(1, Ordering::SeqCst);
            let status = statuses.get(idx).copied().unwrap_or(200);
            ResponseTemplate::new(status)
        })
        .mount(server)
        .await;
}

fn dead_letter_meta_path(source_path: &Path) -> std::path::PathBuf {
    let name = source_path.file_name().and_then(|n| n.to_str()).unwrap();
    source_path.with_file_name(format!("{name}.rejected.meta"))
}

fn assert_rejected_sidecar(source_path: &Path, expected_status: u16, expected_reason: &str) {
    let meta_path = dead_letter_meta_path(source_path);
    assert!(
        meta_path.exists(),
        "dead-letter meta missing: {}",
        meta_path.display()
    );
    assert!(
        !source_path.exists(),
        "rejected payload must leave the replay set: {}",
        source_path.display()
    );
    let rejected_payload = source_path.with_file_name(format!(
        "{}.rejected",
        source_path.file_name().and_then(|n| n.to_str()).unwrap()
    ));
    assert!(
        !rejected_payload.exists(),
        "dead-letter state must not retain charge-record PII: {}",
        rejected_payload.display()
    );
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert!(meta["rejected_rows"].as_u64().unwrap() >= 1);
    assert!(meta["quarantined_at_unix"].as_i64().unwrap() > 0);
    let outcomes = meta["outcomes"].as_array().unwrap();
    assert!(outcomes.iter().any(|outcome| {
        outcome["http_status"] == expected_status
            && outcome["reason"] == expected_reason
            && outcome["row_count"]
                .as_u64()
                .is_some_and(|count| count >= 1)
    }));
    // Safe metadata only — no charge-record fields.
    let serialized = serde_json::to_string(&meta).unwrap();
    for forbidden in [
        "consumer_id",
        "event_id",
        "password",
        "body",
        "response",
        "charge_total",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "dead-letter meta must not include {forbidden}: {meta}"
        );
    }
}

#[tokio::test]
async fn replay_dead_letters_permanent_400_and_continues_to_newer_file() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400, 200]).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let poison = spool.write_events(&[sample_event("evt-poison")]).unwrap();
    let newer = spool.write_events(&[sample_event("evt-good")]).unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();

    assert_rejected_sidecar(&poison, 400, "permanent_http");
    assert!(!newer.exists(), "newer valid file must still replay");
    let requests = wait_for_requests(&server, 2).await;
    assert_eq!(requests.len(), 2);
    let bodies: Vec<String> = requests
        .iter()
        .map(|request| String::from_utf8(request.body.clone()).unwrap())
        .collect();
    assert!(bodies.iter().any(|body| body.contains("evt-good")));
    assert!(bodies.iter().any(|body| body.contains("evt-poison")));
}

#[tokio::test]
async fn replay_keeps_original_when_dead_letter_metadata_cannot_be_written() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool.write_events(&[sample_event("evt-retained")]).unwrap();
    let meta_path = dead_letter_meta_path(&source);
    let tmp_path = meta_path.with_file_name(format!(
        "{}.tmp",
        meta_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    ));
    fs::create_dir(&tmp_path).unwrap();

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("dead-letter metadata failure must stop the replay tick");

    assert!(error.contains("failed to create spool temp file"));
    assert!(
        source.exists(),
        "source must remain replayable on metadata failure"
    );
    assert!(
        !meta_path.exists(),
        "partial metadata must not be published"
    );
}

#[tokio::test]
async fn replay_stops_on_retryable_redirect_auth_408_429_and_5xx_without_removing_file() {
    for status in [302u16, 401u16, 403u16, 408u16, 429u16, 500u16, 503u16] {
        let server = MockServer::start().await;
        mount_status_sequence(&server, &[status]).await;

        let temp = tempfile::tempdir().unwrap();
        let spool = test_spool(&temp);
        let oldest = spool
            .write_events(&[sample_event(&format!("evt-retry-{status}"))])
            .unwrap();
        let newer = spool.write_events(&[sample_event("evt-blocked")]).unwrap();

        let err = replay_spool_once_for_tests(&spool, &server.uri())
            .await
            .expect_err("retryable status must fail the replay tick");
        assert!(
            err.contains(&format!("clickhouse returned HTTP {status}")),
            "unexpected error: {err}"
        );
        assert!(
            oldest.exists(),
            "retryable failure must retain the oldest file"
        );
        assert!(
            newer.exists(),
            "retryable failure must not advance past the oldest file"
        );
        assert!(
            !err.to_ascii_lowercase().contains("evt-"),
            "retryable errors must not include charge-record fields: {err}"
        );
    }
}

#[tokio::test]
async fn replay_stops_on_network_failure_without_removing_file() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool.write_events(&[sample_event("evt-net")]).unwrap();

    let err = replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect_err("unreachable ClickHouse must be retryable");
    assert!(
        err.contains("network") || err.contains("timeout") || err.contains("tls"),
        "unexpected error class: {err}"
    );
    assert!(path.exists(), "network failure must retain the spool file");
}

#[tokio::test]
async fn replay_splits_413_payload_and_preserves_event_ids() {
    let server = MockServer::start().await;
    // Whole 4-row file -> 413, then each half of size 2 -> 200.
    mount_status_sequence(&server, &[413, 200, 200]).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let events = vec![
        sample_event("evt-split-a"),
        sample_event("evt-split-b"),
        sample_event("evt-split-c"),
        sample_event("evt-split-d"),
    ];
    let path = spool.write_events(&events).unwrap();

    replay_spool_once_with_batch_size_for_tests(&spool, &server.uri(), 2)
        .await
        .unwrap();

    assert!(
        !path.exists(),
        "split replay should consume the original file"
    );
    let requests = wait_for_requests(&server, 3).await;
    assert_eq!(requests.len(), 3);
    let bodies: Vec<String> = requests
        .iter()
        .map(|request| String::from_utf8(request.body.clone()).unwrap())
        .collect();
    assert!(bodies[0].contains("evt-split-a") && bodies[0].contains("evt-split-d"));
    let delivered = bodies[1..].join("\n");
    for id in ["evt-split-a", "evt-split-b", "evt-split-c", "evt-split-d"] {
        assert!(
            delivered.contains(id),
            "split replay must preserve event_id {id}; bodies={bodies:?}"
        );
    }
}

#[tokio::test]
async fn replay_dead_letters_single_row_413_then_replays_newer_file() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[413, 200]).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let oversized = spool.write_events(&[sample_event("evt-too-big")]).unwrap();
    let newer = spool
        .write_events(&[sample_event("evt-after-413")])
        .unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();

    assert_rejected_sidecar(&oversized, 413, "payload_too_large");
    assert!(
        !newer.exists(),
        "newer file must replay after single-row 413 dead-letter"
    );
    let requests = wait_for_requests(&server, 2).await;
    let last = String::from_utf8(requests.last().unwrap().body.clone()).unwrap();
    assert!(last.contains("evt-after-413"));
}

#[tokio::test]
async fn replay_partial_split_dead_letters_only_poison_row() {
    // Whole 2-row file -> 413, left row -> 400 permanent, right row -> 200.
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[413, 400, 200]).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool
        .write_events(&[sample_event("evt-bad-row"), sample_event("evt-good-row")])
        .unwrap();

    replay_spool_once_with_batch_size_for_tests(&spool, &server.uri(), 1)
        .await
        .unwrap();

    assert!(
        !path.exists(),
        "original file should be consumed after partial split"
    );
    assert_rejected_sidecar(&path, 400, "permanent_http");
    let meta: Value =
        serde_json::from_str(&fs::read_to_string(dead_letter_meta_path(&path)).unwrap()).unwrap();
    assert_eq!(meta["rejected_rows"], 1);

    let requests = wait_for_requests(&server, 3).await;
    let delivered = String::from_utf8(requests[2].body.clone()).unwrap();
    assert!(delivered.contains("evt-good-row"));
}

#[tokio::test]
async fn replay_deletes_spool_only_after_empty_200_acknowledgement() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool.write_events(&[sample_event("evt-ack-ok")]).unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();

    assert!(
        !path.exists(),
        "complete empty HTTP 200 acknowledgement must delete the spool file"
    );
}

#[tokio::test]
async fn replay_dead_letters_http_200_exception_body_and_redacts_failure_context() {
    let server = MockServer::start().await;
    let exception_body =
        "Code: 60. DB::Exception: Table ferrum.charges_raw does not exist. password=super-secret";
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(exception_body))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool
        .write_events(&[sample_event("evt-exception-body")])
        .unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();

    assert_rejected_sidecar(&path, 200, "permanent_http");
    let meta_raw = fs::read_to_string(dead_letter_meta_path(&path)).unwrap();
    for forbidden in [
        "super-secret",
        "DB::Exception",
        "charges_raw does not exist",
        "evt-exception-body",
        "password",
    ] {
        assert!(
            !meta_raw.contains(forbidden),
            "dead-letter metadata must not retain response or charge contents ({forbidden}): {meta_raw}"
        );
    }
}

#[tokio::test]
async fn replay_dead_letters_http_200_exception_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).insert_header("X-ClickHouse-Exception-Code", "62"))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool
        .write_events(&[sample_event("evt-exception-header")])
        .unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();

    assert_rejected_sidecar(&path, 200, "permanent_http");
}

#[tokio::test]
async fn replay_keeps_spool_on_ambiguous_non_empty_200_acknowledgement() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-an-exception-but-not-empty"))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let oldest = spool
        .write_events(&[sample_event("evt-ambiguous")])
        .unwrap();
    let newer = spool.write_events(&[sample_event("evt-blocked")]).unwrap();

    let err = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("ambiguous acknowledgement must be retryable");
    assert!(
        err.contains("ambiguous") || err.contains("non-empty"),
        "unexpected error: {err}"
    );
    assert!(
        !err.contains("not-an-exception-but-not-empty"),
        "failure context must not echo the response body: {err}"
    );
    assert!(
        !err.contains("evt-ambiguous") && !err.contains("charge_total"),
        "failure context must not include charge contents: {err}"
    );
    assert!(oldest.exists(), "ambiguous ACK must retain the spool file");
    assert!(
        newer.exists(),
        "ambiguous ACK must not advance past the oldest file"
    );
}

#[tokio::test]
async fn replay_retries_after_ambiguous_acknowledgement_without_double_billing_identity_change() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_mock = Arc::clone(&calls);
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            let idx = calls_for_mock.fetch_add(1, Ordering::SeqCst);
            if idx == 0 {
                ResponseTemplate::new(200).set_body_string("temporary-ambiguous")
            } else {
                ResponseTemplate::new(200)
            }
        })
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool
        .write_events(&[sample_event("evt-idempotent-retry")])
        .unwrap();

    let first = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("first ambiguous ACK must keep the file");
    assert!(first.contains("ambiguous") || first.contains("non-empty"));
    assert!(path.exists());

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .unwrap();
    assert!(
        !path.exists(),
        "second empty ACK must delete the spool file"
    );

    let requests = wait_for_requests(&server, 2).await;
    assert_eq!(requests.len(), 2);
    let bodies: Vec<String> = requests
        .iter()
        .map(|request| String::from_utf8(request.body.clone()).unwrap())
        .collect();
    assert!(
        bodies
            .iter()
            .all(|body| body.contains("evt-idempotent-retry")),
        "retry must resend the same event_id for ReplacingMergeTree idempotency"
    );
    assert_eq!(
        bodies[0], bodies[1],
        "retry payload bytes must stay identical"
    );
}
#[tokio::test]
async fn config_validation_rejects_buffer_max_bytes_and_spool_delivery_queue() {
    let temp = tempfile::tempdir().unwrap();
    let mut too_small = valid_config(temp.path());
    too_small["batch"]["buffer_max_bytes"] = json!(1);
    assert!(
        ApiChargebackSink::new(&too_small, PluginHttpClient::default(), "ferrum").is_err(),
        "tiny buffer_max_bytes must fail"
    );

    let mut bad_queue = valid_config(temp.path());
    bad_queue["spool"]["delivery_queue_capacity"] = json!(0);
    assert!(
        ApiChargebackSink::new(&bad_queue, PluginHttpClient::default(), "ferrum").is_err(),
        "zero delivery_queue_capacity must fail"
    );

    let mut ok = valid_config(temp.path());
    ok["batch"]["buffer_max_bytes"] = json!(16_777_216);
    ok["spool"]["delivery_queue_capacity"] = json!(128);
    ApiChargebackSink::new(&ok, PluginHttpClient::default(), "ferrum")
        .expect("valid byte-budget and delivery queue knobs must admit");
}

fn billable_summary(request_id: &str) -> TransactionSummary {
    let mut summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        consumer_username: Some("alice".to_string()),
        proxy_id: Some("proxy-a".to_string()),
        proxy_name: Some("Payments".to_string()),
        response_status_code: 200,
        bytes_sent: 100,
        bytes_received: 200,
        ..TransactionSummary::default()
    };
    summary
        .metadata
        .insert(REQUEST_ID_METADATA_KEY.to_string(), request_id.to_string());
    summary
}

fn spool_delivery_totals() -> (u64, u64, u64) {
    let prom = render_prometheus();
    (
        prometheus_counter(&prom, "chargeback_sink_spool_jobs_enqueued_total"),
        prometheus_counter(&prom, "chargeback_sink_spool_jobs_written_total"),
        prometheus_counter(&prom, "chargeback_sink_spool_jobs_lost_total"),
    )
}

fn prometheus_counter(prom: &str, name: &str) -> u64 {
    let prefix = format!("{name} ");
    prom.lines()
        .find_map(|line| {
            let rest = line.strip_prefix(&prefix)?;
            if rest.starts_with('{') {
                return None;
            }
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0)
}

async fn wait_condvar_flag(flag: Arc<(Mutex<bool>, Condvar)>) {
    tokio::task::spawn_blocking(move || {
        let (lock, cv) = &*flag;
        let mut guard = lock.lock().expect("condvar flag lock");
        while !*guard {
            guard = cv.wait(guard).expect("condvar flag wait");
        }
    })
    .await
    .expect("condvar flag wait task");
}

/// Accepts ClickHouse export connections and holds them open so the batching
/// flush worker stays inside `send_batch` (and therefore cannot drain the
/// capacity-1 mpsc). Dropping/releasing closes the sockets so in-flight HTTP
/// fails promptly instead of waiting out a mock delay or client timeout.
struct HeldClickHouseExport {
    url: String,
    first_accept: Arc<(Mutex<bool>, Condvar)>,
    release: Option<tokio::sync::oneshot::Sender<()>>,
    _task: tokio::task::JoinHandle<()>,
}

impl HeldClickHouseExport {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind held clickhouse listener");
        let addr = listener
            .local_addr()
            .expect("held clickhouse listener addr");
        let first_accept = Arc::new((Mutex::new(false), Condvar::new()));
        let first_accept_for_task = Arc::clone(&first_accept);
        let (release_tx, mut release_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    _ = &mut release_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                {
                                    let (lock, cv) = &*first_accept_for_task;
                                    if let Ok(mut guard) = lock.lock() {
                                        *guard = true;
                                        cv.notify_all();
                                    }
                                }
                                held.push(stream);
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            drop(held);
        });
        Self {
            url: format!("http://{addr}"),
            first_accept,
            release: Some(release_tx),
            _task: task,
        }
    }

    fn release_held_connections(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for HeldClickHouseExport {
    fn drop(&mut self) {
        self.release_held_connections();
    }
}

/// Deterministic BeforeWrite parking gate bound to the spool-write hook.
///
/// Readiness is published only after the writer has incremented `parked` and is
/// committed to blocking on `release` while still holding the release mutex.
/// Waiting on a looser "entered hook" flag published before that increment lets
/// observers race ahead and see `parked == 0` under scheduler pressure (the
/// hosted flake at issue #3433).
struct SpoolBeforeWriteGate {
    release: Mutex<bool>,
    release_cv: Condvar,
    parked: Mutex<usize>,
    parked_cv: Condvar,
    finished: Mutex<bool>,
    finished_cv: Condvar,
}

impl SpoolBeforeWriteGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            release: Mutex::new(false),
            release_cv: Condvar::new(),
            parked: Mutex::new(0),
            parked_cv: Condvar::new(),
            finished: Mutex::new(false),
            finished_cv: Condvar::new(),
        })
    }

    fn on_before_write(&self) {
        // Acquire release first so publishing parked commits us to waiting
        // before any observer can proceed from wait_until_parked.
        let mut release = self.release.lock().expect("release gate lock");
        {
            let mut parked = self.parked.lock().expect("parked gate lock");
            *parked = parked.saturating_add(1);
            self.parked_cv.notify_all();
        }
        while !*release {
            release = self.release_cv.wait(release).expect("release gate wait");
        }
        let mut parked = self.parked.lock().expect("parked gate lock");
        *parked = parked.saturating_sub(1);
    }

    fn on_after_write(&self) {
        let mut finished = self.finished.lock().expect("finished gate lock");
        *finished = true;
        self.finished_cv.notify_all();
    }

    fn parked_count(&self) -> usize {
        *self.parked.lock().expect("parked gate lock")
    }

    fn is_finished(&self) -> bool {
        *self.finished.lock().expect("finished gate lock")
    }

    fn is_released(&self) -> bool {
        *self.release.lock().expect("release gate lock")
    }

    fn diagnostic_snapshot(&self) -> String {
        format!(
            "parked={} finished={} released={}",
            self.parked_count(),
            self.is_finished(),
            self.is_released()
        )
    }

    /// Block until at least `min_parked` writers are inside BeforeWrite.
    ///
    /// Returns a bounded diagnostic when the gate is never reached instead of
    /// racing on a later parked-count assertion.
    fn wait_until_parked(&self, min_parked: usize, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut parked = self.parked.lock().expect("parked gate lock");
        while *parked < min_parked {
            let now = Instant::now();
            if now >= deadline {
                let parked_now = *parked;
                // Drop parked before reading sibling gate locks so we never
                // invert the release->parked order used by on_before_write.
                drop(parked);
                return Err(format!(
                    "spool BeforeWrite gate did not reach parked>={min_parked} within {timeout:?}; parked={parked_now} finished={} released={}",
                    self.is_finished(),
                    self.is_released()
                ));
            }
            let (next, wait_result) = self
                .parked_cv
                .wait_timeout(parked, deadline.saturating_duration_since(now))
                .expect("parked gate wait");
            parked = next;
            if wait_result.timed_out() && *parked < min_parked {
                let parked_now = *parked;
                drop(parked);
                return Err(format!(
                    "spool BeforeWrite gate did not reach parked>={min_parked} within {timeout:?}; parked={parked_now} finished={} released={}",
                    self.is_finished(),
                    self.is_released()
                ));
            }
        }
        Ok(())
    }

    fn wait_until_finished(&self) {
        let mut finished = self.finished.lock().expect("finished gate lock");
        while !*finished {
            finished = self.finished_cv.wait(finished).expect("finished gate wait");
        }
    }

    fn release_all(&self) {
        let mut release = self.release.lock().expect("release gate lock");
        *release = true;
        self.release_cv.notify_all();
    }
}

/// Clears the process-global spool write hook and opens any held release gate
/// even if the test panics mid-block.
struct ClearSpoolWriteHookOnDrop {
    gate: Arc<SpoolBeforeWriteGate>,
}

impl Drop for ClearSpoolWriteHookOnDrop {
    fn drop(&mut self) {
        self.gate.release_all();
        set_spool_write_hook_for_tests(None);
    }
}

#[test]
fn spool_before_write_gate_publishes_parked_before_waiters_return() {
    // Regression for #3433: readiness must not be observable while parked==0.
    let gate = SpoolBeforeWriteGate::new();
    let writer_gate = Arc::clone(&gate);
    let started = Arc::new(Barrier::new(2));
    let writer_started = Arc::clone(&started);

    let writer = thread::spawn(move || {
        writer_started.wait();
        writer_gate.on_before_write();
        writer_gate.on_after_write();
    });

    started.wait();
    gate.wait_until_parked(1, Duration::from_secs(5))
        .expect("writer must publish parked before waiters observe readiness");
    assert_eq!(
        gate.parked_count(),
        1,
        "wait_until_parked must not return while parked==0; {}",
        gate.diagnostic_snapshot()
    );
    assert!(
        !gate.is_finished(),
        "writer must remain inside BeforeWrite until release; {}",
        gate.diagnostic_snapshot()
    );

    gate.release_all();
    writer.join().expect("gated writer thread");
    assert_eq!(gate.parked_count(), 0);
    assert!(gate.is_finished());
}

#[test]
fn spool_before_write_gate_timeout_names_unreachable_gate_state() {
    let gate = SpoolBeforeWriteGate::new();
    let error = gate
        .wait_until_parked(1, Duration::from_millis(20))
        .expect_err("an unreachable BeforeWrite gate must fail closed");
    assert!(
        error.contains("did not reach parked>=1"),
        "timeout must name the missed parked threshold: {error}"
    );
    assert!(
        error.contains("parked=0"),
        "timeout must report parked count: {error}"
    );
    assert!(
        error.contains("finished=false"),
        "timeout must report finished state: {error}"
    );
    assert!(
        error.contains("released=false"),
        "timeout must report release state: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn logging_hook_returns_while_spool_write_is_deliberately_blocked() {
    // A long flush interval alone does not keep the capacity-1 mpsc occupied:
    // the flush worker drains into its local buffer immediately. Occupy the
    // worker instead by holding the export TCP connection open (batch size 1),
    // then release those sockets on teardown so HTTP fails promptly.
    let mut held_export = HeldClickHouseExport::start().await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(held_export.url);
    // Bound any stranded request, but teardown releases sockets so we do not
    // wait this out on the success path.
    config["clickhouse"]["timeout_ms"] = json!(60_000);
    config["batch"]["size"] = json!(1);
    // Use the maximum admitted interval; the held export socket, not this
    // timer, is what deterministically occupies the flush worker.
    config["batch"]["flush_interval_ms"] = json!(600_000);
    config["batch"]["buffer_capacity"] = json!(1);
    config["retry"]["max_attempts"] = json!(1);
    config["spool"]["delivery_queue_capacity"] = json!(8);
    config["spool"]["replay_interval_secs"] = json!(3600);

    let gate = SpoolBeforeWriteGate::new();
    let _clear_hook = ClearSpoolWriteHookOnDrop {
        gate: Arc::clone(&gate),
    };

    let hook_gate = Arc::clone(&gate);
    let hook_spool_dir = temp.path().to_path_buf();
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, namespace_root| {
        // The hook slot is process-global: only gate this test's own spool.
        if !namespace_root.starts_with(&hook_spool_dir) {
            return;
        }
        match point {
            SpoolWriteHookPoint::BeforeWrite => hook_gate.on_before_write(),
            SpoolWriteHookPoint::AfterWrite => hook_gate.on_after_write(),
            // This test gates only the write boundary; quota-eviction snapshots
            // are not part of the stall it asserts.
            SpoolWriteHookPoint::QuotaInventoryTaken => {}
        }
    })));

    let (enqueued_baseline, written_baseline, lost_baseline) = spool_delivery_totals();

    let plugin =
        Arc::new(ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap());
    plugin.start_background_tasks().expect("chargeback start");
    plugin.commit_background_tasks();

    // batch.size=1: the first log starts an export that parks on the held TCP
    // socket, so the flush worker cannot recv from the capacity-1 channel.
    plugin.log(&billable_summary("block-flush")).await;
    wait_condvar_flag(Arc::clone(&held_export.first_accept)).await;

    // Occupy the only channel slot while the flush worker remains inside HTTP.
    plugin.log(&billable_summary("fill-queue")).await;
    // High-water overflow (depth=1, capacity=1, watermark=80%) hands the event
    // to the bounded spool delivery worker, which blocks in write_events.
    plugin.log(&billable_summary("overflow-blocked")).await;

    // Wait on the parked count itself (not a looser "entered" flag) so readiness
    // is bound to the actual BeforeWrite gate under the release mutex.
    let wait_gate = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || {
        wait_gate
            .wait_until_parked(1, Duration::from_secs(5))
            .expect("overflow spool write must park in BeforeWrite")
    })
    .await
    .expect("parked gate wait task");

    let (enqueued_while_blocked, written_while_blocked, lost_while_blocked) =
        spool_delivery_totals();
    assert!(
        enqueued_while_blocked > enqueued_baseline,
        "overflow must enqueue a spool job before the blocking write finishes; baseline={enqueued_baseline} observed={enqueued_while_blocked}"
    );
    assert_eq!(
        written_while_blocked, written_baseline,
        "no spool write may complete while the injected gate is held"
    );
    assert_eq!(
        lost_while_blocked, lost_baseline,
        "a blocked write must not be counted as a spool loss"
    );

    // While spool I/O remains blocked, another logging overflow must return
    // after a non-blocking try_enqueue (second job waits behind the first).
    let plugin_for_bounded_log = Arc::clone(&plugin);
    let bounded_log = tokio::spawn(async move {
        plugin_for_bounded_log
            .log(&billable_summary("overflow-while-blocked"))
            .await;
    });
    tokio::time::timeout(Duration::from_secs(1), bounded_log)
        .await
        .expect("logging hook must return without waiting for blocked spool I/O")
        .expect("bounded logging task must not panic");

    let (enqueued_after_hook, written_after_hook, lost_after_hook) = spool_delivery_totals();
    assert!(
        enqueued_after_hook > enqueued_while_blocked,
        "logging hook must enqueue while the prior spool write is still blocked"
    );
    assert_eq!(
        written_after_hook, written_baseline,
        "logging hook return must not wait for the blocked spool write"
    );
    assert_eq!(
        lost_after_hook, lost_baseline,
        "bounded overflow enqueue must not drop while the delivery queue has capacity"
    );
    assert!(
        gate.parked_count() > 0,
        "gated spool write must still be parked in BeforeWrite before release; {}",
        gate.diagnostic_snapshot()
    );
    assert!(
        !gate.is_finished(),
        "blocked spool write must not finish before release; {}",
        gate.diagnostic_snapshot()
    );

    let enqueued_during_gate = enqueued_after_hook - enqueued_baseline;

    gate.release_all();

    let finished_gate = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || finished_gate.wait_until_finished())
        .await
        .expect("finished gate wait task");

    // AfterWrite runs inside write_events; the delivery worker publishes
    // jobs_written only after spawn_blocking joins. Yield until our gated
    // jobs land without sleeping on the wall clock.
    let (enqueued_final, written_final, lost_final) = {
        let mut observed = spool_delivery_totals();
        for _ in 0..100_000 {
            if observed.1 >= written_baseline + enqueued_during_gate {
                break;
            }
            assert_eq!(
                observed.2, lost_baseline,
                "successful gated writes must not increment spool loss counters"
            );
            tokio::task::yield_now().await;
            observed = spool_delivery_totals();
        }
        observed
    };
    assert!(
        written_final >= written_baseline + enqueued_during_gate,
        "released spool writes must complete cleanly; enqueued_delta={enqueued_during_gate} written_baseline={written_baseline} written_final={written_final} lost_final={lost_final} enqueued_final={enqueued_final}"
    );
    assert_eq!(
        lost_final, lost_baseline,
        "successful gated writes must not increment spool loss counters"
    );
    assert!(
        disk_owned_bytes(temp.path()) > 0,
        "released spool write must leave durable owned spool bytes"
    );

    // Unblock the stranded export before dropping the plugin so teardown cannot
    // sit on the client timeout.
    held_export.release_held_connections();
    set_spool_write_hook_for_tests(None);
    drop(plugin);
}

fn queue_status_counters() -> (u64, u64, u64, u64, u64) {
    let status: Value = serde_json::from_str(&render_status_json()).expect("status json");
    let queue = &status["instances"][0]["queue"];
    (
        queue["depth"].as_u64().unwrap_or(0),
        queue["capacity"].as_u64().unwrap_or(0),
        queue["high_water_hits_total"].as_u64().unwrap_or(0),
        queue["high_water_diversions_total"].as_u64().unwrap_or(0),
        queue["full_drops_total"].as_u64().unwrap_or(0),
    )
}

/// Issue #3038: with spool disabled, high water is telemetry only and every
/// configured channel slot remains usable until the buffer is actually full.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn no_spool_uses_full_buffer_capacity_past_high_water() {
    let mut held_export = HeldClickHouseExport::start().await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(held_export.url);
    config["clickhouse"]["timeout_ms"] = json!(60_000);
    config["batch"]["size"] = json!(1);
    config["batch"]["flush_interval_ms"] = json!(600_000);
    config["batch"]["buffer_capacity"] = json!(10);
    config["retry"]["max_attempts"] = json!(1);
    config["spool"]["enabled"] = json!(false);

    let plugin =
        Arc::new(ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap());
    plugin.start_background_tasks().expect("chargeback start");
    plugin.commit_background_tasks();

    // Park the flush worker inside HTTP so the capacity-10 channel stays full.
    plugin.log(&billable_summary("block-flush")).await;
    wait_condvar_flag(Arc::clone(&held_export.first_accept)).await;

    for idx in 0..10 {
        plugin
            .log(&billable_summary(&format!("fill-{idx:02}")))
            .await;
    }

    let (depth, capacity, high_water_hits, diversions, drops) = queue_status_counters();
    assert_eq!(capacity, 10, "status must report configured capacity");
    assert_eq!(
        depth, 10,
        "all configured no-spool channel slots must remain usable past 80% high water; depth={depth}"
    );
    assert!(
        high_water_hits > 0,
        "crossing high water must still emit telemetry; hits={high_water_hits}"
    );
    assert_eq!(
        diversions, 0,
        "no-spool high water must not divert; diversions={diversions}"
    );
    assert_eq!(
        drops, 0,
        "filling exactly to capacity must not count a full-buffer drop; drops={drops}"
    );

    let prom = render_prometheus();
    assert_eq!(
        prometheus_counter(&prom, "chargeback_sink_queue_high_water_diversions_total"),
        0
    );
    assert_eq!(
        prometheus_counter(&prom, "chargeback_sink_queue_full_drops_total"),
        0
    );

    // The next item follows the configured full-buffer policy (drop).
    plugin.log(&billable_summary("overflow-full")).await;
    let (depth_after, _, _, diversions_after, drops_after) = queue_status_counters();
    assert_eq!(depth_after, 10, "full buffer depth must stay at capacity");
    assert_eq!(
        diversions_after, 0,
        "no-spool full buffer must not record a durable diversion"
    );
    assert_eq!(
        drops_after, 1,
        "the item past capacity must count as a true full-buffer drop"
    );
    let prom_after = render_prometheus();
    assert_eq!(
        prometheus_counter(&prom_after, "chargeback_sink_queue_full_drops_total"),
        1
    );
    assert_eq!(
        prometheus_counter(
            &prom_after,
            "chargeback_sink_queue_high_water_diversions_total"
        ),
        0
    );

    held_export.release_held_connections();
    drop(plugin);
}

/// Issue #3038: with spool enabled, high-water diversion remains durable and is
/// counted separately from true full-buffer drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn spool_enabled_high_water_diversion_is_durable_and_distinct_from_drops() {
    let mut held_export = HeldClickHouseExport::start().await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(held_export.url);
    config["clickhouse"]["timeout_ms"] = json!(60_000);
    config["batch"]["size"] = json!(1);
    config["batch"]["flush_interval_ms"] = json!(600_000);
    config["batch"]["buffer_capacity"] = json!(1);
    config["retry"]["max_attempts"] = json!(1);
    config["spool"]["delivery_queue_capacity"] = json!(8);
    config["spool"]["replay_interval_secs"] = json!(3600);

    let (enqueued_baseline, _, lost_baseline) = spool_delivery_totals();

    let plugin =
        Arc::new(ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap());
    plugin.start_background_tasks().expect("chargeback start");
    plugin.commit_background_tasks();

    plugin.log(&billable_summary("block-flush")).await;
    wait_condvar_flag(Arc::clone(&held_export.first_accept)).await;

    // Fill the only channel slot so the next enqueue observes high water.
    plugin.log(&billable_summary("fill-queue")).await;
    plugin.log(&billable_summary("divert-high-water")).await;

    let (_, _, high_water_hits, diversions, drops) = queue_status_counters();
    assert!(
        high_water_hits > 0,
        "high-water telemetry must fire; hits={high_water_hits}"
    );
    assert!(
        diversions >= 1,
        "spool-enabled high water must durable-divert; diversions={diversions}"
    );
    assert_eq!(
        drops, 0,
        "durable high-water diversion must not count as a full-buffer drop"
    );

    let (enqueued_after, _, lost_after) = spool_delivery_totals();
    assert!(
        enqueued_after > enqueued_baseline,
        "high-water diversion must enqueue a spool delivery job"
    );
    assert_eq!(
        lost_after, lost_baseline,
        "successful high-water diversion must not count spool loss"
    );

    let prom = render_prometheus();
    assert!(prometheus_counter(&prom, "chargeback_sink_queue_high_water_diversions_total") >= 1);
    assert_eq!(
        prometheus_counter(&prom, "chargeback_sink_queue_full_drops_total"),
        0
    );

    // Wait briefly for the async spool write to land on disk.
    for _ in 0..100_000 {
        if disk_owned_bytes(temp.path()) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        disk_owned_bytes(temp.path()) > 0,
        "high-water diversion must leave durable owned spool bytes"
    );

    held_export.release_held_connections();
    drop(plugin);
}

/// Saturated spool delivery must not report a successful high-water diversion or
/// enqueue, and must not masquerade as a full in-memory channel drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn saturated_spool_delivery_does_not_count_failed_high_water_diversion() {
    let mut held_export = HeldClickHouseExport::start().await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(held_export.url);
    config["clickhouse"]["timeout_ms"] = json!(60_000);
    config["batch"]["size"] = json!(1);
    config["batch"]["flush_interval_ms"] = json!(600_000);
    config["batch"]["buffer_capacity"] = json!(1);
    config["retry"]["max_attempts"] = json!(1);
    // Capacity 1: one job can sit in the delivery channel while the worker is
    // parked inside a blocked write, so the next high-water handoff is refused.
    config["spool"]["delivery_queue_capacity"] = json!(1);
    config["spool"]["replay_interval_secs"] = json!(3600);

    let gate = SpoolBeforeWriteGate::new();
    let _clear_hook = ClearSpoolWriteHookOnDrop {
        gate: Arc::clone(&gate),
    };
    let hook_gate = Arc::clone(&gate);
    let hook_spool_dir = temp.path().to_path_buf();
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, namespace_root| {
        // The hook slot is process-global: only gate this test's own spool.
        if !namespace_root.starts_with(&hook_spool_dir) {
            return;
        }
        match point {
            SpoolWriteHookPoint::BeforeWrite => hook_gate.on_before_write(),
            SpoolWriteHookPoint::AfterWrite => hook_gate.on_after_write(),
            // Quota inventory snapshots are unrelated to the delivery-channel
            // saturation boundary this test intentionally stalls.
            SpoolWriteHookPoint::QuotaInventoryTaken => {}
        }
    })));

    let (_, _, spool_lost_baseline) = spool_delivery_totals();
    let enqueued_baseline = prometheus_counter(
        &render_prometheus(),
        "chargeback_sink_events_enqueued_total",
    );

    let plugin =
        Arc::new(ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap());
    plugin.start_background_tasks().expect("chargeback start");
    plugin.commit_background_tasks();

    plugin.log(&billable_summary("block-flush")).await;
    wait_condvar_flag(Arc::clone(&held_export.first_accept)).await;
    plugin.log(&billable_summary("fill-queue")).await;

    // First high-water diversion is accepted and parks the delivery worker.
    plugin.log(&billable_summary("divert-accepted")).await;
    let wait_gate = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || {
        wait_gate
            .wait_until_parked(1, Duration::from_secs(5))
            .expect("accepted diversion must park in BeforeWrite")
    })
    .await
    .expect("parked gate wait task");

    let (_, _, _, diversions_after_accept, drops_after_accept) = queue_status_counters();
    assert_eq!(
        diversions_after_accept, 1,
        "accepted high-water handoff must count exactly one diversion"
    );
    assert_eq!(drops_after_accept, 0);

    // Fill the only delivery-queue slot while the worker remains blocked.
    plugin.log(&billable_summary("divert-fills-delivery")).await;
    let (_, _, _, diversions_after_fill, _) = queue_status_counters();
    assert_eq!(
        diversions_after_fill, 2,
        "second accepted handoff must count a diversion while still durable"
    );
    let enqueued_before_reject = prometheus_counter(
        &render_prometheus(),
        "chargeback_sink_events_enqueued_total",
    );

    // Next high-water handoff must be refused by the saturated delivery queue.
    plugin.log(&billable_summary("divert-rejected")).await;

    let (_, _, _, diversions_after_reject, drops_after_reject) = queue_status_counters();
    assert_eq!(
        diversions_after_reject, diversions_after_fill,
        "refused spool-delivery handoff must not increment high-water diversions"
    );
    assert_eq!(
        drops_after_reject, 0,
        "spool-delivery saturation must not masquerade as a full-buffer drop"
    );

    let prom = render_prometheus();
    let enqueued_after = prometheus_counter(&prom, "chargeback_sink_events_enqueued_total");
    let (_, _, spool_lost_after) = spool_delivery_totals();
    assert!(
        spool_lost_after > spool_lost_baseline,
        "refused handoff must remain visible on spool loss counters"
    );
    assert_eq!(
        enqueued_after, enqueued_before_reject,
        "rejected diversion must not increment events_enqueued_total"
    );
    assert!(
        enqueued_before_reject > enqueued_baseline,
        "accepted channel/diversion admissions must still increment events_enqueued_total"
    );

    gate.release_all();
    let finished_gate = Arc::clone(&gate);
    tokio::task::spawn_blocking(move || finished_gate.wait_until_finished())
        .await
        .expect("finished gate wait task");

    held_export.release_held_connections();
    drop(plugin);
}

#[test]
fn clickhouse_timeout_bound_keeps_claim_lease_above_delivery_budget() {
    let temp = tempfile::tempdir().unwrap();
    let mut raw = valid_config(temp.path());
    raw["clickhouse"]["timeout_ms"] = json!(600_000);
    raw["retry"]["max_attempts"] = json!(5);
    raw["retry"]["initial_delay_ms"] = json!(60_000);
    raw["retry"]["max_delay_ms"] = json!(60_000);
    let config: ApiChargebackSinkConfig = serde_json::from_value(raw.clone()).unwrap();
    let one_delivery_budget_secs = ((600_000u64 * 5) + (60_000u64 * 4)).div_ceil(1_000);
    assert!(
        spool_claim_lease_secs_for_tests(&config) > one_delivery_budget_secs,
        "claim lease must remain strictly above the accepted request/retry budget"
    );
    assert!(
        spool_claim_lease_secs_for_tests(&config) > 3_600,
        "a legitimate long delivery budget must not be truncated at one hour"
    );

    raw["clickhouse"]["timeout_ms"] = json!(600_001);
    let error = match ApiChargebackSink::new(&raw, PluginHttpClient::default(), "ferrum") {
        Ok(_) => panic!("timeout above the documented maximum must be rejected"),
        Err(error) => error,
    };
    assert!(
        error.contains("clickhouse.timeout_ms must be between 1 and 600000"),
        "unexpected error: {error}"
    );
}

#[test]
fn spool_path_component_rejects_or_encodes_escape_forms() {
    let hashed = [
        "../escape",
        "..\\escape",
        "/abs",
        "C:\\windows",
        "C:/windows",
        // Drive-relative forms carry no separator at all and still resolve
        // against a per-drive current directory on Windows.
        "C:",
        "d:data",
        r"\\?\C:\windows",
        r"\\.\pipe\x",
        "//unc/share",
        "\\\\server\\share",
        "has/slash",
        "has\\slash",
        ".",
        "..",
    ];
    for raw in hashed {
        let encoded = SpoolManager::encode_spool_path_component_for_tests(raw)
            .unwrap_or_else(|err| panic!("hostile component {raw:?} should encode: {err}"));
        assert!(
            encoded.starts_with("n_"),
            "hostile {raw:?} must be hashed, got {encoded}"
        );
        assert!(!encoded.contains('/') && !encoded.contains('\\') && !encoded.contains('\0'));
    }
    let nul_err = SpoolManager::encode_spool_path_component_for_tests("x\0y")
        .expect_err("NUL must be rejected");
    assert!(nul_err.contains("NUL"));
    let empty_err = SpoolManager::encode_spool_path_component_for_tests("   ")
        .expect_err("a whitespace-only component must not become a path segment");
    assert!(empty_err.contains("must not be empty"), "{empty_err}");
    assert_eq!(
        SpoolManager::encode_spool_path_component_for_tests("edge-0").unwrap(),
        "edge-0"
    );
}

#[test]
fn hostile_node_ids_stay_inside_the_configured_spool_root() {
    let temp = tempfile::tempdir().unwrap();
    let hostile = [
        "../../escape",
        "/etc",
        "C:\\Windows\\Temp",
        "\\\\server\\share",
        "//?/C:/x",
    ];
    for node_id in hostile {
        let settings = spool_settings(temp.path(), 1024 * 1024);
        let spool = SpoolManager::for_tests(settings, node_id)
            .unwrap_or_else(|err| panic!("hostile node id {node_id:?} must be encoded: {err}"));
        let root = spool.namespace_root_for_tests().to_path_buf();
        assert!(
            root.starts_with(temp.path()),
            "namespace {} escaped {}",
            root.display(),
            temp.path().display()
        );
        let written = spool.write_events(&[sample_event("evt-node")]).unwrap();
        assert!(written.starts_with(temp.path()));
        let relative = root.strip_prefix(temp.path()).unwrap();
        for component in relative.components() {
            let text = component.as_os_str().to_string_lossy().to_string();
            assert!(!text.contains('/'), "component leaked a separator: {text}");
            assert!(!text.contains('\\'), "component leaked a separator: {text}");
            assert_ne!(text, "..", "component escaped the root");
        }
    }
}

#[test]
fn sibling_instances_never_share_a_spool_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let sink_a = SpoolOwnerSpec {
        node_id: "node-a",
        plugin_config_id: "plugin-a",
        ferrum_namespace: "tenant-a",
        destination_endpoint: "http://ch-a:8123",
        database: "ledger_a",
        table: "charges_a",
    };
    let sink_b = SpoolOwnerSpec {
        node_id: "node-a",
        plugin_config_id: "plugin-b",
        ferrum_namespace: "tenant-b",
        destination_endpoint: "http://ch-b:8123",
        database: "ledger_b",
        table: "charges_b",
    };
    let settings_a = spool_settings(temp.path(), 1024 * 1024);
    let settings_b = spool_settings(temp.path(), 1024 * 1024);
    let a = SpoolManager::for_tests_with_owner(settings_a, &sink_a, 1).unwrap();
    let b = SpoolManager::for_tests_with_owner(settings_b, &sink_b, 2).unwrap();

    assert_ne!(
        a.namespace_root_for_tests(),
        b.namespace_root_for_tests(),
        "distinct plugin/ledger/destination identities must not share a namespace"
    );
    assert_ne!(a.owner_tag_for_tests(), b.owner_tag_for_tests());

    let path_a = a.write_events(&[sample_event("evt-a")]).unwrap();
    let path_b = b.write_events(&[sample_event("evt-b")]).unwrap();
    assert!(path_a.starts_with(a.namespace_root_for_tests()));
    assert!(path_b.starts_with(b.namespace_root_for_tests()));

    // Neither instance can see, replay, or evict the other's records.
    let replayable_a = a.list_replayable_spool_files_for_tests().unwrap();
    let replayable_b = b.list_replayable_spool_files_for_tests().unwrap();
    assert_eq!(replayable_a, vec![path_a.clone()]);
    assert_eq!(replayable_b, vec![path_b.clone()]);
    assert!(path_a.exists());
    assert!(path_b.exists());
}

#[test]
fn only_the_ferrum_namespace_differing_still_partitions_the_spool() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger_a = test_owner_spec("node-a");
    ledger_a.ferrum_namespace = "tenant-a";
    let mut ledger_b = test_owner_spec("node-a");
    ledger_b.ferrum_namespace = "tenant-b";

    let root_a = SpoolManager::namespace_root_path_for_tests(temp.path(), &ledger_a).unwrap();
    let root_b = SpoolManager::namespace_root_path_for_tests(temp.path(), &ledger_b).unwrap();
    assert_ne!(
        root_a, root_b,
        "two ledgers on one node/plugin/destination must not share a namespace"
    );
    let tag_a = SpoolManager::owner_tag_of_spec_for_tests(&ledger_a);
    let tag_b = SpoolManager::owner_tag_of_spec_for_tests(&ledger_b);
    assert_eq!(tag_a.len(), 32, "per-file owner tags must retain 128 bits");
    assert_eq!(tag_b.len(), 32, "per-file owner tags must retain 128 bits");
    assert_ne!(tag_a, tag_b, "per-file owner tags must differ per ledger");
}

#[test]
fn spool_metadata_owner_mismatch_fails_closed_without_mutating_records() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let record = spool.write_events(&[sample_event("evt-owned")]).unwrap();

    let meta_path = spool.namespace_root_for_tests().join("spool.meta.json");
    let raw = fs::read_to_string(&meta_path).unwrap();
    let mut meta: Value = serde_json::from_str(&raw).unwrap();
    meta["table"] = json!("someone_elses_table");
    fs::write(&meta_path, serde_json::to_vec_pretty(&meta).unwrap()).unwrap();

    let err = spool
        .list_replayable_spool_files_for_tests()
        .expect_err("mismatched ownership metadata must fail closed");
    assert!(
        err.contains("does not match this sink identity"),
        "unexpected error: {err}"
    );
    assert!(
        record.exists(),
        "a failed ownership check must never delete billing records"
    );

    // Restoring the record makes replay listing work again.
    fs::write(&meta_path, raw).unwrap();
    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert_eq!(replayable, vec![record]);
}

#[test]
fn version_one_spool_replays_legacy_owner_tags() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let current_record = spool
        .write_events(&[sample_event("evt-legacy-owner-tag")])
        .unwrap();
    let current_tag = spool.owner_tag_for_tests();
    let legacy_tag = &current_tag[..16];

    let meta_path = spool.namespace_root_for_tests().join("spool.meta.json");
    let mut meta: Value = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    assert_eq!(meta["version"], json!(1));
    meta["owner_tag"] = json!(legacy_tag);
    fs::write(&meta_path, serde_json::to_vec_pretty(&meta).unwrap()).unwrap();

    let legacy_name = current_record
        .file_name()
        .unwrap()
        .to_string_lossy()
        .replace(current_tag, legacy_tag);
    let legacy_record = current_record.with_file_name(legacy_name);
    fs::rename(&current_record, &legacy_record).unwrap();

    assert_eq!(
        spool.list_replayable_spool_files_for_tests().unwrap(),
        vec![legacy_record.clone()],
        "version-1 records with the original 16-character tag remain replayable"
    );
    let claim = spool
        .claim_replay_file_for_tests(&legacy_record)
        .unwrap()
        .expect("a legacy-tagged record remains claimable by its digest owner");
    assert!(claim.exists());
    assert!(!legacy_record.exists());
}

#[test]
fn oversized_namespace_metadata_fails_closed_without_mutating_records() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let record = spool.write_events(&[sample_event("evt-owned")]).unwrap();

    // A same-UID actor can inflate the manifest without knowing this owner's
    // tag, because it is read before ownership is established. The bounded read
    // must reject it rather than allocating it inside the billing process.
    let meta_path = spool.namespace_root_for_tests().join("spool.meta.json");
    let raw = fs::read_to_string(&meta_path).unwrap();
    let mut planted = raw.as_bytes().to_vec();
    planted.resize(256 * 1024, b' ');
    fs::write(&meta_path, &planted).unwrap();

    let err = spool
        .list_replayable_spool_files_for_tests()
        .expect_err("an oversized ownership manifest must fail closed");
    assert!(err.contains("artifact bound"), "unexpected error: {err}");
    assert!(
        record.exists(),
        "a rejected manifest must never delete billing records"
    );

    fs::write(&meta_path, raw).unwrap();
    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert_eq!(replayable, vec![record]);
}

#[test]
fn foreign_owner_tagged_records_are_never_replayed_or_evicted() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-own");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let settings = spool_settings(temp.path(), encoded_len);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();

    // A record carrying a different owner tag, planted inside our namespace.
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let foreign = day.join("00000000000000000000000000.0123456789abcdef0123456789abcdef.ndjson");
    fs::write(&foreign, vec![b'x'; encoded_len as usize]).unwrap();

    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "a foreign-owned record must never enter the replay set"
    );
    assert_eq!(
        spool.unbound_record_counts_for_tests(),
        (1, 0),
        "a foreign record discovered after prepare must update live status metrics"
    );
    let owned = spool.list_owned_spool_files_for_tests().unwrap();
    assert!(
        owned.contains(&foreign),
        "a foreign-owned record still counts toward the quota"
    );

    // Quota pressure must fail closed rather than delete another owner's data.
    let err = spool
        .write_events(std::slice::from_ref(&event))
        .expect_err("eviction must not be able to reclaim another owner's bytes");
    assert!(
        err.contains("owned by another identity"),
        "unexpected error: {err}"
    );
    assert!(
        foreign.exists(),
        "a foreign-owned record must survive quota pressure"
    );
}

#[test]
fn spool_scan_ignores_symlinks_and_stays_in_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("secret.ndjson");
    fs::write(&outside_file, b"{\"event_id\":\"leaked\"}\n").unwrap();

    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let link = spool.namespace_root_for_tests().join("escape-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(outside.path(), &link).unwrap();

    let owned = spool.list_owned_spool_files_for_tests().unwrap();
    let root = spool.namespace_root_for_tests().to_path_buf();
    assert!(
        owned.iter().all(|path| path.starts_with(&root)),
        "owned listing must stay inside the managed namespace"
    );
    assert!(
        owned.iter().all(|path| path != &outside_file),
        "symlink targets outside the namespace must not be collected"
    );
    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert!(replayable.is_empty());
    assert!(
        outside_file.exists(),
        "maintenance must never delete through a symlink"
    );
}

#[test]
fn spool_walk_bounds_empty_directory_entries() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let root = spool.namespace_root_for_tests();
    for index in 0..8 {
        fs::create_dir(root.join(format!("empty-{index}"))).unwrap();
    }
    let error = spool
        .list_owned_spool_files_with_entry_limit_for_tests(5)
        .expect_err("empty directories must count toward the traversal bound");
    assert!(
        error.contains("max entry count (5)"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[test]
fn configured_spool_directory_symlink_is_rejected_before_write_probe() {
    let parent = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let linked_spool = parent.path().join("spool-link");
    std::os::unix::fs::symlink(outside.path(), &linked_spool).unwrap();

    let error = match SpoolManager::for_tests(spool_settings(&linked_spool, 1024 * 1024), "node-a")
    {
        Err(error) => error,
        Ok(_) => panic!("a symlinked spool root must fail before its write probe"),
    };
    assert!(
        error.contains("symlinked spool path"),
        "unexpected error: {error}"
    );
    assert!(
        fs::read_dir(outside.path()).unwrap().next().is_none(),
        "failed preparation must not create or truncate files through the symlink"
    );
}

#[cfg(unix)]
#[test]
fn namespace_root_symlink_swap_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let root = spool.namespace_root_for_tests().to_path_buf();
    let saved = root.with_extension("original");
    fs::rename(&root, &saved).unwrap();

    fs::copy(
        saved.join("spool.meta.json"),
        outside.path().join("spool.meta.json"),
    )
    .unwrap();
    let outside_day = outside.path().join("20260524");
    fs::create_dir(&outside_day).unwrap();
    let outside_record = outside_day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FBC"));
    fs::write(&outside_record, b"{}\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), &root).unwrap();

    let error = spool
        .list_replayable_spool_files_for_tests()
        .expect_err("a swapped namespace-root symlink must fail closed");
    assert!(
        error.contains("symlinked spool path") || error.contains("canonical target"),
        "unexpected error: {error}"
    );
    assert!(
        outside_record.exists(),
        "failed-closed maintenance must not mutate the replacement tree"
    );

    fs::remove_file(&root).unwrap();
    fs::rename(&saved, &root).unwrap();
}

#[cfg(unix)]
#[test]
fn spool_scan_survives_directory_cycles_and_bounds_depth() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let root = spool.namespace_root_for_tests().to_path_buf();

    // Self-referential loop: the walk must terminate instead of recursing.
    let loop_dir = root.join("20260524");
    fs::create_dir_all(&loop_dir).unwrap();
    std::os::unix::fs::symlink(&root, loop_dir.join("loop")).unwrap();
    let owned = spool.list_owned_spool_files_for_tests().unwrap();
    assert!(owned.iter().all(|path| path.starts_with(&root)));

    // Depth beyond the traversal bound is reported, never followed silently.
    let mut deep = root.clone();
    for index in 0..12 {
        deep = deep.join(format!("d{index}"));
    }
    fs::create_dir_all(&deep).unwrap();
    let record = deep.join(owned_data_name("00000000000000000000000009"));
    fs::write(&record, b"{}\n").unwrap();
    let err = spool
        .list_owned_spool_files_for_tests()
        .expect_err("traversal beyond the depth bound must fail closed");
    assert!(err.contains("max depth"), "unexpected error: {err}");
}

#[test]
fn reload_generation_does_not_delete_a_live_peer_temp() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let gen1 = SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &spec, 11)
        .unwrap();

    let day = gen1.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let final_path = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
    let active_tmp = gen1.write_temp_path_for_tests(&final_path).unwrap();
    fs::write(&active_tmp, b"partial").unwrap();
    // Model generation 11 mid-write: its temp path is leased for this process.
    let lease = SpoolManager::hold_live_spool_path_for_tests(&active_tmp);

    // A replacement generation runs first-prepare reconciliation while the older
    // accepted generation is still mid-write.
    let gen2 = SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &spec, 12)
        .unwrap();
    assert!(
        active_tmp.exists(),
        "a replacement generation must not unlink a live peer's active temp"
    );
    drop(gen2);

    // Once the writer releases the lease, a later generation reconciles it.
    drop(lease);
    drop(gen1);
    let gen3 = SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &spec, 13)
        .unwrap();
    assert!(
        !active_tmp.exists(),
        "an abandoned same-process temp must be reconciled once no writer holds it"
    );
    drop(gen3);
}

#[test]
fn manifest_write_does_not_collide_with_a_peer_manifest_temp() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let root = SpoolManager::namespace_root_path_for_tests(temp.path(), &spec).unwrap();
    fs::create_dir_all(&root).unwrap();

    // A peer generation or peer process sharing this volume is mid-publish on
    // its own ownership manifest. A fixed `spool.meta.json.tmp` would make this
    // path the same name for every writer: `create_new` would fail and the
    // rollback would then unlink the peer's live temp and the manifest itself.
    let peer_tmp = root.join("spool.meta.json.tmp");
    fs::write(&peer_tmp, b"peer in-progress manifest").unwrap();

    let spool = SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &spec, 41)
        .unwrap();
    let manifest = spool.namespace_root_for_tests().join("spool.meta.json");

    assert!(
        peer_tmp.exists(),
        "publishing the ownership manifest must not unlink a peer writer's temp"
    );
    assert_eq!(
        fs::read(&peer_tmp).unwrap(),
        b"peer in-progress manifest".to_vec(),
        "a peer writer's manifest temp must not be truncated or overwritten"
    );
    assert!(
        manifest.is_file(),
        "the ownership manifest must still be published"
    );
}

#[test]
fn admission_eviction_never_unlinks_a_live_peer_generation_temp() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let event = sample_event("evt-live-temp");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    // Room for exactly one encoded record, so the planted temp blocks admission.
    let settings = spool_settings(temp.path(), encoded_len);

    let gen1 = SpoolManager::for_tests_with_owner(settings.clone(), &spec, 21).unwrap();
    let day = gen1.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let final_path = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FB1"));
    let active_tmp = gen1.write_temp_path_for_tests(&final_path).unwrap();
    fs::write(&active_tmp, vec![0u8; encoded_len as usize]).unwrap();
    // Generation 21 is mid-publish: payload written and fsynced, rename pending.
    let lease = SpoolManager::hold_live_spool_path_for_tests(&active_tmp);

    // A replacement generation holds its own writer lock, so only the shared
    // live-path set can stop its quota eviction from unlinking that temp.
    let gen2 = SpoolManager::for_tests_with_owner(settings.clone(), &spec, 22).unwrap();
    let err = gen2
        .write_events(std::slice::from_ref(&event))
        .expect_err("admission must fail closed rather than evict a live peer temp");
    assert!(
        err.contains("cannot fit within spool.max_bytes"),
        "unexpected error: {err}"
    );
    assert!(
        active_tmp.exists(),
        "eviction must never unlink a peer generation's in-progress temp"
    );

    // Once the writer releases the lease the same quota pressure reclaims it.
    drop(lease);
    let written = gen2.write_events(std::slice::from_ref(&event)).unwrap();
    assert!(written.exists());
    assert!(
        !active_tmp.exists(),
        "an abandoned same-process temp stays reclaimable under quota pressure"
    );
}

#[test]
fn admission_eviction_never_unlinks_a_fresh_peer_process_temp() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let event = sample_event("evt-peer-temp");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let settings = spool_settings(temp.path(), encoded_len);

    // Production stale-temp horizon: another process's fresh temp is protected.
    let spool = SpoolManager::for_tests_with_owner_faults_and_ages(
        settings.clone(),
        &spec,
        31,
        SpoolFsFault::None,
        300,
        300,
    )
    .unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let peer_tmp = day.join(format!(
        "{}.write-deadbeefdeadbeefdeadbeefdeadbeef-7.tmp",
        owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FB2")
    ));
    fs::write(&peer_tmp, vec![0u8; encoded_len as usize]).unwrap();

    let err = spool
        .write_events(std::slice::from_ref(&event))
        .expect_err("a peer process's fresh temp must not be evicted to admit a write");
    assert!(
        err.contains("cannot fit within spool.max_bytes"),
        "unexpected error: {err}"
    );
    assert!(
        peer_tmp.exists(),
        "eviction must respect the stale-temp horizon for peer-process temps"
    );

    // With the horizon elapsed the same temp is reconciled and the write fits.
    let reclaiming = SpoolManager::for_tests_with_owner_faults_and_ages(
        settings,
        &spec,
        32,
        SpoolFsFault::None,
        0,
        300,
    )
    .unwrap();
    assert!(
        !peer_tmp.exists(),
        "an expired peer-process temp is reconciled at first prepare"
    );
    let written = reclaiming
        .write_events(std::slice::from_ref(&event))
        .unwrap();
    assert!(written.exists());
}

#[test]
fn compressed_spool_record_expanding_past_its_bound_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let bomb_plain = vec![b'\n'; 2 * 1024 * 1024];
    let bomb =
        encode_spool_bytes_without_content_size_for_tests(&bomb_plain, SpoolCompression::Zstd)
            .unwrap();
    assert!(
        bomb.len() < 4096,
        "the fixture must exercise a high compression ratio"
    );
    let bomb_path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FB3.ndjson.zst");
    fs::write(&bomb_path, &bomb).unwrap();
    let err = decode_spool_file_for_tests(&bomb_path)
        .expect_err("a high-ratio archive must not expand without bound");
    assert!(
        err.contains("decompression bound"),
        "unexpected error: {err}"
    );

    // A record within the expansion allowance still decodes normally.
    let ok_plain = vec![b'\n'; 512 * 1024];
    let ok = encode_spool_bytes_for_tests(&ok_plain, SpoolCompression::Zstd).unwrap();
    let ok_path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FB4.ndjson.zst");
    fs::write(&ok_path, &ok).unwrap();
    let decoded = decode_spool_file_for_tests(&ok_path).unwrap();
    assert_eq!(decoded.len(), ok_plain.len());
}

#[test]
fn spool_replay_caps_large_encoded_and_decoded_artifacts_absolutely() {
    let hard_limit = spool_artifact_byte_limit_for_tests();
    assert_eq!(
        spool_decompression_limit_for_tests(u64::MAX),
        hard_limit,
        "the ratio allowance must never bypass the absolute artifact ceiling"
    );

    // A sparse file proves the encoded-size boundary is checked from metadata
    // before replay attempts to allocate or read its attacker-selected length.
    let temp = tempfile::tempdir().unwrap();
    let oversized_path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FB5.ndjson");
    let oversized = fs::File::create(&oversized_path).unwrap();
    oversized.set_len(hard_limit.saturating_add(1)).unwrap();
    drop(oversized);
    let err = decode_spool_file_for_tests(&oversized_path)
        .expect_err("an oversized raw artifact must fail before allocation");
    assert!(
        err.contains("hard") && err.contains("artifact bound"),
        "unexpected error: {err}"
    );
}

#[test]
fn peer_process_temp_is_quota_owned_and_never_a_replay_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    // A peer process's in-progress temp: a different process tag.
    let peer_tmp = day.join(format!(
        "{}.write-deadbeefdeadbeefdeadbeefdeadbeef-7.tmp",
        owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FAW")
    ));
    fs::write(&peer_tmp, b"peer-partial").unwrap();

    let owned = spool.list_owned_spool_files_for_tests().unwrap();
    assert!(
        owned.contains(&peer_tmp),
        "a peer temp still counts toward the quota"
    );
    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "an in-progress temp is never a replay candidate"
    );

    // Test managers use a zero stale age, so a later generation's first prepare
    // reconciles the foreign temp instead of leaving it forever.
    let next = SpoolManager::for_tests(spool_settings(temp.path(), 1024 * 1024), "node-a").unwrap();
    assert!(
        !peer_tmp.exists(),
        "a stale peer temp is reconciled once past the stale age"
    );
    drop(next);
}

#[test]
fn atomic_spool_write_fault_injection_surfaces_before_success() {
    let temp = tempfile::tempdir().unwrap();
    let final_path = temp.path().join("batch.ndjson");
    let tmp_path = temp.path().join("batch.ndjson.tmp");
    let mut faults = vec![SpoolFsFault::FileSync, SpoolFsFault::Rename];
    if cfg!(unix) {
        faults.push(SpoolFsFault::DirOpen);
        faults.push(SpoolFsFault::DirSync);
    }
    for fault in faults {
        let _ = fs::remove_file(&tmp_path);
        let _ = fs::remove_file(&final_path);
        let err = write_private_file_atomically_with_fault_for_tests(
            &tmp_path,
            &final_path,
            b"{\"ok\":true}\n",
            fault,
            SpoolFinalOwnership::Unique,
        )
        .expect_err("an injected durable-write fault must fail the write");
        assert!(
            err.contains("injected fault"),
            "unexpected error for {fault:?}: {err}"
        );
        assert!(
            !final_path.exists(),
            "a faulted write must not publish for {fault:?}"
        );
        assert!(
            !tmp_path.exists(),
            "a faulted write must clean its temp for {fault:?}"
        );
    }
    // The unfaulted path still publishes durably.
    write_private_file_atomically_for_tests(
        &tmp_path,
        &final_path,
        b"{\"ok\":true}\n",
        SpoolFinalOwnership::Unique,
    )
    .unwrap();
    assert!(final_path.exists());
}

#[test]
fn rollback_before_rename_preserves_a_peer_published_shared_final() {
    // `spool.meta.json` is one shared name for every writer of a namespace, so a
    // writer that fails before its own rename must never unlink the manifest a
    // peer already published.
    let temp = tempfile::tempdir().unwrap();
    let final_path = temp.path().join("spool.meta.json");
    let peer_bytes: &[u8] = b"{\"published_by\":\"peer\"}\n";
    fs::write(&final_path, peer_bytes).unwrap();

    for fault in [SpoolFsFault::FileSync, SpoolFsFault::Rename] {
        let tmp_path = temp
            .path()
            .join(format!("spool.meta.json.write-{fault:?}.tmp"));
        let err = write_private_file_atomically_with_fault_for_tests(
            &tmp_path,
            &final_path,
            b"{\"published_by\":\"me\"}\n",
            fault,
            SpoolFinalOwnership::Shared,
        )
        .expect_err("an injected pre-rename fault must fail the write");
        assert!(
            err.contains("injected fault"),
            "unexpected error for {fault:?}: {err}"
        );
        assert!(
            !err.contains("rollback cleanup also failed"),
            "a clean rollback must not report a cleanup failure for {fault:?}: {err}"
        );
        assert!(
            !tmp_path.exists(),
            "rollback must still remove this attempt's own temp for {fault:?}"
        );
        assert_eq!(
            fs::read(&final_path).unwrap(),
            peer_bytes,
            "rollback must not unlink a final path this attempt never published ({fault:?})"
        );
    }
}

#[cfg(unix)]
#[test]
fn rollback_after_rename_never_unlinks_a_shared_final() {
    // Both post-rename interleavings of the shared manifest name. A path unlink
    // cannot be made atomic with any proof of which file the name currently
    // resolves to, so the shared final is simply never unlinked: with a peer
    // replacement the peer's newer publication survives, and without one this
    // attempt's own unsynced bytes stay put for the next prepare to validate or
    // regenerate. Either way the durability error is still reported.
    let temp = tempfile::tempdir().unwrap();

    // (a) A peer republishes the shared name between this attempt's rename and
    // its failing directory fsync.
    let raced_final = temp.path().join("raced.spool.meta.json");
    let raced_tmp = temp.path().join("raced.spool.meta.json.write-race.tmp");
    let err = write_private_file_atomically_with_fault_for_tests(
        &raced_tmp,
        &raced_final,
        b"{\"published_by\":\"me\"}\n",
        SpoolFsFault::PeerRepublishThenDirSync,
        SpoolFinalOwnership::Shared,
    )
    .expect_err("an injected directory-sync fault must fail the write");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert!(
        !err.contains("rollback cleanup also failed"),
        "a clean rollback must not report a cleanup failure: {err}"
    );
    assert!(
        !raced_tmp.exists(),
        "rollback must still remove this attempt's own temp"
    );
    assert_eq!(
        fs::read(&raced_final).unwrap(),
        PEER_REPUBLISH_MARKER,
        "rollback must not unlink a peer publication that replaced this attempt's rename"
    );

    // (b) No peer replacement at all: the entry is still this attempt's bytes,
    // and it is still left in place rather than unlinked by path.
    let quiet_final = temp.path().join("quiet.spool.meta.json");
    let quiet_tmp = temp.path().join("quiet.spool.meta.json.write-quiet.tmp");
    let mine: &[u8] = b"{\"published_by\":\"me\"}\n";
    let err = write_private_file_atomically_with_fault_for_tests(
        &quiet_tmp,
        &quiet_final,
        mine,
        SpoolFsFault::DirSync,
        SpoolFinalOwnership::Shared,
    )
    .expect_err("an injected directory-sync fault must fail the write");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert!(
        !quiet_tmp.exists(),
        "rollback must still remove this attempt's own temp"
    );
    assert_eq!(
        fs::read(&quiet_final).unwrap(),
        mine,
        "an unsynced shared final is left for the next prepare, not unlinked by path"
    );
}

#[cfg(unix)]
#[test]
fn rollback_after_rename_removes_a_unique_final() {
    // The counterpart to the shared case: a ULID-derived name has exactly one
    // possible writer, so rollback of a post-rename failure unlinks it and the
    // "never delete" rule stays scoped to shared names only.
    let temp = tempfile::tempdir().unwrap();
    let final_path = temp.path().join(format!("{}.owner-tag.ndjson", new_ulid()));
    let tmp_path = temp.path().join("unique.write-own.tmp");

    let err = write_private_file_atomically_with_fault_for_tests(
        &tmp_path,
        &final_path,
        b"{\"ok\":true}\n",
        SpoolFsFault::DirSync,
        SpoolFinalOwnership::Unique,
    )
    .expect_err("an injected directory-sync fault must fail the write");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert!(
        !err.contains("rollback cleanup also failed"),
        "a clean rollback must not report a cleanup failure: {err}"
    );
    assert!(
        !final_path.exists(),
        "an unsynced publication at a uniquely owned name must be rolled back"
    );
    assert!(
        !tmp_path.exists(),
        "rollback must still remove this attempt's own temp"
    );
}

#[cfg(unix)]
#[test]
fn shared_manifest_rollback_leaves_live_storage_unprepared() {
    // A failed manifest publish must not be laundered into a successful prepare
    // just because the shared final is left on disk: the durability error is
    // still returned, no batch is accepted, and nothing is published.
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let faulted =
        SpoolManager::for_tests_with_owner_and_faults(settings, &spec, 31, SpoolFsFault::DirSync)
            .unwrap();

    let err = faulted
        .write_events(&[sample_event("evt-manifest-unsynced")])
        .expect_err("an unsynced manifest publish must fail the write");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    let replayable = faulted.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "a failed prepare must not publish a replay candidate"
    );

    // The retry is the recovery path the shared-final rule relies on: the next
    // prepare revalidates the manifest left on disk against this sink's identity
    // rather than inheriting a "prepared" baseline, and the still-faulted
    // durable write keeps the batch uncommitted.
    let err = faulted
        .write_events(&[sample_event("evt-manifest-unsynced-2")])
        .expect_err("a retry under the same fault must not silently succeed");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert_eq!(
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        0,
        "no attempt may leave a committed or leftover owned byte behind"
    );
}

#[test]
fn injected_file_sync_failure_keeps_the_spool_batch_uncommitted() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let faulted =
        SpoolManager::for_tests_with_owner_and_faults(settings, &spec, 21, SpoolFsFault::FileSync)
            .unwrap();
    let err = faulted
        .write_events(&[sample_event("evt-not-durable")])
        .expect_err("a failed durable handoff must be reported to the caller");
    assert!(err.contains("injected fault"), "unexpected error: {err}");

    let root = default_test_namespace_root(temp.path());
    assert_eq!(
        disk_owned_bytes(&root),
        0,
        "a write that reported failure must leave no committed or leftover bytes"
    );
    let replayable = faulted.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "a failed write must not publish a replay candidate"
    );
}

#[test]
fn injected_rename_failure_keeps_the_spool_batch_uncommitted() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let faulted =
        SpoolManager::for_tests_with_owner_and_faults(settings, &spec, 23, SpoolFsFault::Rename)
            .unwrap();
    let err = faulted
        .write_events(&[sample_event("evt-no-rename")])
        .expect_err("a failed rename must be reported to the caller");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert_eq!(
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        0,
        "a failed rename must leave no committed or leftover bytes"
    );
}

#[cfg(unix)]
#[test]
fn injected_directory_open_failure_rolls_back_the_publish() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let faulted =
        SpoolManager::for_tests_with_owner_and_faults(settings, &spec, 24, SpoolFsFault::DirOpen)
            .unwrap();
    let err = faulted
        .write_events(&[sample_event("evt-dir-open")])
        .expect_err("a directory-open failure must not be reported as a durable commit");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert_eq!(
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        0,
        "an unpersisted rename must be rolled back, not left as a phantom batch"
    );
}

#[cfg(unix)]
#[test]
fn injected_directory_sync_failure_rolls_back_the_publish() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let faulted =
        SpoolManager::for_tests_with_owner_and_faults(settings, &spec, 22, SpoolFsFault::DirSync)
            .unwrap();
    let err = faulted
        .write_events(&[sample_event("evt-dir-sync")])
        .expect_err("a directory-sync failure must not be reported as a durable commit");
    assert!(err.contains("injected fault"), "unexpected error: {err}");
    assert_eq!(
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        0,
        "an unpersisted rename must be rolled back, not left as a phantom batch"
    );
}

#[tokio::test]
async fn replay_claim_is_excluded_from_eviction_and_released_on_retryable() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[503]).await;

    let temp = tempfile::tempdir().unwrap();
    let probe = sample_event("evt-old");
    let encoded_len = encoded_event_len(&probe, SpoolCompression::None);
    let settings = spool_settings(temp.path(), encoded_len);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let oldest = spool.write_events(std::slice::from_ref(&probe)).unwrap();

    let claim = spool
        .hold_replay_claim_for_tests(&oldest)
        .unwrap()
        .expect("an uncontended claim must succeed");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    assert!(claim_path.exists());
    assert!(!oldest.exists());
    let claim_name = claim_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap()
        .to_string();
    assert!(claim_name.ends_with(".inflight"));

    // Quota pressure while the file is claimed must fail closed, never evict it.
    let err = spool
        .write_events(&[sample_event("evt-new")])
        .expect_err("an in-flight claim is never an eviction candidate");
    assert!(err.contains("in-flight"), "unexpected error: {err}");
    assert!(claim_path.exists(), "in-flight claim must survive eviction");
    drop(claim);

    // Retryable delivery releases the claim back to a durable replayable name.
    let released = spool.release_inflight_file_for_tests(&claim_path).unwrap();
    assert_eq!(released.as_deref(), Some(oldest.as_path()));
    assert!(oldest.exists());
    assert!(!claim_path.exists());

    let err = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("503 must remain retryable");
    assert!(!err.is_empty());
    assert!(
        oldest.exists(),
        "a retryable failure must leave the record durable and replayable"
    );
}

#[test]
fn contended_claim_returns_none_instead_of_stealing() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let old_gen =
        SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &spec, 31)
            .unwrap();
    let new_gen =
        SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &spec, 32)
            .unwrap();

    let record = old_gen
        .write_events(&[sample_event("evt-handoff")])
        .unwrap();
    // Both accepted generations see the same candidate.
    assert_eq!(
        old_gen.list_replayable_spool_files_for_tests().unwrap(),
        new_gen.list_replayable_spool_files_for_tests().unwrap()
    );

    let winner = old_gen
        .hold_replay_claim_for_tests(&record)
        .unwrap()
        .expect("the first claimer wins");
    let loser = new_gen.hold_replay_claim_for_tests(&record).unwrap();
    assert!(
        loser.is_none(),
        "a second accepted generation must not be able to claim the same file"
    );

    // The winner's live claim survives the peer generation's maintenance.
    new_gen.prepare_live_storage_for_tests().unwrap();
    let claim_path = winner.claim_path_for_tests().to_path_buf();
    assert!(
        claim_path.exists(),
        "peer maintenance must not reclaim a live claim"
    );

    // After the winner disappears, the peer recovers the record for delivery.
    drop(winner);
    new_gen.prepare_live_storage_for_tests().unwrap();
    assert!(!claim_path.exists(), "an orphaned claim must be recovered");
    assert_eq!(
        new_gen.list_replayable_spool_files_for_tests().unwrap(),
        vec![record],
        "safe handoff returns the record to the surviving generation"
    );
}

#[test]
fn unexpired_peer_claim_is_left_alone_and_expired_one_is_recovered() {
    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let live_name = owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FB1");
    let expired_name = owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FB2");
    // 2100-01-01T00:00:00Z, comfortably beyond any test clock.
    let far_future = 4_102_444_800i64;
    let live_claim = day.join(format!(
        "{live_name}.claim-deadbeefdeadbeefdeadbeefdeadbeef-9-{far_future}.inflight"
    ));
    let expired_claim = day.join(format!(
        "{expired_name}.claim-deadbeefdeadbeefdeadbeefdeadbeef-9-1.inflight"
    ));
    fs::write(&live_claim, b"{}\n").unwrap();
    fs::write(&expired_claim, b"{}\n").unwrap();

    spool.prepare_live_storage_for_tests().unwrap();
    assert!(
        live_claim.exists(),
        "a peer process's unexpired lease must not be reclaimed"
    );
    assert!(
        !expired_claim.exists(),
        "an expired peer lease must be recovered"
    );
    assert!(
        day.join(&expired_name).exists(),
        "recovery restores the durable replayable name"
    );
}

/// Lexical containment guard run before every managed create/rename/unlink.
fn within_root(candidate: &str) -> Result<(), String> {
    SpoolManager::ensure_path_within_root_for_tests(Path::new("spool"), Path::new(candidate))
}

#[test]
fn managed_path_containment_rejects_escape_and_absolute_replacement() {
    // Ordinary managed descendants, including a no-op `.` component and a `..`
    // that still resolves inside the root.
    within_root("spool/20260524/a.ndjson").expect("a managed descendant is inside");
    within_root("spool/./20260524").expect("a current-dir component is a no-op");
    within_root("spool/a/../b").expect("an interior parent segment is allowed");

    // `..` walking off the front of the candidate is rejected before any
    // filesystem call.
    let popped = within_root("spool/../../etc/passwd").expect_err("escape refused");
    assert!(popped.contains("escapes root"), "{popped}");

    // A sibling tree that merely shares a parent is outside the root.
    let sibling = within_root("other/a.ndjson").expect_err("sibling refused");
    assert!(sibling.contains("outside root"), "{sibling}");

    // An absolute component replaces the join instead of extending it.
    let absolute = within_root("/etc/shadow").expect_err("absolute refused");
    assert!(absolute.contains("outside root"), "{absolute}");
}

#[test]
fn claiming_a_foreign_or_non_replayable_spool_file_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(spool_settings(temp.path(), 1 << 20), "node-a").unwrap();
    assert_eq!(spool.generation_for_tests(), 1);

    let record = spool
        .write_events(&[sample_event("evt-claimable")])
        .unwrap();
    let claim = spool
        .claim_replay_file_for_tests(&record)
        .unwrap()
        .expect("the owner claims its own durable record");
    assert!(claim.exists(), "the claim rename must have happened");
    assert!(!record.exists(), "the durable name is consumed");

    // A claim marker is not itself a replay candidate.
    let non_replayable = spool
        .claim_replay_file_for_tests(&claim)
        .expect_err("an in-flight claim must not be re-claimed");
    assert!(
        non_replayable.contains("refusing to claim non-replayable spool file"),
        "{non_replayable}"
    );

    // A record carrying another owner's tag is never claimable, read, or moved.
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let foreign_tag = "00112233445566778899aabbccddeeff";
    assert_ne!(foreign_tag, default_test_owner_tag());
    let foreign = day.join(format!("01ARZ3NDEKTSV4RRFFQ69G5FB7.{foreign_tag}.ndjson"));
    fs::write(&foreign, b"{}\n").unwrap();
    let refused = spool
        .claim_replay_file_for_tests(&foreign)
        .expect_err("a foreign-tagged record must not be claimable");
    assert!(refused.contains("owned by another identity"), "{refused}");
    assert!(foreign.exists(), "a foreign record must not be touched");

    // Releasing a path that carries no claim marker is refused rather than
    // renaming an arbitrary managed file.
    let not_a_claim = spool
        .release_inflight_file_for_tests(&foreign)
        .expect_err("only claim markers can be released");
    assert!(
        not_a_claim.contains("missing a claim marker"),
        "{not_a_claim}"
    );
    assert!(foreign.exists(), "a refused release mutates nothing");
}

#[test]
fn unattributed_claim_is_recovered_only_after_its_lease_horizon() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    // A long lease horizon: an unparseable claim marker is treated as a peer's
    // live work and left alone.
    let patient = SpoolManager::for_tests_with_owner_faults_and_ages(
        spool_settings(temp.path(), 1 << 20),
        &spec,
        41,
        SpoolFsFault::None,
        300,
        3_600,
    )
    .unwrap();
    let day = patient.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let data_name = owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FB8");
    let mangled = day.join(format!("{data_name}.claim-not-a-valid-marker.inflight"));
    fs::write(&mangled, b"{}\n").unwrap();

    patient.prepare_live_storage_for_tests().unwrap();
    assert!(
        mangled.exists(),
        "an unattributable claim inside its lease horizon must be left alone"
    );
    assert!(
        !day.join(&data_name).exists(),
        "nothing may be published back to the replayable name yet"
    );

    // The same marker past its horizon is recovered to the durable name.
    let impatient = SpoolManager::for_tests_with_owner_faults_and_ages(
        spool_settings(temp.path(), 1 << 20),
        &spec,
        42,
        SpoolFsFault::None,
        300,
        0,
    )
    .unwrap();
    assert!(
        !mangled.exists(),
        "an unattributable claim past its lease horizon is recovered"
    );
    assert!(
        day.join(&data_name).exists(),
        "recovery restores the durable replayable name"
    );
    assert_eq!(
        impatient.list_replayable_spool_files_for_tests().unwrap(),
        vec![day.join(&data_name)],
        "the recovered record becomes replayable again"
    );
}

#[test]
fn claim_renewal_moves_the_lease_deadline_without_releasing_the_record() {
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(spool_settings(temp.path(), 1 << 20), "node-a").unwrap();
    let record = spool.write_events(&[sample_event("evt-renew")]).unwrap();
    let mut claim = spool
        .hold_replay_claim_for_tests(&record)
        .unwrap()
        .expect("the owner claims its own durable record");
    let first = claim.claim_path_for_tests().to_path_buf();

    // 2100-01-01T00:00:00Z, unambiguously distinct from the initial deadline.
    let far_future = 4_102_444_800i64;
    spool
        .renew_claim_at_for_tests(&mut claim, far_future)
        .unwrap();
    let renewed = claim.claim_path_for_tests().to_path_buf();
    let renewed_name = renewed.file_name().unwrap().to_string_lossy().to_string();

    assert_ne!(first, renewed, "renewal moves the lease deadline");
    assert!(renewed_name.ends_with(&format!("-{far_future}.inflight")));
    assert!(!first.exists(), "the previous claim name is gone");
    assert!(renewed.exists(), "the renewed claim holds the record");
    assert!(!record.exists(), "the durable name stays claimed");

    // A live renewed claim is still protected from peer maintenance.
    spool.prepare_live_storage_for_tests().unwrap();
    assert!(
        renewed.exists(),
        "a live renewed claim must not be reclaimed by maintenance"
    );

    let released = spool
        .release_inflight_file_for_tests(&renewed)
        .unwrap()
        .expect("release restores the durable record");
    assert_eq!(released, record);
    assert!(record.exists(), "the payload is replayable again");
}

#[tokio::test]
async fn replay_removes_a_claimed_spool_file_with_no_rows() {
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(spool_settings(temp.path(), 1 << 20), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let empty = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FB9"));
    fs::write(&empty, b"\n   \n").unwrap();

    // The unreachable address proves no delivery is attempted: the claimed file
    // carries no rows, so it is finalized without a ClickHouse call.
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/insert")
        .await
        .expect("a row-less spool file must not fail the replay tick");

    assert!(
        !empty.exists(),
        "a row-less spool file is claimed and removed"
    );
    assert!(
        spool
            .list_replayable_spool_files_for_tests()
            .unwrap()
            .is_empty(),
        "no claim or durable remnant may be left behind"
    );
}

#[tokio::test]
async fn replay_outcomes_delivered_permanent_and_claim_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);

    let server_ok = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server_ok)
        .await;
    let delivered = spool
        .write_events(&[sample_event("evt-delivered")])
        .unwrap();
    replay_spool_once_for_tests(&spool, &server_ok.uri())
        .await
        .unwrap();
    assert!(!delivered.exists(), "a delivered claim must be removed");
    let owned = spool.list_owned_spool_files_for_tests().unwrap();
    assert!(
        owned.is_empty(),
        "a delivered replay must leave no claim behind: {owned:?}"
    );

    let server_perm = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server_perm)
        .await;
    let poison = spool
        .write_events(&[sample_event("evt-permanent")])
        .unwrap();
    replay_spool_once_for_tests(&spool, &server_perm.uri())
        .await
        .unwrap();
    assert_rejected_sidecar(&poison, 400, "permanent_http");
    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "a permanently rejected record must leave the replay set"
    );
}

#[test]
fn legacy_and_orphaned_namespaces_are_reported_but_never_replayed() {
    let temp = tempfile::tempdir().unwrap();
    let spec = test_owner_spec("node-a");
    let root = SpoolManager::namespace_root_path_for_tests(temp.path(), &spec).unwrap();
    let plugin_dir = root.parent().unwrap().to_path_buf();
    let node_dir = plugin_dir.parent().unwrap().to_path_buf();

    // Pre-namespace layout: `<spool.dir>/<node>/<YYYYMMDD>/<ULID>.ndjson`.
    let legacy_day = node_dir.join("20260101");
    fs::create_dir_all(&legacy_day).unwrap();
    let legacy = legacy_day.join("00000000000000000000000000.ndjson");
    fs::write(&legacy, b"{\"event_id\":\"legacy\"}\n").unwrap();

    // A namespace orphaned by a destination change.
    let orphan_ns = plugin_dir.join("o00000000000000000000000000000000");
    let orphan_day = orphan_ns.join("20260102");
    fs::create_dir_all(&orphan_day).unwrap();
    let orphan = orphan_day.join("00000000000000000000000001.ndjson");
    fs::write(&orphan, b"{\"event_id\":\"old-destination\"}\n").unwrap();

    let settings = spool_settings(temp.path(), 1024 * 1024);
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let (files, namespaces) = spool.unbound_record_counts_for_tests();
    assert_eq!(files, 2, "both unbound records must be reported");
    assert_eq!(namespaces, 1, "the orphaned namespace must be reported");
    let replayable = spool.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "unbound records must never be replayed to the newly configured destination"
    );

    // Writing under the new identity leaves the unbound records untouched.
    spool.write_events(&[sample_event("evt-new")]).unwrap();
    assert!(legacy.exists(), "legacy records must never be deleted");
    assert!(orphan.exists(), "orphaned records must never be deleted");
}

#[test]
fn unbound_scan_shares_one_entry_budget_across_sibling_namespaces() {
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(spool_settings(temp.path(), 1 << 20), "node-a").unwrap();
    let root = spool.namespace_root_for_tests();
    let plugin_dir = root.parent().unwrap();

    let mut records = Vec::new();
    for index in 1..=4 {
        let day = plugin_dir.join(format!("o{index:032x}")).join("20260101");
        fs::create_dir_all(&day).unwrap();
        let record = day.join(format!("{index:026}.ndjson"));
        fs::write(&record, b"{\"event_id\":\"orphan\"}\n").unwrap();
        records.push(record);
    }

    // The node directory consumes one entry and the plugin directory contains
    // the live namespace plus these four siblings. Six entries therefore
    // exhaust one aggregate budget before any sibling can receive a fresh
    // recursive allowance.
    let (files, namespaces, truncated) = spool.scan_unbound_records_with_entry_limit_for_tests(6);
    assert!(truncated, "the aggregate scan must report its global cap");
    assert!(
        files < records.len() as u64 && namespaces < records.len() as u64,
        "a bounded scan must not restart the entry budget for every sibling namespace"
    );
    assert!(
        records.iter().all(|record| record.exists()),
        "a truncated unbound scan is observability-only and must not mutate records"
    );
}

#[test]
fn destination_change_moves_to_a_fresh_namespace_without_rerouting() {
    let temp = tempfile::tempdir().unwrap();
    let mut before = test_owner_spec("node-a");
    before.table = "charges_v1";
    let mut after = test_owner_spec("node-a");
    after.table = "charges_v2";

    let old = SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &before, 1)
        .unwrap();
    let stranded = old.write_events(&[sample_event("evt-v1")]).unwrap();
    drop(old);

    let new = SpoolManager::for_tests_with_owner(spool_settings(temp.path(), 1 << 20), &after, 2)
        .unwrap();
    assert!(
        !stranded.starts_with(new.namespace_root_for_tests()),
        "a destination change must move to a fresh managed namespace"
    );
    let replayable = new.list_replayable_spool_files_for_tests().unwrap();
    assert!(
        replayable.is_empty(),
        "records for the previous destination must not be replayed to the new one"
    );
    let (files, namespaces) = new.unbound_record_counts_for_tests();
    assert_eq!(files, 1);
    assert_eq!(namespaces, 1);
    assert!(
        stranded.exists(),
        "the stranded record is retained for the operator"
    );
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn staged_and_rejected_generations_never_touch_the_spool() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(server.uri());

    // Stage a candidate without committing it: nothing may be created on disk.
    let staged = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    staged.start_background_tasks().unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let entries: Vec<_> = fs::read_dir(temp.path())
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert!(
        entries.is_empty(),
        "a staged, never-accepted generation must not create spool state: {entries:?}"
    );
    assert!(
        !staged.owns_active_sink(),
        "staging must not publish an accepted sink"
    );

    // Dropping without commit models a rejected plugin-cache generation.
    drop(staged);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after: Vec<_> = fs::read_dir(temp.path())
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert!(
        after.is_empty(),
        "a rejected generation must leave no spool side effects: {after:?}"
    );
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.is_empty(),
        "a rejected generation must never deliver externally"
    );
}

#[test]
fn snapshot_call_count_preserves_values_above_u32_max() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    accumulator.seed_call_count_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        u32::MAX as u64,
    );
    let at_max = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-u32-max")
        .unwrap();
    assert_eq!(at_max.len(), 1);
    assert_eq!(at_max[0].call_count, u32::MAX as u64);

    let accumulator = SnapshotAccumulator::new();
    accumulator.seed_call_count_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        (u32::MAX as u64) + 1,
    );
    let above = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-u32-plus-one")
        .unwrap();
    assert_eq!(above.len(), 1);
    assert_eq!(above[0].call_count, (u32::MAX as u64) + 1);

    let encoded = serialize_json_each_row(&above).unwrap();
    assert!(
        encoded.contains(&format!("\"call_count\":{}", (u32::MAX as u64) + 1)),
        "JSONEachRow must serialize lossless u64 call_count: {encoded}"
    );
}

#[test]
fn snapshot_cleanup_preserves_pending_unemitted_totals() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        unit_call_charge(0.01),
    );
    // First-tick / never-emitted: TTL zero must not discard pending totals.
    assert_eq!(accumulator.cleanup_stale_for_tests(0), 0);
    let first = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-pending")
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].call_count, 1);

    // After durable baseline commit, idle cleanup may remove the entry.
    assert_eq!(accumulator.cleanup_stale_for_tests(0), 1);
}

#[test]
fn snapshot_cleanup_preserves_pending_during_spool_outage_baseline() {
    let config = snapshot_test_config();
    let accumulator = SnapshotAccumulator::new();
    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        unit_call_charge(0.01),
    );
    let _ = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-1")
        .unwrap();
    // Additional charge after baseline: simulates failed spool leaving baseline
    // unadvanced while traffic stops.
    accumulator.record_for_test(
        "ferrum",
        "alice",
        "proxy-a",
        "Payments",
        200,
        "http",
        unit_call_charge(0.01),
    );
    assert_eq!(
        accumulator.cleanup_stale_for_tests(0),
        0,
        "pending delta above durable baseline must survive stale cleanup"
    );
    let second = accumulator
        .compute_deltas(&config, "node-a", 200, "snap-2")
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].call_count, 1);
}

#[test]
fn config_validation_rejects_stale_ttl_shorter_than_snapshot_interval() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["mode"] = json!("snapshot");
    config["snapshot"] = json!({
        "interval_secs": 300,
        "cleanup_interval_secs": 1,
        "stale_entry_ttl_secs": 2
    });
    let err = match ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum") {
        Ok(_) => panic!("ttl shorter than interval must fail"),
        Err(err) => err,
    };
    assert!(
        err.contains("stale_entry_ttl_secs must be >= snapshot.interval_secs"),
        "unexpected error: {err}"
    );
}

#[test]
fn snapshot_cardinality_overflow_bounds_entries_and_preserves_protocol_dimensions() {
    let temp = tempfile::tempdir().unwrap();
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 10 * 1024 * 1024,
        replay_interval_secs: 3600,
        delivery_queue_capacity: 128,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let accumulator = SnapshotAccumulator::with_limits(1, 16 * 1024 * 1024);
    let charge = unit_call_charge(0.01);

    // Occupy the sole accumulator slot with an HTTP identity.
    accumulator.record_for_test("ferrum", "alice", "proxy-http", "HTTP", 200, "http", charge);
    assert_eq!(accumulator.entry_count(), 1);

    // Additional distinct identities must not expand cardinality.
    accumulator.record_for_test(
        "ferrum",
        "bob",
        "proxy-http-2",
        "HTTP2",
        200,
        "http",
        charge,
    );
    assert_eq!(
        accumulator.entry_count(),
        1,
        "hard max_entries must reject new identities into the map"
    );

    // Durable overflow staging preserves the billable event without merging.
    let overflow = sample_event("overflow-http");
    assert!(accumulator.stage_overflow_event_for_tests(overflow.clone()));
    spool.write_events(&[overflow]).unwrap();
    let files = spool.scan_stats().unwrap();
    assert!(files.files >= 1, "overflow must be durably spooled");

    // Stream and websocket dimensions stay distinct when under budget.
    let config = snapshot_test_config();
    let wide = SnapshotAccumulator::with_limits(10, 16 * 1024 * 1024);
    wide.record_for_test("ferrum", "s1", "proxy-s", "Stream", 0, "tcp", charge);
    wide.record_for_test("ferrum", "w1", "proxy-w", "WS", 0, "ws", charge);
    let mut events = wide
        .compute_deltas(&config, "node-a", 100, "snap-dims")
        .unwrap();
    events.sort_by(|a, b| a.protocol.cmp(&b.protocol));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].protocol, "tcp");
    assert_eq!(events[1].protocol, "ws");
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn repeated_reload_under_permanent_spool_failure_bounds_full_generations() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_finalize_snapshot_for_test,
        api_chargeback_sink_snapshot_accumulator_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    // Point spool at a path that cannot accept durable writes after commit by
    // using a regular file where a directory is required.
    let blocked = temp.path().join("not-a-dir");
    fs::write(&blocked, b"blocked").unwrap();

    let mut plugins = Vec::new();
    for idx in 0..4 {
        let mut config = valid_config(temp.path());
        config["mode"] = json!("snapshot");
        config["spool"]["dir"] = json!(blocked.to_string_lossy());
        config["snapshot"] = json!({
            "interval_secs": 30,
            "cleanup_interval_secs": 300,
            "stale_entry_ttl_secs": 3600,
            "max_entries": 1000,
            "max_retained_bytes": 1_048_576
        });
        config["pricing_tiers"] = json!([{"status_codes": [200], "price_per_call": 0.01}]);
        // Unique plugin-config ids so each activation is a distinct generation.
        let plugin = ApiChargebackSink::new_with_config_id(
            &config,
            PluginHttpClient::default(),
            "ferrum",
            Some(&format!("cfg-{idx}")),
        );
        // Construction is shape-only; live spool prepare happens at start.
        match plugin {
            Ok(plugin) => {
                if plugin.start_background_tasks().is_err() {
                    // Fail-closed when spool cannot be prepared is acceptable.
                    continue;
                }
                plugin.commit_background_tasks();
                if let Some(acc) = api_chargeback_sink_snapshot_accumulator_for_test(&plugin) {
                    acc.record_for_test(
                        "ferrum",
                        "alice",
                        "proxy-a",
                        "Payments",
                        200,
                        "http",
                        unit_call_charge(0.01),
                    );
                }
                let _ = api_chargeback_sink_finalize_snapshot_for_test(&plugin).await;
                plugins.push(plugin);
            }
            Err(_) => {
                // Fail-closed admission when pending recovery budget is exhausted
                // is an acceptable outcome of repeated permanent spool failure.
            }
        }
    }

    let status: Value = serde_json::from_str(&render_status_json()).unwrap();
    let pending = status["snapshot_finalizations_pending"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        pending <= 64,
        "pending finalizations must stay count-bounded: {status}"
    );
    assert!(
        status["snapshot_finalization_recovery_policy"]
            .as_str()
            .unwrap_or("")
            .contains("restore_spool_writability"),
        "status must expose explicit recovery policy: {status}"
    );
    assert!(
        status.get("snapshot_finalizations_pending_bytes").is_some(),
        "status must expose pending recovery bytes: {status}"
    );
    drop(plugins);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn compact_recovery_survives_subsequent_full_finalize_after_mapping() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_finalize_snapshot_for_test,
        api_chargeback_sink_force_compact_snapshot_finalization_for_test,
        api_chargeback_sink_snapshot_accumulator_for_test,
        api_chargeback_sink_snapshot_compact_recovery_registered_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();

    let mut config = valid_config(temp.path());
    config["mode"] = json!("snapshot");
    config["spool"]["dir"] = json!(spool_dir.to_string_lossy());
    config["snapshot"] = json!({
        "interval_secs": 30,
        "cleanup_interval_secs": 300,
        "stale_entry_ttl_secs": 3600,
        "max_entries": 1000,
        "max_retained_bytes": 1_048_576
    });
    config["pricing_tiers"] = json!([{"status_codes": [200], "price_per_call": 0.01}]);

    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("compact-mapping"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();
    if let Some(acc) = api_chargeback_sink_snapshot_accumulator_for_test(&plugin) {
        acc.record_for_test(
            "ferrum",
            "alice",
            "proxy-a",
            "Payments",
            200,
            "http",
            unit_call_charge(0.01),
        );
    }

    // Permanent write failure after admission: replace the spool directory with a
    // regular file so Compact retries cannot drain recovery state.
    fs::remove_dir_all(&spool_dir).unwrap();
    fs::write(&spool_dir, b"blocked").unwrap();

    // Transfer pending deltas to Compact while the Full handle remains alive.
    assert!(
        api_chargeback_sink_force_compact_snapshot_finalization_for_test(&plugin),
        "failed finalization must compact to durable recovery state"
    );
    assert_eq!(
        api_chargeback_sink_snapshot_compact_recovery_registered_for_test(&plugin),
        Some(true),
        "Compact recovery must own the generation after mapping"
    );

    let status_before: Value = serde_json::from_str(&render_status_json()).unwrap();
    let pending_before = status_before["snapshot_finalizations_pending"]
        .as_u64()
        .unwrap_or(0);
    let bytes_before = status_before["snapshot_finalizations_pending_bytes"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        pending_before >= 1 && bytes_before > 0,
        "compact recovery must remain observable: {status_before}"
    );

    // A later Full finalize against the cleared accumulator must not unregister
    // Compact or claim empty success that drops billable recovery state.
    let _ = api_chargeback_sink_finalize_snapshot_for_test(&plugin).await;
    assert_eq!(
        api_chargeback_sink_snapshot_compact_recovery_registered_for_test(&plugin),
        Some(true),
        "Full finalize after compaction must preserve Compact ownership while spool remains unwritable"
    );

    let status_after: Value = serde_json::from_str(&render_status_json()).unwrap();
    assert!(
        status_after["snapshot_finalizations_pending"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "pending compact recovery must survive Full remapping attempts: {status_after}"
    );
    assert!(
        status_after["snapshot_finalizations_pending_bytes"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "compact retained bytes must survive Full remapping attempts: {status_after}"
    );
    drop(plugin);
}

fn snapshot_sink_config(spool_dir: &Path, max_entries: usize) -> Value {
    let mut config = valid_config(spool_dir);
    config["mode"] = json!("snapshot");
    config["spool"]["dir"] = json!(spool_dir.to_string_lossy());
    config["snapshot"] = json!({
        "interval_secs": 30,
        "cleanup_interval_secs": 300,
        "stale_entry_ttl_secs": 3600,
        "max_entries": max_entries,
        "max_retained_bytes": 16_777_216
    });
    config["pricing_tiers"] = json!([{"status_codes": [200], "price_per_call": 0.01}]);
    config
}

/// Issue #1: overflow delivery is bounded, owned, non-blocking, and only counts
/// a durable success after the async worker's blocking write genuinely lands.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn snapshot_overflow_delivery_is_nonblocking_and_durably_acknowledged() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_snapshot_overflow_counters_for_test,
        api_chargeback_sink_spool_snapshot_overflow_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("overflow-async"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    // Route a cardinality overflow charge through the non-blocking delivery path.
    assert!(api_chargeback_sink_spool_snapshot_overflow_for_test(
        &plugin,
        sample_event("overflow-async-1")
    ));

    // Durable-success counters advance only after the worker's blocking write.
    let mut spooled = 0u64;
    for _ in 0..200 {
        let (s, pending, rejections) =
            api_chargeback_sink_snapshot_overflow_counters_for_test(&plugin).unwrap();
        assert_eq!(rejections, 0, "a writable spool must never record a loss");
        assert_eq!(
            pending, 0,
            "a writable spool must not stage bounded overflow"
        );
        if s >= 1 {
            spooled = s;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        spooled, 1,
        "overflow charge must be durably spooled via the bounded async worker"
    );
    assert!(
        disk_owned_bytes(&spool_dir) > 0,
        "durable overflow acknowledgement must leave a spool file on disk"
    );
    drop(plugin);
}

/// Issue #1: when the async spool write fails, the exact overflow event is
/// re-staged in bounded overflow (not silently lost) and no cardinality loss is
/// recorded while bounded staging still has room.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn snapshot_overflow_delivery_write_failure_stages_within_bound() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_snapshot_overflow_counters_for_test,
        api_chargeback_sink_spool_snapshot_overflow_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("overflow-async-fallback"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    // Make every spool write fail by replacing the directory with a file.
    fs::remove_dir_all(&spool_dir).unwrap();
    fs::write(&spool_dir, b"blocked").unwrap();

    assert!(api_chargeback_sink_spool_snapshot_overflow_for_test(
        &plugin,
        sample_event("overflow-async-fallback-1")
    ));

    let mut pending_seen = 0u64;
    for _ in 0..200 {
        let (spooled, pending, rejections) =
            api_chargeback_sink_snapshot_overflow_counters_for_test(&plugin).unwrap();
        assert_eq!(
            spooled, 0,
            "a failed write must not count a durable success"
        );
        assert_eq!(
            rejections, 0,
            "bounded staging still has room, so no cardinality loss"
        );
        if pending >= 1 {
            pending_seen = pending;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        pending_seen, 1,
        "a failed async write must re-stage the exact event in bounded overflow"
    );
    drop(plugin);
}

/// A queued overflow owns its recovery payload until durable success. Aborting
/// an uncommitted delivery worker must re-stage that payload before releasing
/// lifecycle delivery ownership.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn snapshot_overflow_queue_abort_restages_before_delivery_release() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_abort_spool_delivery_for_test,
        api_chargeback_sink_snapshot_overflow_counters_for_test,
        api_chargeback_sink_spool_snapshot_overflow_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("overflow-abort-recovery"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");

    // Leave the worker behind its commit gate so the event is certainly queued
    // when abort drops the receiver.
    assert!(api_chargeback_sink_spool_snapshot_overflow_for_test(
        &plugin,
        sample_event("overflow-abort-recovery-1")
    ));
    assert!(api_chargeback_sink_abort_spool_delivery_for_test(&plugin));

    let mut pending_seen = 0u64;
    for _ in 0..200 {
        let (spooled, pending, rejections) =
            api_chargeback_sink_snapshot_overflow_counters_for_test(&plugin).unwrap();
        assert_eq!(spooled, 0, "an uncommitted worker cannot spool the event");
        assert_eq!(
            rejections, 0,
            "bounded recovery has room and must not record loss"
        );
        if pending >= 1 {
            pending_seen = pending;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        pending_seen, 1,
        "worker abort must re-stage its queued snapshot overflow payload"
    );
    drop(plugin);
}

/// Issue #2: compaction refuses to clear full-generation state while an
/// admission guard is held and succeeds on retry once the admitted hook drains.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn compaction_refuses_while_admitted_and_succeeds_after_drain() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_compact_refuses_while_admitted_then_succeeds_for_test,
        api_chargeback_sink_snapshot_accumulator_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1000);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("compaction-quiescence"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    // Seed a pending delta so compaction has real state to transfer.
    if let Some(acc) = api_chargeback_sink_snapshot_accumulator_for_test(&plugin) {
        acc.record_for_test(
            "ferrum",
            "alice",
            "proxy-a",
            "Payments",
            200,
            "http",
            unit_call_charge(0.01),
        );
    }

    let (refused_while_admitted, compacted_after_drain) =
        api_chargeback_sink_compact_refuses_while_admitted_then_succeeds_for_test(&plugin)
            .expect("snapshot lifecycle must exist");
    assert!(
        refused_while_admitted,
        "compaction must refuse to clear full state while an admission guard is held"
    );
    assert!(
        compacted_after_drain,
        "compaction must succeed once the admitted hook has drained"
    );
    drop(plugin);
}

#[tokio::test]
async fn compaction_refuses_while_overflow_delivery_can_stage_back() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_compact_refuses_while_overflow_delivery_for_test,
        api_chargeback_sink_snapshot_accumulator_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1000);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("compaction-delivery-quiescence"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    if let Some(acc) = api_chargeback_sink_snapshot_accumulator_for_test(&plugin) {
        assert!(acc.stage_overflow_event_for_tests(sample_event("delivery-pending")));
    }

    let (refused_while_delivery, compacted_after_drain) =
        api_chargeback_sink_compact_refuses_while_overflow_delivery_for_test(&plugin)
            .expect("snapshot lifecycle");
    assert!(
        refused_while_delivery,
        "compaction must retain Full ownership while a delivery can stage back"
    );
    assert!(
        compacted_after_drain,
        "compaction should succeed after overflow delivery ownership drains"
    );
    drop(plugin);
}

/// A compaction that refuses *after* preparation drained the staged overflow
/// must give that overflow back and must not disable the generation's periodic
/// emitter. Preparation takes the staged overflow rather than cloning it, so a
/// refusal that simply dropped its local vector would destroy the only
/// authoritative copy of those billing deltas while the code claims the Full
/// generation is retained for a later retry.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn compaction_projection_shortfall_restages_overflow_and_keeps_retry_alive() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_compact_projection_shortfall_for_test,
        api_chargeback_sink_snapshot_accumulator_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1000);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("compaction-projection-shortfall"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    let accumulator =
        api_chargeback_sink_snapshot_accumulator_for_test(&plugin).expect("snapshot accumulator");
    assert!(accumulator.stage_overflow_event_for_tests(sample_event("shortfall-pending-a")));
    assert!(accumulator.stage_overflow_event_for_tests(sample_event("shortfall-pending-b")));
    let charged_before = accumulator.retained_bytes_for_tests();

    let (compacted, overflow_pending, periodic_task_alive) =
        api_chargeback_sink_compact_projection_shortfall_for_test(&plugin)
            .expect("snapshot lifecycle");

    assert!(
        !compacted,
        "a measured payload above the reserved projection must fail closed, not publish an undercharged compact recovery"
    );
    assert_eq!(
        overflow_pending, 2,
        "the refused compaction must return every staged overflow charge it borrowed"
    );
    assert!(
        periodic_task_alive,
        "a refused compaction must not abort the retained generation's periodic emitter; that task is its retry path"
    );
    assert_eq!(
        accumulator.retained_bytes_for_tests(),
        charged_before,
        "restaged overflow must re-reserve exactly the bytes preparation released"
    );

    drop(plugin);
}

/// Full→Compact compaction must own the generation's pending deltas for the
/// whole prepare→publish interval, not just at preparation.
///
/// The periodic and final emitters hold the generation's emission lock across
/// their own prepare-deltas → durable-spool → advance-baseline sequence. If
/// compaction only took that lock while preparing, an emitter could durably
/// emit and advance the same baseline after compaction snapshotted its deltas
/// and before it published them, so the same charge would be billed twice.
/// Holding the emission lock during this test must therefore block compaction
/// outright, and releasing it must let compaction complete.
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn compaction_cannot_interleave_with_snapshot_emission() {
    use ferrum_edge::_test_support::{
        api_chargeback_sink_compact_excluded_by_emission_lock_for_test,
        api_chargeback_sink_snapshot_accumulator_for_test,
    };

    let temp = tempfile::tempdir().unwrap();
    let spool_dir = temp.path().join("spool");
    fs::create_dir_all(&spool_dir).unwrap();
    let config = snapshot_sink_config(&spool_dir, 1000);
    let plugin = ApiChargebackSink::new_with_config_id(
        &config,
        PluginHttpClient::default(),
        "ferrum",
        Some("compaction-emission-exclusion"),
    )
    .expect("construct snapshot sink");
    plugin
        .start_background_tasks()
        .expect("start snapshot sink");
    plugin.commit_background_tasks();

    let accumulator =
        api_chargeback_sink_snapshot_accumulator_for_test(&plugin).expect("snapshot accumulator");
    assert!(accumulator.stage_overflow_event_for_tests(sample_event("exclusion-pending")));

    let (blocked_while_emission_held, compacted_after_release) =
        api_chargeback_sink_compact_excluded_by_emission_lock_for_test(
            &plugin,
            Duration::from_millis(250),
        )
        .expect("snapshot lifecycle");

    assert!(
        blocked_while_emission_held,
        "compaction must not reach its commit while an emission owns the generation's pending deltas"
    );
    assert!(
        compacted_after_release,
        "compaction must complete once the emission releases ownership"
    );

    drop(plugin);
}

/// Issue #3: concurrent new-key insertion, same-key refresh, and overflow
/// staging never push the accumulator past its hard entry/byte ceilings, and no
/// charge is double-counted or silently dropped.
#[test]
fn snapshot_admission_reservation_never_exceeds_hard_limits_under_concurrency() {
    const MAX_ENTRIES: usize = 64;
    // Small enough that the retained-byte ceiling also binds before max_entries.
    const MAX_BYTES: usize = 8 * 1024;
    const THREADS: usize = 8;
    const PER_THREAD: usize = 4_000;
    // More distinct identities than the entry ceiling forces overflow, and
    // reusing them across all threads forces new-key/refresh races on hot keys.
    const DISTINCT_KEYS: usize = 200;

    let accumulator = Arc::new(SnapshotAccumulator::with_limits(MAX_ENTRIES, MAX_BYTES));
    let barrier = Arc::new(Barrier::new(THREADS));
    let accumulated = Arc::new(AtomicU64::new(0));
    let overflowed = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let acc = Arc::clone(&accumulator);
        let barrier = Arc::clone(&barrier);
        let accumulated = Arc::clone(&accumulated);
        let overflowed = Arc::clone(&overflowed);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..PER_THREAD {
                let key = (i + t) % DISTINCT_KEYS;
                let consumer = format!("consumer-{key}");
                let accepted = acc.record_accumulated_for_test(
                    "ferrum",
                    &consumer,
                    "proxy",
                    "Proxy",
                    200,
                    "http",
                    unit_call_charge(0.01),
                );
                if accepted {
                    accumulated.fetch_add(1, Ordering::Relaxed);
                } else {
                    overflowed.fetch_add(1, Ordering::Relaxed);
                }
                // Race overflow staging against entry admission on the shared
                // combined byte ceiling from some threads.
                if t % 2 == 0 && i % 8 == 0 {
                    let _ =
                        acc.stage_overflow_event_for_tests(sample_event(&format!("ov-{t}-{i}")));
                }
                // Hard ceilings must hold at every observation.
                assert!(
                    acc.entry_count() <= MAX_ENTRIES,
                    "entry count exceeded the hard ceiling"
                );
                assert!(
                    acc.retained_bytes_for_tests() <= MAX_BYTES,
                    "combined retained bytes exceeded the hard ceiling"
                );
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let total = (THREADS * PER_THREAD) as u64;
    let accumulated = accumulated.load(Ordering::Relaxed);
    let overflowed = overflowed.load(Ordering::Relaxed);
    assert_eq!(
        accumulated + overflowed,
        total,
        "every record must be accumulated or overflowed exactly once"
    );
    assert!(
        overflowed > 0,
        "the test must actually exercise the overflow path"
    );
    // No double-count and no silent drop: one call per accumulated record means
    // the summed call_count across live entries must equal the accumulated count.
    assert_eq!(
        accumulator.total_call_count_for_tests(),
        accumulated,
        "accumulated call_count must equal the accumulated record count"
    );
    assert!(accumulator.entry_count() <= MAX_ENTRIES);
    assert!(accumulator.retained_bytes_for_tests() <= MAX_BYTES);
}

// --- Billing identity integrity (GHSA-m28c-f3v5-26qg) ---

/// Two authenticated identities sharing a 512-byte prefix must produce two
/// snapshot accumulator entries and two exported `consumer_id` values. A
/// prefix-only bound merged their calls, bytes, and charges into one billed
/// principal.
#[test]
fn snapshot_keeps_shared_prefix_identities_separate() {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    let accumulator = SnapshotAccumulator::new();
    let charge = ChargeComputation {
        call_count: 1,
        charge_call: 0.25,
        charge_total: 0.25,
        ..ChargeComputation::default()
    };

    let prefix = "p".repeat(512);
    let alice = format!("{prefix}alice");
    let bob = format!("{prefix}bob");
    let summary = grpc_summary("shared-prefix", "0");
    accumulator.record_http_for_test(&summary, &alice, charge);
    accumulator.record_http_for_test(&summary, &bob, charge);

    assert_eq!(
        accumulator.entry_count(),
        2,
        "shared-prefix identities must not share one accumulator entry"
    );

    let events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-identity")
        .unwrap();
    assert_eq!(events.len(), 2);
    let mut consumer_ids: Vec<&str> = events
        .iter()
        .map(|event| event.consumer_id.as_str())
        .collect();
    consumer_ids.sort_unstable();
    assert_ne!(
        consumer_ids[0], consumer_ids[1],
        "distinct principals must export distinct consumer_id values"
    );
    for consumer_id in &consumer_ids {
        assert!(consumer_id.len() <= 512, "consumer_id exceeded the bound");
        assert!(
            consumer_id.contains("~sha256:"),
            "oversized identity must carry a digest of the complete value"
        );
    }
    for event in &events {
        assert_eq!(event.call_count, 1, "charges must not be merged");
    }
}

/// A 512-byte identity is exactly at the bound and must be exported verbatim.
#[test]
fn snapshot_exports_at_limit_identity_verbatim() {
    let mut config = ApiChargebackSinkConfig {
        mode: ferrum_edge::plugins::api_chargeback_sink::SinkMode::Snapshot,
        ..Default::default()
    };
    config.currency = "USD".to_string();
    config.pricing_version = "test-v1".to_string();
    let accumulator = SnapshotAccumulator::new();
    let charge = ChargeComputation {
        call_count: 1,
        charge_call: 0.25,
        charge_total: 0.25,
        ..ChargeComputation::default()
    };

    let consumer = "u".repeat(512);
    accumulator.record_http_for_test(&grpc_summary("at-limit", "0"), &consumer, charge);

    let events = accumulator
        .compute_deltas(&config, "node-a", 100, "snap-at-limit")
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].consumer_id, consumer);
}

// ---------------------------------------------------------------------------
// JSONEachRow request-body retained-byte ownership — GHSA-83h5-52mw-f33p.
//
// The queued `ChargeEvent`s hold a per-instance lease covering one copy. The
// serialized insert body is a second attacker-shaped copy that coexists with
// them, so it is reserved against the retained-byte ceiling before serialization
// and released when the request (and every retry handle) is gone.
// ---------------------------------------------------------------------------

fn leaked_chargeback_test_ceiling(max_bytes: usize) -> &'static RetainedByteCeiling {
    let ceiling: &'static RetainedByteCeiling =
        Box::leak(Box::new(RetainedByteCeiling::new(max_bytes)));
    ceiling.set_max_unclamped_for_test(max_bytes);
    ceiling
}

#[test]
fn chargeback_insert_body_is_reserved_before_serialization_and_released_on_drop() {
    let ceiling = leaked_chargeback_test_ceiling(4 * 1024 * 1024);
    let events: Vec<ChargeEvent> = (0..8)
        .map(|index| sample_event(&format!("event-{index}")))
        .collect();

    let (bound, held, after) =
        probe_charge_body_materialization_for_tests(ceiling, &events).expect("body materialized");

    assert!(bound > 0);
    assert_eq!(
        held, bound,
        "the reserved bound stays charged for the request body's whole life"
    );
    assert_eq!(
        after, 0,
        "the body reservation releases exactly once, with no underflow"
    );
}

#[test]
fn chargeback_insert_body_is_refused_rather_than_serialized_under_a_saturated_ceiling() {
    let ceiling = leaked_chargeback_test_ceiling(1_024);
    let events: Vec<ChargeEvent> = (0..8)
        .map(|index| sample_event(&format!("event-{index}")))
        .collect();

    let error = probe_charge_body_materialization_for_tests(ceiling, &events)
        .expect_err("a 1 KiB ceiling cannot admit an eight-row insert body");
    assert!(
        error.contains("ceiling"),
        "the refusal must name the ceiling: {error}"
    );
    assert_eq!(
        ceiling.used(),
        0,
        "a refused body must not charge the ceiling"
    );
    assert!(ceiling.rejections() > 0);
}

// ---------------------------------------------------------------------------
// Spool replay retained-byte ownership — GHSA-83h5-52mw-f33p.
//
// Replay must not create an attacker-shaped representation outside the
// retained-byte ceiling. The decoded artifact, its line index, the replay
// worklist, and every chunk body are each reserved *before* they exist and held
// for their real lifetime; 413 splits address line ranges instead of deep-
// copying rows, so splitting cannot multiply retained row bytes.
// ---------------------------------------------------------------------------

/// A replay artifact big enough that its decoded bytes dominate every fixed
/// allowance in the accounting below.
fn spool_replay_events(count: usize) -> Vec<ChargeEvent> {
    (0..count)
        .map(|index| sample_event(&format!("evt-ceiling-{index:04}")))
        .collect()
}

#[tokio::test]
async fn spool_replay_refuses_before_decoding_when_the_ceiling_cannot_hold_the_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool.write_events(&spool_replay_events(8)).unwrap();
    let encoded_len = usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();

    // One byte short of the decoded artifact itself. The old replay decoded the
    // whole file into an owned `String` before anything was charged.
    let ceiling = leaked_chargeback_test_ceiling(encoded_len - 1);
    let error = replay_spool_once_with_ceiling_for_tests(&spool, "http://127.0.0.1:1/", 4, ceiling)
        .await
        .expect_err("a ceiling below the artifact size must defer replay");

    assert!(
        error.contains("ceiling"),
        "the refusal must name the ceiling: {error}"
    );
    assert!(
        !error.to_ascii_lowercase().contains("evt-"),
        "refusal diagnostics must not carry charge-record fields: {error}"
    );
    assert_eq!(
        ceiling.high_water(),
        0,
        "nothing may be decoded, indexed, or serialized before the refusal"
    );
    assert!(ceiling.rejections() > 0, "the refusal must be counted");
    assert_eq!(ceiling.used(), 0, "a refused replay leaks no reservation");
    assert!(
        path.exists(),
        "a ceiling refusal is retryable and must leave the durable record claimable"
    );
}

#[tokio::test]
async fn spool_replay_413_split_does_not_multiply_retained_row_bytes() {
    let server = MockServer::start().await;
    // Whole 8-row file -> 413, then each half -> 413 again, then the quarters
    // deliver. Three levels of splitting over one decoded artifact.
    mount_status_sequence(&server, &[413, 413, 200, 200, 413, 200, 200]).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let events = spool_replay_events(8);
    let path = spool.write_events(&events).unwrap();
    let encoded_len = usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();

    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 2, ceiling)
        .await
        .expect("split replay must succeed");

    assert!(!path.exists(), "split replay consumes the original file");
    assert_eq!(
        ceiling.used(),
        0,
        "every replay reservation releases exactly once"
    );
    assert_eq!(ceiling.rejections(), 0);

    // Peak retention is one decoded artifact + its index + the worklist + the
    // single largest chunk body. Splitting borrows line ranges, so it never adds
    // another artifact-sized copy: three levels of halving stay well under two
    // artifacts plus fixed slack.
    let artifact_scale = encoded_len * 2 + 4_096;
    assert!(
        ceiling.high_water() > 0,
        "the injected ceiling must really be on the replay path"
    );
    assert!(
        ceiling.high_water() <= artifact_scale,
        "413 splitting must not multiply retained row bytes: high_water={} artifact={} bound={}",
        ceiling.high_water(),
        encoded_len,
        artifact_scale
    );

    // Ordering, event identity, and dead-letter semantics are unchanged.
    let requests = wait_for_requests(&server, 7).await;
    let delivered: String = requests
        .iter()
        .map(|request| String::from_utf8(request.body.clone()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for index in 0..8 {
        assert!(
            delivered.contains(&format!("evt-ceiling-{index:04}")),
            "split replay must preserve every event_id"
        );
    }
}

#[tokio::test]
async fn spool_replay_releases_its_reservations_on_success_and_on_retryable_failure() {
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);

    // Retryable path: unreachable ClickHouse. The artifact, index, worklist, and
    // body all release even though delivery never completed.
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let path = spool.write_events(&spool_replay_events(4)).unwrap();
    replay_spool_once_with_ceiling_for_tests(&spool, "http://127.0.0.1:1/", 4, ceiling)
        .await
        .expect_err("unreachable ClickHouse must be retryable");
    assert_eq!(
        ceiling.used(),
        0,
        "a retryable failure releases every replay reservation"
    );
    assert!(path.exists(), "the durable record stays claimable");

    // Permanent path: the file is dead-lettered, and that too releases.
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 4, ceiling)
        .await
        .expect("a permanent rejection is not a replay error");
    assert_eq!(
        ceiling.used(),
        0,
        "a dead-lettered replay releases every reservation"
    );
    assert_rejected_sidecar(&path, 400, "permanent_http");

    // Success path.
    let success_server = MockServer::start().await;
    mount_status_sequence(&success_server, &[200]).await;
    let delivered = spool.write_events(&spool_replay_events(3)).unwrap();
    replay_spool_once_with_ceiling_for_tests(&spool, &success_server.uri(), 4, ceiling)
        .await
        .expect("delivery must succeed");
    assert!(!delivered.exists(), "a delivered file is removed");
    assert_eq!(
        ceiling.used(),
        0,
        "a successful replay releases every reservation"
    );
}

// ---------------------------------------------------------------------------
// ClickHouse endpoint credential handling — advisory GHSA-8594-2xhc-8g38
// ---------------------------------------------------------------------------

/// Sentinel planted in an `insert_query_params` value. Parameter *values* stay
/// arbitrary (ClickHouse settings are operator tuning), so the guarantee is
/// that the INSERT query string never reaches a diagnostic.
const CH_VALUE_SENTINEL: &str = "clickhouse-setting-value-canary";

#[test]
fn insert_query_params_reject_credential_bearing_names() {
    use ferrum_edge::plugins::validate_plugin_config;

    let temp = tempfile::tempdir().unwrap();
    for name in [
        "user",
        "password",
        "access_token",
        "session_id",
        "USER",
        "Password",
        "x_api_key",
        "myapikey",
        "vendor_secret",
        "svc_credential",
        "db_passwd",
        "refresh_token",
    ] {
        let mut config = valid_config(temp.path());
        config["clickhouse"]["insert_query_params"] = json!({ name: CH_VALUE_SENTINEL });
        let err = validate_plugin_config("api_chargeback_sink", &config)
            .expect_err("credential-bearing parameter names must be rejected");
        assert!(
            err.contains("names a credential"),
            "rejection must explain the contract for {name}: {err}"
        );
        assert!(
            err.contains("password_ref"),
            "rejection must point at the supported channel for {name}: {err}"
        );
        assert!(
            !err.contains(CH_VALUE_SENTINEL),
            "rejection must not echo the value for {name}: {err}"
        );
    }
}

#[test]
fn insert_query_params_still_accept_ordinary_clickhouse_settings() {
    use ferrum_edge::plugins::validate_plugin_config;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["insert_query_params"] = json!({
        "async_insert": "1",
        "wait_for_async_insert": "1",
        "max_insert_threads": "4",
        "date_time_input_format": "best_effort",
    });
    validate_plugin_config("api_chargeback_sink", &config)
        .expect("ordinary ClickHouse settings must remain admitted");
}

/// The INSERT URL carries every configured parameter (so the export works),
/// while the diagnostic rendering keeps only scheme/host/port.
#[test]
fn insert_url_carries_params_but_redacted_form_does_not() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!("https://clickhouse.example.com:8443/base-path");
    config["clickhouse"]["insert_query_params"] = json!({ "async_insert": CH_VALUE_SENTINEL });
    let parsed: ApiChargebackSinkConfig = serde_json::from_value(config).unwrap();

    let insert_url = clickhouse_insert_url_for_tests(&parsed).unwrap();
    assert!(
        insert_url.contains(CH_VALUE_SENTINEL),
        "the real request must still carry the configured parameter: {insert_url}"
    );

    let redacted = ferrum_edge::plugins::utils::redacted_endpoint_url_str(&insert_url);
    assert_eq!(redacted, "https://clickhouse.example.com:8443/redacted");
    assert!(!redacted.contains(CH_VALUE_SENTINEL));
    assert!(
        !redacted.contains("base-path"),
        "redaction is structural: the path is dropped, not substring-replaced"
    );
    assert!(!redacted.contains("INSERT"));
}

/// The custom-TLS (`Dedicated`) client path classifies its transport failure
/// rather than rendering the `reqwest::Error`, so the INSERT URL cannot reach a
/// log line or the returned replay error.
#[tokio::test(flavor = "current_thread")]
async fn spool_replay_failure_does_not_leak_insert_url() {
    let (logs, guard) = super::plugin_utils::capture_logs();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let insert_url =
        format!("http://{addr}/?database=ferrum&query=INSERT&password={CH_VALUE_SENTINEL}");

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    spool
        .write_events(&[sample_event("evt-redaction")])
        .unwrap();

    let outcome = replay_spool_once_for_tests(&spool, &insert_url).await;
    drop(guard);

    if let Err(error) = &outcome {
        assert!(
            !error.contains(CH_VALUE_SENTINEL),
            "replay error leaked the INSERT credential: {error}"
        );
    }
    let captured = logs.contents();
    super::plugin_utils::assert_no_secrets(
        &captured,
        "chargeback spool replay",
        &[CH_VALUE_SENTINEL],
    );
}

// ---------------------------------------------------------------------------
// Spool-write, snapshot, and dead-letter retained-byte ownership —
// GHSA-83h5-52mw-f33p residuals.
//
// The advertised process ceiling only holds if *every* attacker-shaped
// representation is reserved before it exists: the durable spool artifact's
// JSON and compressed forms, the snapshot accumulator's identities and staged
// overflow, the Full -> Compact recovery payload, the replay worklist, and the
// dead-letter accumulation. These tests assert exact reservation and release on
// success, refusal, retry, transfer, and drop.
// ---------------------------------------------------------------------------

fn ceiling_spool(temp: &tempfile::TempDir, ceiling: &'static RetainedByteCeiling) -> SpoolManager {
    let settings = spool_settings(temp.path(), 1024 * 1024);
    SpoolManager::for_tests_with_ceiling(settings, "node-a", ceiling).unwrap()
}

fn compressing_ceiling_spool(
    temp: &tempfile::TempDir,
    ceiling: &'static RetainedByteCeiling,
) -> SpoolManager {
    let mut settings = spool_settings(temp.path(), 1024 * 1024);
    settings.compression = SpoolCompression::Zstd;
    SpoolManager::for_tests_with_ceiling(settings, "node-a", ceiling).unwrap()
}

#[test]
fn spool_write_charges_its_json_and_compressed_representations_and_releases_them() {
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = compressing_ceiling_spool(&temp, ceiling);
    let events = spool_replay_events(16);
    let json_len = serialize_json_each_row(&events).unwrap().len();

    let (encoded_len, held, after) = spool
        .probe_spool_artifact_materialization_for_tests(&events)
        .expect("artifact materializes");

    assert!(encoded_len > 0);
    assert!(
        held >= encoded_len,
        "the encoded artifact stays charged for its whole life: held={held} encoded={encoded_len}"
    );
    assert!(
        ceiling.high_water() >= json_len + encoded_len,
        "the JSON and compressed representations coexist and must both be charged: \
         high_water={} json={json_len} encoded={encoded_len}",
        ceiling.high_water()
    );
    assert_eq!(
        after, 0,
        "every spool-write reservation releases exactly once, with no underflow"
    );
    assert_eq!(ceiling.rejections(), 0);
}

#[test]
fn spool_write_is_refused_rather_than_materialized_under_a_saturated_ceiling() {
    // Far below one serialized row: the JSON reservation must be refused before
    // a single byte is serialized.
    let ceiling = leaked_chargeback_test_ceiling(512);
    let temp = tempfile::tempdir().unwrap();
    let spool = ceiling_spool(&temp, ceiling);

    let error = spool
        .write_events(&spool_replay_events(8))
        .expect_err("a saturated ceiling must refuse the spool artifact");

    assert!(
        error.contains("ceiling"),
        "the refusal must name the ceiling: {error}"
    );
    assert!(
        !error.contains("evt-ceiling-"),
        "refusal diagnostics must not carry charge-record fields: {error}"
    );
    assert_eq!(ceiling.used(), 0, "a refused write leaks no reservation");
    assert!(ceiling.rejections() > 0);
    assert_eq!(
        spool.list_owned_spool_files_for_tests().unwrap().len(),
        0,
        "a refused write must not publish a partial artifact"
    );
}

#[test]
fn every_writable_artifact_is_structurally_replayable_under_the_same_ceiling() {
    // The liveness contract: if a ceiling admitted the write, it must also admit
    // the replay. The write reserves `charge_body_byte_bound`; replay's peak is
    // `spool_replay_peak_bytes`. Proving the second never exceeds the first, for
    // every artifact shape this build can produce, is what rules out an artifact
    // that is deterministically impossible to read back.
    let roomy = leaked_chargeback_test_ceiling(64 * 1024 * 1024);
    for count in [1usize, 2, 8, 64, 512, 4_096] {
        let events = spool_replay_events(count);
        let (write_bound, _held, _after) =
            probe_charge_body_materialization_for_tests(roomy, &events)
                .expect("the write reservation must be representable");
        let json_len = serialize_json_each_row(&events).unwrap().len() as u64;
        let replay_peak = spool_replay_peak_bytes_for_tests(json_len, count)
            .expect("the replay peak must be representable");
        assert!(
            replay_peak <= write_bound as u64,
            "a {count}-row artifact would need {replay_peak} replay bytes but only \
             {write_bound} were required to write it"
        );
    }
    assert_eq!(roomy.used(), 0);
}

#[tokio::test]
async fn spool_replay_of_a_written_artifact_fits_under_the_proven_liveness_bound() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[200]).await;

    let events = spool_replay_events(256);
    let json_len = serialize_json_each_row(&events).unwrap().len() as u64;
    let peak = spool_replay_peak_bytes_for_tests(json_len, events.len()).unwrap();

    let write_ceiling = leaked_chargeback_test_ceiling(64 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = ceiling_spool(&temp, write_ceiling);
    let path = spool.write_events(&events).expect("artifact is admitted");

    // Replay against exactly the proven bound — no slack. A file this build
    // spooled must replay under it rather than becoming permanently
    // unreplayable.
    let ceiling = leaked_chargeback_test_ceiling(usize::try_from(peak).unwrap());
    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 128, ceiling)
        .await
        .expect("a written artifact must be replayable under the same ceiling");

    assert!(!path.exists(), "a delivered artifact is removed");
    assert_eq!(ceiling.used(), 0, "replay releases every reservation");
    assert_eq!(
        ceiling.rejections(),
        0,
        "the proven bound must leave no room for a structural refusal"
    );
    assert!(
        ceiling.high_water() <= peak as usize,
        "observed peak {} exceeded the proven bound {peak}",
        ceiling.high_water()
    );
}

#[test]
fn spool_replay_worklist_reservation_is_independent_of_row_count() {
    let entries = spool_split_worklist_max_entries_for_tests();
    let entry_bytes = spool_index_entry_bytes_for_tests();
    assert!(
        entries >= usize::BITS as usize,
        "the bound must cover every halving level"
    );

    // The worklist charge is fixed, and it is already part of the peak for a
    // single-row artifact.
    let worklist = (entries * entry_bytes) as u64;
    let one_row = spool_replay_peak_bytes_for_tests(1_024, 1).unwrap();
    assert!(
        one_row >= worklist,
        "the peak accounting must include the fixed worklist reservation"
    );

    // Row-count growth costs only the line index and one row separator each —
    // never a per-line worklist slot. The old O(lines) worklist reservation is
    // what this delta would have exposed, and it is what could strand a healthy
    // high-row-count artifact.
    let many_rows = spool_replay_peak_bytes_for_tests(1_024, 1_001).unwrap();
    assert_eq!(
        many_rows - one_row,
        1_000 * (entry_bytes as u64 + 1),
        "each extra row costs exactly one index entry plus its row separator"
    );
}

#[tokio::test]
async fn spool_replay_dead_letter_accounting_is_aggregated_not_per_row() {
    let server = MockServer::start().await;
    // Whole file rejected permanently: one aggregate outcome, not one per row.
    mount_status_sequence(&server, &[400]).await;

    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = ceiling_spool(&temp, ceiling);
    let events = spool_replay_events(64);
    let path = spool.write_events(&events).unwrap();

    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 128, ceiling)
        .await
        .expect("a permanent rejection is not a replay error");

    let meta_path = dead_letter_meta_path(&path);
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(
        meta["rejected_rows"].as_u64().unwrap(),
        64,
        "every rejected row must still be counted"
    );
    let outcomes = meta["outcomes"].as_array().unwrap();
    assert_eq!(
        outcomes.len(),
        1,
        "64 rejected rows must aggregate into one outcome: {outcomes:?}"
    );
    assert_eq!(outcomes[0]["http_status"], 400);
    assert_eq!(outcomes[0]["reason"], "permanent_http");
    assert_eq!(outcomes[0]["row_count"].as_u64().unwrap(), 64);
    assert_eq!(ceiling.used(), 0);
}

#[tokio::test]
async fn spool_replay_dead_letter_tally_preserves_distinct_statuses() {
    let server = MockServer::start().await;
    // 403 is retryable here, so distinct *permanent* statuses come from 400/404:
    // (0,4) 413 -> (0,1) 413 (single-row dead letter), (1,4) 413 -> (1,2) 400,
    // (2,4) 413 -> (2,3) 404, (3,4) 200.
    mount_status_sequence(&server, &[413, 413, 413, 400, 413, 404, 200]).await;

    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = ceiling_spool(&temp, ceiling);
    let path = spool.write_events(&spool_replay_events(4)).unwrap();

    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 1, ceiling)
        .await
        .expect("permanent rejections are not replay errors");

    let meta_path = dead_letter_meta_path(&path);
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    let outcomes = meta["outcomes"].as_array().unwrap();
    let statuses: Vec<u64> = outcomes
        .iter()
        .filter_map(|outcome| outcome["http_status"].as_u64())
        .collect();
    assert!(
        statuses.contains(&400) && statuses.contains(&404),
        "distinct permanent statuses must survive aggregation: {outcomes:?}"
    );
    assert!(
        outcomes.iter().any(|outcome| {
            outcome["reason"] == "payload_too_large" && outcome["http_status"] == 413
        }),
        "a single-row 413 must still be recorded as its own reason: {outcomes:?}"
    );
    let total: u64 = outcomes
        .iter()
        .map(|outcome| outcome["row_count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, meta["rejected_rows"].as_u64().unwrap());
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn snapshot_accumulators_share_one_process_ceiling_across_instances() {
    // Below the sum of the two per-instance budgets, so the shared ceiling —
    // not the private one — is what stops the second instance.
    let ceiling = leaked_chargeback_test_ceiling(48 * 1024);
    let charge = unit_call_charge(0.01);

    let first = SnapshotAccumulator::with_limits_shards_and_ceiling(4_096, 32 * 1024, 8, ceiling);
    let second = SnapshotAccumulator::with_limits_shards_and_ceiling(4_096, 32 * 1024, 8, ceiling);

    let mut first_accumulated = 0usize;
    for index in 0..4_096 {
        if !first.record_accumulated_for_test(
            "ns",
            &format!("first-{index}"),
            "proxy",
            "proxy-name",
            200,
            "http",
            charge,
        ) {
            break;
        }
        first_accumulated += 1;
    }
    assert!(first_accumulated > 0, "the first instance must admit work");
    assert_eq!(
        first.process_retained_bytes_for_tests(),
        first.retained_bytes_for_tests(),
        "the process charge must track the per-instance counter exactly"
    );

    let mut second_accumulated = 0usize;
    for index in 0..4_096 {
        if !second.record_accumulated_for_test(
            "ns",
            &format!("second-{index}"),
            "proxy",
            "proxy-name",
            200,
            "http",
            charge,
        ) {
            break;
        }
        second_accumulated += 1;
    }

    assert!(
        ceiling.used() <= ceiling.max(),
        "N instances must not multiply past the shared ceiling: used={} max={}",
        ceiling.used(),
        ceiling.max()
    );
    assert!(
        second_accumulated < first_accumulated,
        "the second instance must be squeezed by the shared ceiling, not get its own \
         private budget: first={first_accumulated} second={second_accumulated}"
    );
    assert!(
        ceiling.rejections() > 0,
        "shared-ceiling refusals must be counted"
    );

    // Clear and drop both release exactly what they took, with no underflow.
    first.clear_for_compaction_for_tests();
    assert_eq!(first.process_retained_bytes_for_tests(), 0);
    let after_first = ceiling.used();
    assert_eq!(after_first, second.process_retained_bytes_for_tests());
    drop(second);
    assert_eq!(ceiling.used(), 0, "drop releases the remaining charge");
    drop(first);
    assert_eq!(
        ceiling.used(),
        0,
        "a cleared accumulator cannot double-release"
    );
}

#[test]
fn snapshot_accumulator_releases_its_process_charge_when_overflow_is_drained() {
    let ceiling = leaked_chargeback_test_ceiling(1024 * 1024);
    let accumulator =
        SnapshotAccumulator::with_limits_shards_and_ceiling(4, 512 * 1024, 4, ceiling);

    for index in 0..8 {
        assert!(
            accumulator.stage_overflow_event_for_tests(sample_event(&format!("overflow-{index}"))),
            "staging must be admitted below the ceiling"
        );
    }
    let staged = accumulator.process_retained_bytes_for_tests();
    assert!(
        staged > 0,
        "staged overflow must charge the process ceiling"
    );
    assert_eq!(staged, ceiling.used());

    accumulator.clear_for_compaction_for_tests();
    assert_eq!(
        ceiling.used(),
        0,
        "draining staged overflow releases exactly the staged bytes"
    );
    assert_eq!(accumulator.retained_bytes_for_tests(), 0);
}

#[test]
fn borrowed_snapshot_overflow_keeps_its_process_reservation_until_commit() {
    let ceiling = leaked_chargeback_test_ceiling(1024 * 1024);
    let accumulator =
        SnapshotAccumulator::with_limits_shards_and_ceiling(4, 512 * 1024, 4, ceiling);

    assert!(
        accumulator.stage_overflow_event_for_tests(sample_event("borrowed-overflow")),
        "staging must be admitted below the ceiling"
    );
    let staged_bytes = accumulator.process_retained_bytes_for_tests();
    assert!(staged_bytes > 0);
    ceiling.set_max_unclamped_for_test(staged_bytes);

    let (
        taken_events,
        taken_bytes,
        held_while_taken,
        competing_byte_admitted,
        pending_after_restore,
        held_after_restore,
    ) = accumulator.probe_taken_overflow_ownership_for_tests(ceiling);

    assert_eq!(taken_events, 1);
    assert_eq!(taken_bytes, staged_bytes);
    assert_eq!(
        held_while_taken, staged_bytes,
        "borrowing staged billing deltas must not release their shared charge"
    );
    assert!(
        !competing_byte_admitted,
        "another sink must not consume capacity owned by borrowed billing deltas"
    );
    assert_eq!(
        pending_after_restore, 1,
        "failed handoff restoration must preserve the exact billing event"
    );
    assert_eq!(
        held_after_restore, staged_bytes,
        "restoration must reuse the continuous reservation without a second admission"
    );

    accumulator.clear_for_compaction_for_tests();
    assert_eq!(
        ceiling.used(),
        0,
        "the restored charge releases exactly once"
    );
}

#[test]
fn compact_snapshot_recovery_owns_its_reservation_and_restores_deltas_on_a_failed_retry() {
    let ceiling = leaked_chargeback_test_ceiling(1024 * 1024);
    let events: Vec<ChargeEvent> = (0..12)
        .map(|index| sample_event(&format!("compact-{index}")))
        .collect();

    let (reserved, held_after_retry, pending, after_drop) =
        probe_compact_recovery_retry_for_tests(ceiling, events)
            .expect("the probe must observe a failed handoff");

    assert!(reserved > 0);
    assert_eq!(
        held_after_retry, reserved,
        "a failed retry must neither release the reservation nor take a second one \
         for a clone of the pending set"
    );
    assert_eq!(
        pending, 12,
        "a failed handoff must restore every pending billing delta"
    );
    assert_eq!(
        after_drop, 0,
        "dropping the recovery releases its reservation exactly once"
    );
}

#[test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
fn compact_snapshot_recovery_serializes_take_write_restore_attempts() {
    let ceiling = leaked_chargeback_test_ceiling(1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = ceiling_spool(&temp, ceiling);
    let events: Vec<ChargeEvent> = (0..12)
        .map(|index| sample_event(&format!("compact-concurrent-{index}")))
        .collect();
    let recovery = Arc::new(
        compact_recovery_probe_for_tests(ceiling, events, spool)
            .expect("compact recovery must fit below the test ceiling"),
    );

    let gate = SpoolBeforeWriteGate::new();
    let _clear_hook = ClearSpoolWriteHookOnDrop {
        gate: Arc::clone(&gate),
    };
    let hook_gate = Arc::clone(&gate);
    let hook_spool_dir = temp.path().to_path_buf();
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, namespace_root| {
        // The hook slot is process-global: only gate this test's own spool.
        if !namespace_root.starts_with(&hook_spool_dir) {
            return;
        }
        match point {
            SpoolWriteHookPoint::BeforeWrite => hook_gate.on_before_write(),
            SpoolWriteHookPoint::AfterWrite => hook_gate.on_after_write(),
            SpoolWriteHookPoint::QuotaInventoryTaken => {}
        }
    })));

    let first_recovery = Arc::clone(&recovery);
    let first = thread::spawn(move || first_recovery.try_spool_for_tests());
    gate.wait_until_parked(1, Duration::from_secs(5))
        .expect("first retry must park after taking the pending set");

    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let second_recovery = Arc::clone(&recovery);
    let second = thread::spawn(move || {
        started_tx.send(()).expect("publish second retry start");
        let durable = second_recovery.try_spool_for_tests();
        done_tx.send(durable).expect("publish second retry outcome");
    });
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("second retry must start");
    assert!(
        matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "a concurrent retry must wait rather than treating the borrowed empty set as success"
    );

    gate.release_all();
    assert!(
        first.join().expect("first retry thread must not panic"),
        "the first retry must durably spool the pending set"
    );
    assert!(
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second retry must finish after the first"),
        "the serialized second retry must observe durable completion"
    );
    second.join().expect("second retry thread must not panic");
    assert_eq!(recovery.pending_len_for_tests(), 0);
    drop(recovery);
    assert_eq!(
        ceiling.used(),
        0,
        "dropping the drained recovery releases its reservation"
    );
}

#[test]
fn compact_snapshot_recovery_is_refused_rather_than_built_under_a_saturated_ceiling() {
    let ceiling = leaked_chargeback_test_ceiling(256);
    let events: Vec<ChargeEvent> = (0..12)
        .map(|index| sample_event(&format!("compact-refused-{index}")))
        .collect();

    let error = probe_compact_recovery_retry_for_tests(ceiling, events)
        .expect_err("a saturated ceiling must refuse the recovery payload");
    assert!(error.contains("ceiling"), "{error}");
    assert_eq!(ceiling.used(), 0);
    assert!(ceiling.rejections() > 0);
}

#[test]
fn a_zstd_artifact_without_a_frame_content_size_still_decodes_via_the_ratio_clamp() {
    // Legacy and foreign archives carry no decompressed size in the frame
    // header. Replay must fall back to the ratio clamp rather than refusing
    // them, and the clamp must still fail closed on a high-ratio bomb.
    let temp = tempfile::tempdir().unwrap();

    let plain = vec![b'\n'; 512 * 1024];
    let legacy =
        encode_spool_bytes_without_content_size_for_tests(&plain, SpoolCompression::Zstd).unwrap();
    let legacy_path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FC1.ndjson.zst");
    fs::write(&legacy_path, &legacy).unwrap();
    let decoded = decode_spool_file_for_tests(&legacy_path)
        .expect("a frame without a content size must still decode");
    assert_eq!(decoded.len(), plain.len());

    let bomb_plain = vec![b'\n'; 2 * 1024 * 1024];
    let bomb =
        encode_spool_bytes_without_content_size_for_tests(&bomb_plain, SpoolCompression::Zstd)
            .unwrap();
    let bomb_path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FC2.ndjson.zst");
    fs::write(&bomb_path, &bomb).unwrap();
    let err = decode_spool_file_for_tests(&bomb_path)
        .expect_err("the ratio clamp must still bound a header-less high-ratio archive");
    assert!(
        err.contains("decompression bound"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_zstd_artifact_this_build_writes_declares_its_decompressed_size() {
    // The declared size is what replay reserves instead of the 200x heuristic,
    // so an ordinary compressible batch no longer reserves two orders of
    // magnitude more than it needs.
    let plain = vec![b'\n'; 512 * 1024];
    let one_shot = encode_spool_bytes_for_tests(&plain, SpoolCompression::Zstd).unwrap();
    let streamed =
        encode_spool_bytes_without_content_size_for_tests(&plain, SpoolCompression::Zstd).unwrap();
    assert_ne!(
        one_shot, streamed,
        "the production encoder must record the decompressed size the streaming one omits"
    );
    let ratio_bound = spool_decompression_limit_for_tests(one_shot.len() as u64);
    assert!(
        ratio_bound > plain.len() as u64,
        "the heuristic must really over-reserve for this fixture: ratio={ratio_bound} \
         actual={}",
        plain.len()
    );
}

#[test]
fn a_highly_compressible_zstd_artifact_this_build_writes_uses_its_declared_size() {
    // A legitimate one-shot artifact can compress beyond the heuristic used
    // for foreign/headerless frames. Its declared size remains authoritative
    // up to the absolute artifact ceiling, so replay must not quarantine it.
    let temp = tempfile::tempdir().unwrap();
    let plain = vec![b'\n'; 2 * 1024 * 1024];
    let encoded = encode_spool_bytes_for_tests(&plain, SpoolCompression::Zstd).unwrap();
    let ratio_bound = spool_decompression_limit_for_tests(encoded.len() as u64);
    assert!(
        ratio_bound < plain.len() as u64,
        "fixture must exceed the fallback ratio bound: ratio={ratio_bound} actual={}",
        plain.len()
    );

    let path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FC3.ndjson.zst");
    fs::write(&path, encoded).unwrap();
    let decoded = decode_spool_file_for_tests(&path)
        .expect("a writer-owned frame with a safe declared size must decode");
    assert_eq!(decoded.len(), plain.len());
}
