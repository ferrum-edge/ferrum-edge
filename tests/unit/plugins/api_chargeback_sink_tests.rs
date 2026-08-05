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
    SpoolManager, SpoolOwnerSpec, SpoolSettings, SpoolStats, SpoolWriteHookPoint,
    active_spool_inventory_walks_for_tests, classify_clickhouse_acknowledgement_for_tests,
    classify_clickhouse_http_status_for_tests, clickhouse_insert_url_for_tests,
    compact_recovery_probe_for_tests, compile_charge_event_projection, decode_spool_file_for_tests,
    encode_spool_bytes_for_tests, encode_spool_bytes_without_content_size_for_tests,
    encode_spool_bytes_without_ratio_padding_for_tests,
    encode_zstd_declaring_content_size_for_tests, new_ulid,
    pin_dead_letter_claim_identity_for_tests, probe_charge_body_materialization_for_tests,
    probe_charge_body_materialization_with_projection_for_tests,
    probe_compact_recovery_retry_for_tests, probe_empty_dead_letter_publish_for_tests,
    probe_empty_dead_letter_publish_with_identity_for_tests,
    probe_shared_spool_batch_clone_for_tests, probe_streaming_replay_batch_range_errors_for_tests,
    probe_streaming_spool_reader_defensive_paths_for_tests, publish_dead_letter_payload_for_tests,
    publish_dead_letter_payload_replacing_prior_for_tests,
    publish_dead_letter_payload_with_identity_for_tests, reconcile_active_spool_usage_for_tests,
    render_prometheus, render_status_json, replay_spool_once_for_tests,
    replay_spool_once_with_batch_size_for_tests, replay_spool_once_with_ceiling_for_tests,
    serialize_json_each_row, serialize_json_each_row_projected, set_spool_write_hook_for_tests,
    spool_artifact_byte_limit_for_tests, spool_claim_lease_secs_for_tests,
    spool_decompression_limit_for_tests, spool_index_entry_bytes_for_tests,
    spool_split_worklist_max_entries_for_tests, spool_streaming_limits_for_tests,
    write_dead_letter_meta_for_tests, write_dead_letter_meta_with_identity_for_tests,
    write_private_file_atomically_for_tests, write_private_file_atomically_with_fault_for_tests,
};
#[cfg(unix)]
use ferrum_edge::plugins::api_chargeback_sink::{
    SpoolReplayHookPoint, probe_streaming_replay_path_swap_for_tests,
    set_spool_replay_hook_for_tests,
};
use ferrum_edge::plugins::chargeback::pricing::{ChargeComputation, MAX_UNIT_PRICE, PricingConfig};
use ferrum_edge::plugins::utils::byte_budget::{
    RetainedByteCeiling, probe_preallocated_payload_capacity_guard_for_tests,
};
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let before = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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
    let after = spool.scan_stats_for_tests().unwrap();
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
    let before = spool.scan_stats_for_tests().unwrap();
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
    let after = spool.scan_stats_for_tests().unwrap();
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

    let after = spool.scan_stats_for_tests().unwrap();
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

/// Deterministically parks the first quota admission while publishing when a
/// second independent manager has reached the namespace-lock boundary.
struct SharedQuotaRaceGate {
    root: std::path::PathBuf,
    lock_attempts: Mutex<usize>,
    lock_attempts_cv: Condvar,
    first_admission_parked: Mutex<bool>,
    first_admission_cv: Condvar,
    release: Mutex<bool>,
    release_cv: Condvar,
    admission_claimed: AtomicBool,
}

impl SharedQuotaRaceGate {
    fn new(root: std::path::PathBuf) -> Arc<Self> {
        Arc::new(Self {
            root,
            lock_attempts: Mutex::new(0),
            lock_attempts_cv: Condvar::new(),
            first_admission_parked: Mutex::new(false),
            first_admission_cv: Condvar::new(),
            release: Mutex::new(false),
            release_cv: Condvar::new(),
            admission_claimed: AtomicBool::new(false),
        })
    }

    fn observe(&self, point: SpoolWriteHookPoint, root: &Path) {
        if root != self.root.as_path() {
            return;
        }
        match point {
            SpoolWriteHookPoint::BeforeNamespaceLock => {
                let mut attempts = self.lock_attempts.lock().expect("lock-attempt gate");
                *attempts = attempts.saturating_add(1);
                self.lock_attempts_cv.notify_all();
            }
            SpoolWriteHookPoint::QuotaAdmissionReady
                if !self.admission_claimed.swap(true, Ordering::SeqCst) =>
            {
                {
                    let mut parked = self
                        .first_admission_parked
                        .lock()
                        .expect("admission parked gate");
                    *parked = true;
                    self.first_admission_cv.notify_all();
                }
                let mut released = self.release.lock().expect("admission release gate");
                while !*released {
                    released = self
                        .release_cv
                        .wait(released)
                        .expect("admission release wait");
                }
            }
            _ => {}
        }
    }

    fn wait_for_first_admission(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut parked = self
            .first_admission_parked
            .lock()
            .expect("admission parked gate");
        while !*parked {
            let now = Instant::now();
            assert!(now < deadline, "first quota admission did not park");
            let (next, timeout) = self
                .first_admission_cv
                .wait_timeout(parked, deadline.saturating_duration_since(now))
                .expect("admission parked wait");
            parked = next;
            assert!(
                !timeout.timed_out() || *parked,
                "first quota admission timed out"
            );
        }
    }

    fn wait_for_lock_attempts(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut attempts = self.lock_attempts.lock().expect("lock-attempt gate");
        while *attempts < expected {
            let now = Instant::now();
            assert!(
                now < deadline,
                "namespace lock attempts did not reach {expected}; observed {attempts}"
            );
            let (next, timeout) = self
                .lock_attempts_cv
                .wait_timeout(attempts, deadline.saturating_duration_since(now))
                .expect("lock-attempt wait");
            attempts = next;
            assert!(
                !timeout.timed_out() || *attempts >= expected,
                "namespace lock attempt wait timed out"
            );
        }
    }

    fn release(&self) {
        let mut release = self.release.lock().expect("admission release gate");
        *release = true;
        self.release_cv.notify_all();
    }
}

struct ClearSharedQuotaRaceHook {
    gate: Arc<SharedQuotaRaceGate>,
}

impl Drop for ClearSharedQuotaRaceHook {
    fn drop(&mut self) {
        self.gate.release();
        set_spool_write_hook_for_tests(None);
    }
}

#[cfg(unix)]
#[test]
fn replaced_namespace_coordination_inode_refuses_spool_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 1024 * 1024), "node-a").unwrap();
    let lock = spool.namespace_root_for_tests().join(".spool-quota.lock");
    let displaced = spool
        .namespace_root_for_tests()
        .join("displaced-quota-lock");
    fs::rename(&lock, &displaced).unwrap();
    fs::write(&lock, b"").unwrap();

    let error = spool
        .write_events(&[sample_event("replaced-quota-lock")])
        .expect_err("a replaced coordination inode must fail closed");

    assert!(error.contains("coordination"), "unexpected error: {error}");
    assert_eq!(spool.scan_stats_for_tests().unwrap(), SpoolStats::default());
}

#[cfg(unix)]
#[test]
fn hard_linked_namespace_coordination_inode_refuses_spool_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 1024 * 1024), "node-a").unwrap();
    let lock = spool.namespace_root_for_tests().join(".spool-quota.lock");
    let alias = spool.namespace_root_for_tests().join("quota-lock-alias");
    fs::hard_link(&lock, &alias).unwrap();

    let error = spool
        .write_events(&[sample_event("hard-linked-quota-lock")])
        .expect_err("a hard-linked coordination inode must fail closed");

    assert!(error.contains("hard link"), "unexpected error: {error}");
    assert_eq!(spool.scan_stats_for_tests().unwrap(), SpoolStats::default());
}

#[test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
fn independent_managers_cannot_over_admit_ordinary_spool_writes() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("shared-quota-ordinary");
    let encoded_len = serialize_json_each_row(std::slice::from_ref(&event))
        .unwrap()
        .len() as u64;
    let settings = spool_settings(temp.path(), encoded_len);
    let ceiling = leaked_chargeback_test_ceiling(16 * 1024 * 1024);
    let first = Arc::new(
        SpoolManager::for_tests_with_owner_faults_ages_and_ceiling(
            settings.clone(),
            &test_owner_spec("node-a"),
            101,
            SpoolFsFault::None,
            0,
            3_600,
            ceiling,
        )
        .unwrap(),
    );
    let second = Arc::new(
        SpoolManager::for_tests_with_owner_faults_ages_and_ceiling(
            settings,
            &test_owner_spec("node-a"),
            102,
            SpoolFsFault::None,
            0,
            3_600,
            ceiling,
        )
        .unwrap(),
    );
    let gate = SharedQuotaRaceGate::new(first.namespace_root_for_tests().to_path_buf());
    let _clear = ClearSharedQuotaRaceHook {
        gate: Arc::clone(&gate),
    };
    let hook_gate = Arc::clone(&gate);
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, root| {
        hook_gate.observe(point, root);
    })));

    let first_manager = Arc::clone(&first);
    let first_event = event.clone();
    let first_writer = thread::spawn(move || first_manager.write_events(&[first_event]));
    gate.wait_for_first_admission();

    let second_manager = Arc::clone(&second);
    let second_writer = thread::spawn(move || second_manager.write_events(&[event]));
    gate.wait_for_lock_attempts(2);
    gate.release();

    first_writer.join().expect("first writer thread").unwrap();
    second_writer.join().expect("second writer thread").unwrap();
    let stats = first.scan_stats_for_tests().unwrap();
    assert_eq!(
        stats.files, 1,
        "the second admission must evict, not overlap"
    );
    assert!(
        stats.bytes <= encoded_len,
        "shared namespace exceeded quota: {stats:?}"
    );
    assert_eq!(ceiling.used(), 0);
}

#[test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
fn independent_managers_cannot_over_admit_streamed_dead_letter_appends() {
    let temp = tempfile::tempdir().unwrap();
    let row = br#"{"event_id":"shared-quota-dead-letter"}"#.to_vec();
    let source_bytes = row.len() as u64;
    let max_bytes = source_bytes.saturating_mul(3);
    let settings = spool_settings(temp.path(), max_bytes);
    let ceiling = leaked_chargeback_test_ceiling(16 * 1024 * 1024);
    let first = Arc::new(
        SpoolManager::for_tests_with_owner_faults_ages_and_ceiling(
            settings.clone(),
            &test_owner_spec("node-a"),
            201,
            SpoolFsFault::None,
            0,
            3_600,
            ceiling,
        )
        .unwrap(),
    );
    let second = Arc::new(
        SpoolManager::for_tests_with_owner_faults_ages_and_ceiling(
            settings,
            &test_owner_spec("node-a"),
            202,
            SpoolFsFault::None,
            0,
            3_600,
            ceiling,
        )
        .unwrap(),
    );
    let day = first.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source_a = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FD1"));
    let source_b = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FD2"));
    fs::write(&source_a, &row).unwrap();
    fs::write(&source_b, &row).unwrap();
    let claim_a = first
        .hold_replay_claim_for_tests(&source_a)
        .unwrap()
        .unwrap();
    let claim_b = second
        .hold_replay_claim_for_tests(&source_b)
        .unwrap()
        .unwrap();
    let claim_a_path = claim_a.claim_path_for_tests().to_path_buf();
    let claim_b_path = claim_b.claim_path_for_tests().to_path_buf();

    let gate = SharedQuotaRaceGate::new(first.namespace_root_for_tests().to_path_buf());
    let _clear = ClearSharedQuotaRaceHook {
        gate: Arc::clone(&gate),
    };
    let hook_gate = Arc::clone(&gate);
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, root| {
        hook_gate.observe(point, root);
    })));

    let first_manager = Arc::clone(&first);
    let first_row = row.clone();
    let first_append = thread::spawn(move || {
        publish_dead_letter_payload_for_tests(&first_manager, &claim_a_path, &first_row)
    });
    gate.wait_for_first_admission();

    let second_manager = Arc::clone(&second);
    let second_append = thread::spawn(move || {
        publish_dead_letter_payload_for_tests(&second_manager, &claim_b_path, &row)
    });
    // First helper acquires once to create its temp and again for the parked
    // append; the second helper's create is the third lock attempt.
    gate.wait_for_lock_attempts(3);
    gate.release();

    let first_result = first_append.join().expect("first append thread");
    let second_result = second_append.join().expect("second append thread");
    assert!(
        first_result.is_ok(),
        "first append failed: {first_result:?}"
    );
    let error = second_result.expect_err("second protected append must fail closed");
    assert!(
        error.contains("cannot fit within spool.max_bytes"),
        "{error}"
    );
    assert!(claim_a.claim_path_for_tests().exists());
    assert!(claim_b.claim_path_for_tests().exists());
    let stats = first.scan_stats_for_tests().unwrap();
    assert_eq!(
        stats.files, 3,
        "two claims plus one dead-letter payload remain"
    );
    assert!(
        stats.bytes <= max_bytes,
        "streamed append exceeded quota: {stats:?}"
    );
    assert_eq!(ceiling.used(), 0);
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
    let after = spool.scan_stats_for_tests().unwrap();
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
    let after = spool.scan_stats_for_tests().unwrap();
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
    let stats = spool.scan_stats_for_tests().unwrap();
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

        // Planted files sit outside the writer path; a bounded worker reconcile
        // (or this test seam) publishes them into the maintained gauges that
        // status/Prometheus scrapes read without walking the tree.
        reconcile_active_spool_usage_for_tests();

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
            "# HELP chargeback_sink_spool_bytes Chargeback sink on-disk owned spool bytes (active, temp, in-flight claim, corrupt, and dead-lettered files)."
        ),
        "prometheus HELP must describe the owned-byte ceiling contract"
    );
    assert!(
        prom.contains(
            "# HELP chargeback_sink_spool_files Chargeback sink on-disk owned spool file count (active, temp, in-flight claim, corrupt, and dead-lettered files)."
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

#[test]
fn durable_request_pins_wait_when_profile_may_enable_async_insert() {
    let temp = tempfile::tempdir().unwrap();
    let config = valid_config(temp.path());
    let config: ApiChargebackSinkConfig = serde_json::from_value(config).unwrap();
    let url = url::Url::parse(&clickhouse_insert_url_for_tests(&config).unwrap()).unwrap();
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

    assert!(
        !params.contains_key("async_insert"),
        "fixture must omit async_insert so profile defaults are the only source"
    );
    assert_eq!(
        params.get("wait_for_async_insert").map(String::as_str),
        Some("1"),
        "durable requests must pin wait_for_async_insert even when Ferrum omits async_insert"
    );
}

#[test]
fn durable_request_does_not_duplicate_wait_for_async_insert_query_key() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["insert_query_params"] = json!({
        "async_insert": "1",
        "wait_for_async_insert": "1"
    });
    let config: ApiChargebackSinkConfig = serde_json::from_value(config).unwrap();
    let insert_url = clickhouse_insert_url_for_tests(&config).unwrap();
    let url = url::Url::parse(&insert_url).unwrap();
    let wait_values: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key == "wait_for_async_insert")
        .map(|(_, value)| value.into_owned())
        .collect();

    assert_eq!(
        wait_values,
        vec!["1"],
        "explicit wait_for_async_insert must not be duplicated in the INSERT URL: {insert_url}"
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

async fn mount_rejecting_body_marker(server: &MockServer, marker: &'static str, status: u16) {
    Mock::given(method("POST"))
        .respond_with(move |request: &Request| {
            let rejected = request
                .body
                .windows(marker.len())
                .any(|window| window == marker.as_bytes());
            ResponseTemplate::new(if rejected { status } else { 200 })
        })
        .mount(server)
        .await;
}

fn dead_letter_meta_path(source_path: &Path) -> std::path::PathBuf {
    let name = source_path.file_name().and_then(|n| n.to_str()).unwrap();
    source_path.with_file_name(format!("{name}.rejected.meta"))
}

fn dead_letter_payload_path(source_path: &Path) -> std::path::PathBuf {
    let name = source_path.file_name().and_then(|n| n.to_str()).unwrap();
    source_path.with_file_name(format!("{name}.rejected.ndjson"))
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
    let rejected_payload = dead_letter_payload_path(source_path);
    assert!(
        rejected_payload.exists(),
        "dead-letter state must retain the original rejected row payload: {}",
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
    assert_eq!(
        meta["payload_file"],
        rejected_payload
            .file_name()
            .unwrap()
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(
        meta["payload_bytes"].as_u64().unwrap(),
        fs::metadata(&rejected_payload).unwrap().len()
    );
    assert_eq!(meta["payload_sha256"].as_str().unwrap().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&rejected_payload)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "dead-letter billing payload must be owner-only"
        );
    }
    // Metadata stays safe even though its owner-only sibling intentionally
    // preserves the original rejected billing row.
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
async fn replay_bisects_mixed_http_400_and_preserves_only_the_original_bad_row() {
    let server = MockServer::start().await;
    mount_rejecting_body_marker(&server, "evt-bad-400", 400).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let events = vec![
        sample_event("evt-good-a"),
        sample_event("evt-good-b"),
        sample_event("evt-bad-400"),
        sample_event("evt-good-c"),
    ];
    let expected_bad = serialize_json_each_row(&[events[2].clone()]).unwrap();
    let source = spool.write_events(&events).unwrap();

    replay_spool_once_with_batch_size_for_tests(&spool, &server.uri(), 4)
        .await
        .expect("permanent batch rejection must isolate the poison row");

    assert_rejected_sidecar(&source, 400, "permanent_http");
    assert_eq!(
        fs::read_to_string(dead_letter_payload_path(&source)).unwrap(),
        expected_bad,
        "dead-letter payload must preserve exactly the rejected source row"
    );
    let meta: Value =
        serde_json::from_str(&fs::read_to_string(dead_letter_meta_path(&source)).unwrap()).unwrap();
    assert_eq!(meta["rejected_rows"], 1);

    let requests = wait_for_requests(&server, 5).await;
    assert_eq!(
        requests.len(),
        5,
        "four rows with one poison row use a fixed tree"
    );
    let accepted_attempts: Vec<String> = requests
        .iter()
        .map(|request| String::from_utf8(request.body.clone()).unwrap())
        .filter(|body| !body.contains("evt-bad-400"))
        .collect();
    let accepted = accepted_attempts.join("\n");
    for id in ["evt-good-a", "evt-good-b", "evt-good-c"] {
        assert!(accepted.contains(id), "good row {id} was not delivered");
    }
}

#[tokio::test]
async fn replay_schema_evolution_400_isolates_the_legacy_row_verbatim() {
    let server = MockServer::start().await;
    mount_rejecting_body_marker(&server, "legacy_column", 400).await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FE0"));
    let legacy = br#"{"event_id":"legacy","legacy_column":"kept"}"#;
    let current = br#"{"event_id":"current","current_column":"ok"}"#;
    let mut artifact = Vec::new();
    artifact.extend_from_slice(legacy);
    artifact.push(b'\n');
    artifact.extend_from_slice(current);
    fs::write(&source, artifact).unwrap();

    replay_spool_once_with_batch_size_for_tests(&spool, &server.uri(), 2)
        .await
        .expect("schema-evolution rejection must isolate the legacy row");

    assert_eq!(fs::read(dead_letter_payload_path(&source)).unwrap(), legacy);
    let requests = wait_for_requests(&server, 3).await;
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .any(|request| request.body.as_slice() == current)
    );
}

#[tokio::test]
async fn replay_permanent_isolation_attempts_are_bounded_by_the_batch_tree() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool.write_events(&spool_replay_events(8)).unwrap();
    replay_spool_once_with_batch_size_for_tests(&spool, &server.uri(), 8)
        .await
        .expect("a complete permanent tree must terminate");

    let requests = wait_for_requests(&server, 15).await;
    let (_, _, _, hard_attempt_limit) = spool_streaming_limits_for_tests();
    assert_eq!(
        requests.len(),
        15,
        "eight rejected rows require 2n-1 attempts"
    );
    assert!(requests.len() <= hard_attempt_limit);
    assert_eq!(
        fs::read_to_string(dead_letter_payload_path(&source))
            .unwrap()
            .lines()
            .count(),
        8
    );
}

#[tokio::test]
async fn replay_keeps_original_when_dead_letter_metadata_cannot_be_written() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400, 400]).await;

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
    assert!(
        dead_letter_payload_path(&source).exists(),
        "a payload published before metadata failure remains recoverable while the source stays authoritative"
    );

    fs::remove_dir(&tmp_path).unwrap();
    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("replay must recover after the metadata store becomes writable");
    assert_rejected_sidecar(&source, 400, "permanent_http");
}

#[tokio::test]
async fn dead_letter_recovery_reuses_quota_held_by_a_partially_published_payload() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400, 400]).await;

    let mut event = sample_event("evt-partial-dead-letter-quota");
    event.request_id = Some("x".repeat(32 * 1024));
    let encoded = serialize_json_each_row(std::slice::from_ref(&event)).unwrap();
    // One authoritative source + one rejected payload + bounded metadata fits.
    // A second complete payload does not, proving recovery replaces the partial
    // sibling instead of demanding duplicate quota or evicting other data.
    let max_bytes = (encoded.len() as u64)
        .saturating_mul(2)
        .saturating_add(4 * 1024);
    assert!(encoded.len() > 4 * 1024);

    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(spool_settings(temp.path(), max_bytes), "node-a").unwrap();
    let source = spool.write_events(&[event]).unwrap();
    let meta_path = dead_letter_meta_path(&source);
    let meta_temp = meta_path.with_file_name(format!(
        "{}.tmp",
        meta_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    ));
    fs::create_dir(&meta_temp).unwrap();

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("blocked metadata publication must retain the source");
    let payload_path = dead_letter_payload_path(&source);
    assert!(source.exists());
    assert!(payload_path.exists());
    assert!(spool.scan_stats_for_tests().unwrap().bytes <= max_bytes);

    fs::remove_dir(&meta_temp).unwrap();
    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("recovery must replace the partial payload within the original quota peak");

    assert_rejected_sidecar(&source, 400, "permanent_http");
    assert_eq!(fs::read_to_string(payload_path).unwrap(), encoded);
    assert!(spool.scan_stats_for_tests().unwrap().bytes <= max_bytes);
}

#[cfg(unix)]
#[tokio::test]
async fn dead_letter_payload_publish_refuses_symlink_and_restores_the_source_claim() {
    use std::os::unix::fs::symlink;

    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-symlink-dead-letter")])
        .unwrap();
    let outside = temp.path().join("outside-billing-data");
    fs::write(&outside, b"do-not-touch").unwrap();
    let payload = dead_letter_payload_path(&source);
    symlink(&outside, &payload).unwrap();

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("a planted dead-letter symlink must fail closed");

    assert!(error.contains("symlink"), "unexpected error: {error}");
    assert!(source.exists(), "the authoritative source must be restored");
    assert_eq!(fs::read(&outside).unwrap(), b"do-not-touch");
    assert!(
        fs::symlink_metadata(&payload)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn dead_letter_payload_admits_each_append_before_exceeding_spool_quota() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;

    let event = sample_event("evt-dead-letter-quota");
    let encoded = serialize_json_each_row(std::slice::from_ref(&event)).unwrap();
    let max_bytes = encoded.len() as u64;
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(spool_settings(temp.path(), max_bytes), "node-a").unwrap();
    let source = spool.write_events(&[event]).unwrap();
    assert_eq!(fs::metadata(&source).unwrap().len(), max_bytes);
    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    let source_parent = source.parent().unwrap().to_path_buf();
    let payload_name = dead_letter_payload_path(&source)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let observed_temp_bytes = Arc::new(AtomicU64::new(u64::MAX));
    let observed_for_hook = Arc::clone(&observed_temp_bytes);
    let _clear_hook = ClearSpoolWriteHookGuard;
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, root| {
        if point != SpoolWriteHookPoint::QuotaInventoryTaken || root != namespace_root.as_path() {
            return;
        }
        let temp_bytes = fs::read_dir(&source_parent)
            .expect("dead-letter quota hook reads the spool day directory")
            .filter_map(Result::ok)
            .find_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                if name.starts_with(&format!("{payload_name}.write-")) && name.ends_with(".tmp") {
                    entry.metadata().ok().map(|metadata| metadata.len())
                } else {
                    None
                }
            })
            .expect("dead-letter quota hook finds the live payload temp");
        observed_for_hook.store(temp_bytes, Ordering::SeqCst);
    })));

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("the uncompressed dead-letter copy must not exceed spool.max_bytes");
    set_spool_write_hook_for_tests(None);

    assert!(
        error.contains("cannot fit within spool.max_bytes"),
        "unexpected quota diagnostic: {error}"
    );
    assert!(
        source.exists(),
        "quota refusal must restore the authoritative replay source"
    );
    assert!(
        !dead_letter_payload_path(&source).exists(),
        "quota refusal must not publish a partial dead-letter payload"
    );
    let stats = spool.scan_stats_for_tests().unwrap();
    assert!(
        stats.bytes <= max_bytes,
        "dead-letter staging exceeded the hard spool quota: {stats:?}"
    );
    assert_eq!(
        observed_temp_bytes.load(Ordering::SeqCst),
        0,
        "quota admission must run before the first rejected payload byte is written"
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

    replay_spool_once_with_batch_size_for_tests(&spool, &server.uri(), 4)
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
            SpoolWriteHookPoint::BeforeNamespaceLock
            | SpoolWriteHookPoint::QuotaAdmissionReady
            | SpoolWriteHookPoint::QuotaInventoryTaken => {}
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

    // The delivery worker persists through spawn_blocking. A fixed number of
    // yield_now calls can expire before that pool schedules the write when the
    // full unit suite is saturating the hosted runner, even though the durable
    // handoff is healthy. Wait on the actual filesystem postcondition with a
    // bounded wall-clock deadline instead.
    let owned_bytes = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let owned_bytes = disk_owned_bytes(temp.path());
            if owned_bytes > 0 {
                break owned_bytes;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("durable high-water spool write timed out");
    assert!(
        owned_bytes > 0,
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
            SpoolWriteHookPoint::BeforeNamespaceLock
            | SpoolWriteHookPoint::QuotaAdmissionReady
            | SpoolWriteHookPoint::QuotaInventoryTaken => {}
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
    let files = spool.scan_stats_for_tests().unwrap();
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
// retained-byte ceiling. A fixed row scratch, decoder window, one bounded
// batch, its line index, and the isolation worklist are reserved before they
// exist. Peak retention is independent of artifact size.
// ---------------------------------------------------------------------------

/// A replay artifact big enough that its decoded bytes dominate every fixed
/// allowance in the accounting below.
fn spool_replay_events(count: usize) -> Vec<ChargeEvent> {
    (0..count)
        .map(|index| sample_event(&format!("evt-ceiling-{index:04}")))
        .collect()
}

fn fixed_width_json_rows(row_bytes: usize, count: usize) -> Vec<u8> {
    const PREFIX: &[u8] = b"{\"padding\":\"";
    const SUFFIX: &[u8] = b"\"}\n";
    assert!(row_bytes > PREFIX.len() + SUFFIX.len());
    let padding = row_bytes - PREFIX.len() - SUFFIX.len();
    let mut rows = Vec::with_capacity(row_bytes.saturating_mul(count));
    for _ in 0..count {
        rows.extend_from_slice(PREFIX);
        rows.resize(rows.len().saturating_add(padding), b'x');
        rows.extend_from_slice(SUFFIX);
    }
    rows
}

fn current_inflight_file(day: &Path) -> std::path::PathBuf {
    fs::read_dir(day)
        .expect("spool day remains readable during replay")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".inflight"))
        })
        .expect("replay owns one in-flight claim while delivering")
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
async fn spool_replay_quarantines_row_length_and_row_count_violations_before_http() {
    let (row_limit, row_count_limit, _, _) = spool_streaming_limits_for_tests();
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 8 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let long_row = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FE1"));
    fs::write(&long_row, vec![b'x'; row_limit + 1]).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("an oversized row is quarantined, not retried");
    assert!(!long_row.exists());
    assert!(
        long_row
            .with_file_name(format!(
                "{}.corrupt",
                long_row.file_name().unwrap().to_string_lossy()
            ))
            .exists()
    );

    let too_many_rows = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FE2"));
    let mut rows = Vec::with_capacity((row_count_limit + 1) * 3);
    for _ in 0..=row_count_limit {
        rows.extend_from_slice(b"{}\n");
    }
    fs::write(&too_many_rows, rows).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("an over-row-count artifact is quarantined before delivery");
    assert!(!too_many_rows.exists());
    assert!(
        too_many_rows
            .with_file_name(format!(
                "{}.corrupt",
                too_many_rows.file_name().unwrap().to_string_lossy()
            ))
            .exists()
    );
}

#[tokio::test]
async fn spool_replay_quarantines_a_compressed_bomb_during_bounded_preflight() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 8 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let plain = vec![b' '; 2 * 1024 * 1024];
    let encoded = encode_spool_bytes_without_ratio_padding_for_tests(&plain).unwrap();
    assert!(
        spool_decompression_limit_for_tests(encoded.len() as u64) < plain.len() as u64,
        "fixture must exceed the encoded-ratio limit"
    );
    let source = day.join(format!(
        "01ARZ3NDEKTSV4RRFFQ69G5FE3.{}.ndjson.zst",
        default_test_owner_tag()
    ));
    fs::write(&source, encoded).unwrap();

    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("a compressed bomb is quarantined without an HTTP attempt");

    assert!(!source.exists());
    assert!(
        source
            .with_file_name(format!(
                "{}.corrupt",
                source.file_name().unwrap().to_string_lossy()
            ))
            .exists()
    );
}

#[tokio::test]
async fn writer_zstd_artifact_replays_through_the_bounded_streaming_decoder() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let mut settings = spool_settings(temp.path(), 8 * 1024 * 1024);
    settings.compression = SpoolCompression::Zstd;
    let spool = SpoolManager::for_tests_with_ceiling(settings, "node-a", ceiling).unwrap();
    let source = spool.write_events(&spool_replay_events(200)).unwrap();

    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 128, ceiling)
        .await
        .expect("writer-produced zstd must stream through bounded replay");

    assert!(!source.exists());
    assert_eq!(wait_for_requests(&server, 2).await.len(), 2);
    assert_eq!(ceiling.used(), 0);
    assert!(ceiling.high_water() <= ceiling.max());
}

#[tokio::test]
async fn large_uncompressed_replay_has_artifact_size_independent_peak_retention() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 16 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FE4"));
    let padding = "x".repeat(1_000);
    let mut artifact = Vec::new();
    for index in 0..5_000 {
        if index != 0 {
            artifact.push(b'\n');
        }
        artifact.extend_from_slice(
            format!(r#"{{"event_id":"large-{index}","padding":"{padding}"}}"#).as_bytes(),
        );
    }
    assert!(artifact.len() > 4 * 1024 * 1024);
    fs::write(&source, artifact).unwrap();
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);

    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 128, ceiling)
        .await
        .expect("large replay must stream under the fixed ceiling");

    assert!(!source.exists());
    assert_eq!(ceiling.used(), 0);
    assert!(
        ceiling.high_water() <= 6 * 1024 * 1024,
        "streaming peak {} must stay below fixed reader+batch headroom",
        ceiling.high_water()
    );
    assert_eq!(wait_for_requests(&server, 40).await.len(), 40);
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

    // Peak retention is one fixed row/reader reservation plus one fixed-capacity
    // streaming batch and its bounded index/worklist, independent of split
    // depth and artifact size.
    assert!(
        ceiling.high_water() > 0,
        "the injected ceiling must really be on the replay path"
    );
    assert!(
        ceiling.high_water() <= 6 * 1024 * 1024,
        "413 splitting must stay inside fixed streaming headroom: high_water={} artifact={}",
        ceiling.high_water(),
        encoded_len
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
    // Four rejected rows require the complete seven-node isolation tree.
    mount_status_sequence(&server, &[400, 400, 400, 400, 400, 400, 400]).await;
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
// Fail-closed coverage for replay/dead-letter hardening (PR #3535).
//
// These probes exercise currently uncovered boundary and restoration branches:
// writer admission bounds, hostile on-disk shapes, durable dead-letter publish
// faults, and streaming range validation. Assertions stay behavioral — no
// ignore attributes and no vacuous threshold changes.
// ---------------------------------------------------------------------------

#[test]
fn spool_artifact_materialization_fails_closed_on_row_count_row_bytes_and_replay_ceiling() {
    let (_, max_rows, _, _) = spool_streaming_limits_for_tests();
    let temp = tempfile::tempdir().unwrap();
    let roomy = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let spool = ceiling_spool(&temp, roomy);

    let too_many = vec![sample_event("bound-row-count"); max_rows + 1];
    let error = spool
        .probe_spool_artifact_materialization_for_tests(&too_many)
        .expect_err("row-count overflow must refuse before serialization");
    assert!(
        error.contains("refusing to spool") && error.contains("row"),
        "unexpected row-count refusal: {error}"
    );
    assert!(
        !error.contains("bound-row-count"),
        "refusal diagnostics must not echo charge-record fields: {error}"
    );

    let mut oversized = sample_event("bound-row-bytes");
    oversized.request_id = Some("x".repeat(200 * 1024));
    let error = spool
        .probe_spool_artifact_materialization_for_tests(&[oversized])
        .expect_err("an oversize conservative row bound must refuse");
    assert!(
        error.contains("refusing to spool a row") && error.contains("byte"),
        "unexpected row-byte refusal: {error}"
    );

    // Large enough to serialize one JSON row, but below the streaming-replay
    // minimum the writer proves before publishing a durable artifact.
    let tight = leaked_chargeback_test_ceiling(64 * 1024);
    let tight_spool = ceiling_spool(&tempfile::tempdir().unwrap(), tight);
    let error = tight_spool
        .probe_spool_artifact_materialization_for_tests(&[sample_event("bound-replay-ceiling")])
        .expect_err("artifacts that cannot stream under the ceiling must be refused");
    assert!(
        error.contains("streaming replay") || error.contains("retained bytes"),
        "unexpected replay-ceiling refusal: {error}"
    );
    assert_eq!(tight.used(), 0);
    assert_eq!(
        spool_split_worklist_max_entries_for_tests(),
        usize::BITS as usize + 4
    );
}

#[test]
fn streaming_replay_batch_range_validation_fails_closed() {
    let ceiling = leaked_chargeback_test_ceiling(64 * 1024);
    let [empty, out_of_range, inverted] =
        probe_streaming_replay_batch_range_errors_for_tests(ceiling)
            .expect("range probes must run under the test ceiling");
    assert!(empty.contains("empty batch range"), "{empty}");
    assert!(out_of_range.contains("out of range"), "{out_of_range}");
    assert!(inverted.contains("byte range is invalid"), "{inverted}");
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn streaming_spool_reader_defensive_paths_fail_closed() {
    let ceiling = leaked_chargeback_test_ceiling(64 * 1024);
    let [
        batch_overflow,
        single_row,
        payload_charge,
        decoded_overflow,
        buffer_range,
        row_count,
    ] = probe_streaming_spool_reader_defensive_paths_for_tests(ceiling)
        .expect("streaming spool defensive probes must run");
    assert!(
        batch_overflow.contains("batch byte bound overflowed"),
        "{batch_overflow}"
    );
    assert!(
        single_row.contains("one row cannot fit the charged streaming batch"),
        "{single_row}"
    );
    assert!(
        payload_charge.contains("streaming spool batch violated its retained-byte bound"),
        "{payload_charge}"
    );
    assert!(
        decoded_overflow.contains("decoded byte count overflowed"),
        "{decoded_overflow}"
    );
    assert!(
        buffer_range.contains("invalid buffer range"),
        "{buffer_range}"
    );
    assert!(row_count.contains("row count overflowed"), "{row_count}");
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn streaming_replay_batch_range_probe_releases_on_second_index_refusal() {
    let index_bytes = 2usize.saturating_mul(spool_index_entry_bytes_for_tests());
    let ceiling = leaked_chargeback_test_ceiling(128usize.saturating_add(index_bytes));

    let error = probe_streaming_replay_batch_range_errors_for_tests(ceiling)
        .expect_err("the second line index must be refused after both payloads are charged");

    assert!(
        error.contains("ceiling") || error.contains("retained"),
        "unexpected second-index refusal: {error}"
    );
    assert_eq!(ceiling.used(), 0, "all partial probe charges must release");
}

#[cfg(unix)]
#[test]
fn streaming_reader_rejects_a_directory_descriptor_as_non_regular() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("directory.ndjson");
    fs::create_dir(&directory).unwrap();
    let replacement = temp.path().join("unused-replacement.ndjson");
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);

    let error = probe_streaming_replay_path_swap_for_tests(&directory, &replacement, ceiling)
        .expect_err("a directory descriptor must fail before streaming preflight");

    assert!(
        error.contains("not a regular file"),
        "unexpected error: {error}"
    );
    assert_eq!(ceiling.used(), 0);
}

#[cfg(unix)]
#[test]
fn namespace_coordination_lock_rejects_initial_non_files() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let directory_temp = tempfile::tempdir().unwrap();
    let directory_root = SpoolManager::namespace_root_path_for_tests(
        directory_temp.path(),
        &test_owner_spec("node-a"),
    )
    .unwrap();
    fs::create_dir_all(directory_root.join(".spool-quota.lock")).unwrap();
    let directory_error =
        match SpoolManager::for_tests(spool_settings(directory_temp.path(), 1024 * 1024), "node-a")
        {
            Ok(_) => panic!("a directory must never become the namespace coordination lock"),
            Err(error) => error,
        };
    assert!(
        directory_error.contains("securely open") || directory_error.contains("directory"),
        "unexpected initial directory refusal: {directory_error}"
    );

    let temp = tempfile::tempdir().unwrap();
    let namespace_root =
        SpoolManager::namespace_root_path_for_tests(temp.path(), &test_owner_spec("node-a"))
            .unwrap();
    fs::create_dir_all(&namespace_root).unwrap();
    let lock = namespace_root.join(".spool-quota.lock");
    let lock_c = CString::new(lock.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(lock_c.as_ptr(), 0o600) }, 0);

    let error = match SpoolManager::for_tests(spool_settings(temp.path(), 1024 * 1024), "node-a") {
        Ok(_) => panic!("a FIFO must never become the namespace coordination lock"),
        Err(error) => error,
    };

    assert!(
        error.contains("not a regular file") || error.contains("securely open"),
        "unexpected FIFO refusal: {error}"
    );
}

#[tokio::test]
async fn streaming_replay_rejects_concatenated_zstd_past_the_declared_first_frame() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 8 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(format!(
        "01ARZ3NDEKTSV4RRFFQ69G5FG1.{}.ndjson.zst",
        default_test_owner_tag()
    ));
    let first = encode_spool_bytes_without_ratio_padding_for_tests(b"{}\n").unwrap();
    let second = encode_spool_bytes_without_ratio_padding_for_tests(b"{}\n").unwrap();
    let mut concatenated = first;
    concatenated.extend_from_slice(&second);
    fs::write(&source, concatenated).unwrap();

    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("bytes beyond the declared first frame are quarantined, not delivered");

    assert!(!source.exists());
    assert!(
        source
            .with_file_name(format!(
                "{}.corrupt",
                source.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "concatenated decoded bytes must fail the complete preflight bound"
    );
}

#[tokio::test]
async fn streaming_replay_quarantines_an_in_place_row_count_change() {
    let server = MockServer::start().await;
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 8 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FG2"));
    // A row including its newline is exactly one 64 KiB replay-reader buffer.
    // The first 64 rows fill the 4 MiB HTTP batch, while row 65 remains fully
    // validated and ready without any bytes from row 66 buffered behind it.
    fs::write(&source, fixed_width_json_rows(64 * 1024, 66)).unwrap();
    let mutated = Arc::new(AtomicBool::new(false));
    let mutated_for_mock = Arc::clone(&mutated);
    let day_for_mock = day.clone();
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            if !mutated_for_mock.swap(true, Ordering::SeqCst) {
                let claim = current_inflight_file(&day_for_mock);
                std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(claim)
                    .expect("the replay mutation truncates the claimed inode in place");
            }
            ResponseTemplate::new(200)
        })
        .mount(&server)
        .await;

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("a changed second-pass row count is quarantined without retrying delivery");

    assert!(mutated.load(Ordering::SeqCst));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        2,
        "only the completely buffered first batch and row 65 may be delivered"
    );
    assert!(
        source
            .with_file_name(format!(
                "{}.corrupt",
                source.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "the changed artifact must leave the live replay set"
    );
}

#[tokio::test]
async fn streaming_replay_quarantines_a_partial_row_after_in_place_truncation() {
    let server = MockServer::start().await;
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 8 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FG3"));
    // One byte beyond the reader buffer deliberately leaves a partial following
    // row buffered when the first 4 MiB batch is sent. Truncating the same inode
    // must reject that partial row before a second HTTP request is attempted.
    fs::write(&source, fixed_width_json_rows(64 * 1024 + 1, 66)).unwrap();
    let mutated = Arc::new(AtomicBool::new(false));
    let mutated_for_mock = Arc::clone(&mutated);
    let day_for_mock = day.clone();
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            if !mutated_for_mock.swap(true, Ordering::SeqCst) {
                let claim = current_inflight_file(&day_for_mock);
                std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(claim)
                    .expect("the replay mutation truncates the claimed inode in place");
            }
            ResponseTemplate::new(200)
        })
        .mount(&server)
        .await;

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("a partial second-pass row is quarantined without aborting the replay tick");

    assert!(mutated.load(Ordering::SeqCst));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the partial buffered row must fail closed before a second delivery"
    );
    assert!(
        source
            .with_file_name(format!(
                "{}.corrupt",
                source.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "the malformed second-pass artifact must be quarantined"
    );
}

#[tokio::test]
async fn streaming_replay_defers_when_the_second_batch_index_is_starved() {
    let server = MockServer::start().await;
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests_with_ceiling(
        spool_settings(temp.path(), 8 * 1024 * 1024),
        "node-a",
        ceiling,
    )
    .unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FG4"));
    fs::write(&source, fixed_width_json_rows(64 * 1024, 66)).unwrap();
    let (_, _, batch_bytes, _) = spool_streaming_limits_for_tests();
    let index_entry_bytes = spool_index_entry_bytes_for_tests();
    let fixed_index_bytes = 128usize.saturating_mul(index_entry_bytes);
    let fixed_worklist_bytes =
        spool_split_worklist_max_entries_for_tests().saturating_mul(index_entry_bytes);
    let narrowed = Arc::new(AtomicBool::new(false));
    let narrowed_for_mock = Arc::clone(&narrowed);
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            if !narrowed_for_mock.swap(true, Ordering::SeqCst) {
                let used = ceiling.used();
                let narrowed_max = used
                    .checked_sub(fixed_index_bytes)
                    .and_then(|value| value.checked_sub(fixed_worklist_bytes))
                    .expect("the active batch holds both fixed reservations");
                assert!(narrowed_max >= batch_bytes);
                ceiling.set_max_unclamped_for_test(narrowed_max);
            }
            ResponseTemplate::new(200)
        })
        .mount(&server)
        .await;

    let error = replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 4, ceiling)
        .await
        .expect_err("the second batch body may fit while its fixed index is refused");

    assert!(narrowed.load(Ordering::SeqCst));
    assert!(
        error.contains("ceiling") || error.contains("deferred"),
        "unexpected second-index refusal: {error}"
    );
    assert!(
        source.exists(),
        "an index refusal must restore the source claim"
    );
    assert_eq!(ceiling.used(), 0);
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn dead_letter_publish_refuses_a_final_planted_after_writer_open() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-dead-letter-publish-race")])
        .unwrap();
    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    let source_parent = source.parent().unwrap().to_path_buf();
    let payload_final = dead_letter_payload_path(&source);
    let payload_name = payload_final
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let planted = Arc::new(AtomicBool::new(false));
    let planted_for_hook = Arc::clone(&planted);
    let payload_for_hook = payload_final.clone();
    let _clear_hook = ClearSpoolWriteHookGuard;
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, root| {
        if point != SpoolWriteHookPoint::BeforeNamespaceLock
            || root != namespace_root.as_path()
            || planted_for_hook.load(Ordering::SeqCst)
        {
            return;
        }
        let writer_is_open = fs::read_dir(&source_parent)
            .expect("dead-letter race hook reads the spool day")
            .filter_map(Result::ok)
            .any(|entry| {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return false;
                };
                name.starts_with(&format!("{payload_name}.write-")) && name.ends_with(".tmp")
            });
        if writer_is_open {
            fs::create_dir(&payload_for_hook)
                .expect("the race plants a non-file final after writer preflight");
            planted_for_hook.store(true, Ordering::SeqCst);
        }
    })));

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("a post-open non-file final must fail dead-letter publication");
    set_spool_write_hook_for_tests(None);

    assert!(planted.load(Ordering::SeqCst));
    assert!(
        error.contains("failed to replace prior dead-letter payload")
            || error.contains("directory"),
        "unexpected post-open publish refusal: {error}"
    );
    assert!(
        source.exists(),
        "the complete source claim must be restored"
    );
    assert!(
        payload_final.is_dir(),
        "the planted final is never replaced"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn dead_letter_publish_refuses_a_completed_temp_path_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let event = sample_event("evt-dead-letter-temp-replacement");
    let expected_payload = serialize_json_each_row(std::slice::from_ref(&event)).unwrap();
    let source = spool.write_events(&[event]).unwrap();
    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    let source_parent = source.parent().unwrap().to_path_buf();
    let payload_final = dead_letter_payload_path(&source);
    let payload_name = payload_final
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let displaced_writer = temp.path().join("displaced-dead-letter-writer");
    let displaced_for_hook = displaced_writer.clone();
    let hostile_payload = b"hostile-planted-dead-letter".to_vec();
    let hostile_for_hook = hostile_payload.clone();
    let planted_temp = Arc::new(Mutex::new(None));
    let planted_for_hook = Arc::clone(&planted_temp);
    let replaced = Arc::new(AtomicBool::new(false));
    let replaced_for_hook = Arc::clone(&replaced);
    let _clear_hook = ClearSpoolWriteHookGuard;
    set_spool_write_hook_for_tests(Some(Arc::new(move |point, root| {
        if point != SpoolWriteHookPoint::BeforeNamespaceLock
            || root != namespace_root.as_path()
            || replaced_for_hook.load(Ordering::SeqCst)
        {
            return;
        }
        let completed_temp = fs::read_dir(&source_parent)
            .expect("dead-letter replacement hook reads the spool day")
            .filter_map(Result::ok)
            .find_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                let metadata = entry.metadata().ok()?;
                (name.starts_with(&format!("{payload_name}.write-"))
                    && name.ends_with(".tmp")
                    && metadata.len() > 0)
                    .then_some(entry.path())
            });
        let Some(completed_temp) = completed_temp else {
            return;
        };
        fs::rename(&completed_temp, &displaced_for_hook)
            .expect("the race preserves the completed writer inode outside the managed path");
        fs::write(&completed_temp, &hostile_for_hook)
            .expect("the race plants hostile bytes at the predictable temp path");
        fs::set_permissions(&completed_temp, fs::Permissions::from_mode(0o600))
            .expect("the planted replacement has valid owner-only permissions");
        *planted_for_hook.lock().expect("planted temp path") = Some(completed_temp);
        replaced_for_hook.store(true, Ordering::SeqCst);
    })));

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("a replaced completed dead-letter temp must fail publication");
    set_spool_write_hook_for_tests(None);

    assert!(replaced.load(Ordering::SeqCst));
    assert!(
        error.contains("metadata changed")
            || error.contains("does not name the opened writer file")
            || error.contains("file identity"),
        "unexpected completed-temp replacement refusal: {error}"
    );
    assert!(
        source.exists(),
        "the authoritative source must remain replayable"
    );
    assert!(
        !payload_final.exists(),
        "hostile temp bytes must never be accepted as the dead-letter payload"
    );
    assert!(
        !dead_letter_meta_path(&source).exists(),
        "metadata must not publish for a rejected payload identity"
    );
    assert_eq!(
        fs::read_to_string(&displaced_writer).unwrap(),
        expected_payload,
        "the displaced original descriptor target must not be modified"
    );
    let planted_temp = planted_temp
        .lock()
        .unwrap()
        .clone()
        .expect("the hostile temp path was recorded");
    assert_eq!(
        fs::read(planted_temp).unwrap(),
        hostile_payload,
        "the planted replacement must not be removed or rewritten"
    );
}

#[tokio::test]
async fn dead_letter_handoff_preserves_evidence_when_the_source_path_becomes_a_directory() {
    let server = MockServer::start().await;
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-dead-letter-source-race")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let displaced = temp.path().join("displaced-authoritative-source.ndjson");
    let displaced_for_mock = displaced.clone();
    let changed = Arc::new(AtomicBool::new(false));
    let changed_for_mock = Arc::clone(&changed);
    let planted_claim: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));
    let planted_claim_for_mock = Arc::clone(&planted_claim);
    Mock::given(method("POST"))
        .respond_with(move |_: &Request| {
            if !changed_for_mock.swap(true, Ordering::SeqCst) {
                let claim = current_inflight_file(&day);
                fs::rename(&claim, &displaced_for_mock)
                    .expect("the race preserves the original claimed inode");
                fs::create_dir(&claim).expect("the race plants a directory at the claim path");
                *planted_claim_for_mock.lock().expect("planted claim slot") = Some(claim);
            }
            ResponseTemplate::new(400)
        })
        .mount(&server)
        .await;

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("the terminal claim operation must refuse a replaced claim pathname");

    assert!(changed.load(Ordering::SeqCst));
    assert!(
        error.contains("no longer resolves to the authoritative claimed artifact"),
        "unexpected terminal claim refusal: {error}"
    );
    let planted = planted_claim
        .lock()
        .expect("planted claim slot")
        .clone()
        .expect("the race plants exactly one claim path");
    assert!(
        planted.is_dir(),
        "the planted directory must be left exactly where it was planted"
    );
    assert!(
        !source.exists(),
        "a claim pathname that stopped resolving to the pinned artifact must never be released back to the replayable name"
    );
    let displaced_bytes = fs::read(&displaced).unwrap();
    assert!(
        String::from_utf8_lossy(&displaced_bytes).contains("evt-dead-letter-source-race"),
        "the displaced authoritative evidence must remain intact"
    );
    assert!(dead_letter_payload_path(&source).exists());
    assert!(dead_letter_meta_path(&source).exists());
}

// ---------------------------------------------------------------------------
// Same-UID substitution of the claim pathname through the production replay
// path. The authoritative artifact is a descriptor this replay opened and
// validated, not a metadata snapshot, so a planted regular file at the claim
// pathname must never be renamed, removed, quarantined, released, or accounted
// out — while the dead-letter evidence this attempt constructed must still be
// published durably.
// ---------------------------------------------------------------------------

/// Bytes of the file a same-UID racer plants at the claim pathname.
#[cfg(unix)]
const PLANTED_CLAIM_SUBSTITUTE: &[u8] = b"{\"event_id\":\"planted-not-the-claimed-artifact\"}\n";

/// Clears the process-global replay hook on every exit path, panics included.
#[cfg(unix)]
struct ClearReplayHookOnDrop;

#[cfg(unix)]
impl Drop for ClearReplayHookOnDrop {
    fn drop(&mut self) {
        set_spool_replay_hook_for_tests(None);
    }
}

/// Install a one-shot substitution of the observed pathname at `point`.
///
/// The authoritative artifact is renamed out of the managed tree first, so its
/// inode survives exactly as a hostile racer would leave it, and a *different*
/// regular file then occupies that pathname. Points before the atomic claim
/// rename observe the DURABLE candidate; later points observe the claim.
/// Returns the "fired" flag and the pathname the race observed.
#[cfg(unix)]
fn install_claim_substitution_hook(
    namespace_root: std::path::PathBuf,
    displaced: std::path::PathBuf,
    point: SpoolReplayHookPoint,
) -> (Arc<AtomicBool>, Arc<Mutex<Option<std::path::PathBuf>>>) {
    let fired = Arc::new(AtomicBool::new(false));
    let claim_slot: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));
    let fired_for_hook = Arc::clone(&fired);
    let claim_for_hook = Arc::clone(&claim_slot);
    set_spool_replay_hook_for_tests(Some(Arc::new(move |observed, claimed| {
        if observed != point || !claimed.starts_with(&namespace_root) {
            return;
        }
        if fired_for_hook.swap(true, Ordering::SeqCst) {
            return;
        }
        fs::rename(claimed, &displaced).expect("the race preserves the claimed inode");
        fs::write(claimed, PLANTED_CLAIM_SUBSTITUTE)
            .expect("the race plants a substitute regular file");
        *claim_for_hook.lock().expect("planted claim slot") = Some(claimed.to_path_buf());
    })));
    (fired, claim_slot)
}

#[cfg(unix)]
fn spool_day_has_quarantine(day: &Path) -> bool {
    fs::read_dir(day)
        .expect("spool day remains readable")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".corrupt"))
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn claim_substituted_after_the_validated_replay_open_is_never_mutated() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-substitute-after-validated-open")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let authoritative_bytes = fs::read(&source).unwrap();
    let before = spool.cached_stats_for_tests();
    let displaced = outside.path().join("displaced-authoritative-source.ndjson");

    let clear = ClearReplayHookOnDrop;
    let (fired, claim_slot) = install_claim_substitution_hook(
        spool.namespace_root_for_tests().to_path_buf(),
        displaced.clone(),
        SpoolReplayHookPoint::AfterMatchingReplayOpen,
    );

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("a substituted claim pathname must fail the tick");
    drop(clear);

    assert!(fired.load(Ordering::SeqCst));
    // The refusal can surface either at claim renewal (a rename of the claim
    // pathname) or at the terminal claim operation, depending on whether this
    // batch crosses a lease second. Both are the same fail-closed decision and
    // both must leave the substitute alone, so the assertions below hold either
    // way; the deterministic evidence-publication case is covered by
    // `claim_substituted_before_finalization_still_publishes_but_never_mutates`.
    assert!(
        error.contains("no longer resolves to the authoritative claimed artifact"),
        "unexpected substituted-claim diagnostic: {error}"
    );
    let claim = claim_slot
        .lock()
        .expect("planted claim slot")
        .clone()
        .expect("the race plants exactly one claim pathname");
    assert_eq!(
        fs::read(&claim).unwrap(),
        PLANTED_CLAIM_SUBSTITUTE,
        "the planted regular file must be byte-identical and never rewritten"
    );
    assert!(
        !source.exists(),
        "a substituted claim must never be released back to the replayable name"
    );
    assert!(
        !spool_day_has_quarantine(&day),
        "a substituted claim must never be quarantined"
    );
    assert_eq!(
        fs::read(&displaced).unwrap(),
        authoritative_bytes,
        "the displaced authoritative artifact must remain intact"
    );
    let after = spool.cached_stats_for_tests();
    assert!(
        after.files >= before.files && after.bytes >= before.bytes,
        "no owned-file or owned-byte accounting may be released for a pathname that stopped resolving to the pinned artifact"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn claim_substituted_before_finalization_still_publishes_but_never_mutates() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-substitute-before-finalize")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let authoritative_bytes = fs::read(&source).unwrap();
    let before = spool.cached_stats_for_tests();
    let displaced = outside.path().join("displaced-authoritative-source.ndjson");

    let clear = ClearReplayHookOnDrop;
    let (fired, claim_slot) = install_claim_substitution_hook(
        spool.namespace_root_for_tests().to_path_buf(),
        displaced.clone(),
        SpoolReplayHookPoint::BeforeReplayFinalize,
    );

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("the terminal claim operation must refuse a substituted claim pathname");
    drop(clear);

    assert!(fired.load(Ordering::SeqCst));
    assert!(
        error.contains("no longer resolves to the authoritative claimed artifact"),
        "unexpected terminal-claim diagnostic: {error}"
    );

    // Constructive evidence is NOT suppressed by the substitution: both durable
    // rejected artifacts are published for the rows this replay actually read
    // from its own validated descriptor.
    let payload_path = dead_letter_payload_path(&source);
    let meta_path = dead_letter_meta_path(&source);
    assert_eq!(
        fs::read(&payload_path).unwrap(),
        authoritative_bytes,
        "the rejected payload must hold exactly the rows the validated descriptor produced"
    );
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(meta["rejected_rows"], 1);

    // Publishing that evidence authorizes nothing against the substitute.
    let claim = claim_slot
        .lock()
        .expect("planted claim slot")
        .clone()
        .expect("the race plants exactly one claim pathname");
    assert_eq!(
        fs::read(&claim).unwrap(),
        PLANTED_CLAIM_SUBSTITUTE,
        "the planted regular file must be byte-identical and never rewritten"
    );
    assert!(
        !source.exists(),
        "the substitute must never be released back to the replayable name"
    );
    assert!(
        !spool_day_has_quarantine(&day),
        "the substitute must never be quarantined"
    );
    assert_eq!(fs::read(&displaced).unwrap(), authoritative_bytes);

    // Exactly two owned records were added and nothing was accounted out.
    let payload_len = fs::metadata(&payload_path).unwrap().len();
    let meta_len = fs::metadata(&meta_path).unwrap().len();
    let after = spool.cached_stats_for_tests();
    assert_eq!(
        after.files,
        before.files.saturating_add(2),
        "the substituted claim must not be accounted out of the owned inventory"
    );
    assert_eq!(
        after.bytes,
        before
            .bytes
            .saturating_add(payload_len)
            .saturating_add(meta_len),
        "only the newly published evidence may change owned bytes"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn generic_finalize_failure_never_releases_a_substituted_claim() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400]).await;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-generic-finalize-failure")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let meta_path = dead_letter_meta_path(&source);
    // Ordinary I/O failure inside finalization: the metadata temp name is
    // occupied by a directory, exactly as in
    // `replay_keeps_original_when_dead_letter_metadata_cannot_be_written`.
    let meta_temp = meta_path.with_file_name(format!(
        "{}.tmp",
        meta_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    ));
    fs::create_dir(&meta_temp).unwrap();
    let displaced = outside.path().join("displaced-authoritative-source.ndjson");

    let clear = ClearReplayHookOnDrop;
    let (fired, claim_slot) = install_claim_substitution_hook(
        spool.namespace_root_for_tests().to_path_buf(),
        displaced.clone(),
        SpoolReplayHookPoint::BeforeReplayFinalize,
    );

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("a blocked metadata store must still fail the tick");
    drop(clear);

    assert!(fired.load(Ordering::SeqCst));
    // The ordinary retryable cause is preserved, and the release it would
    // normally perform is refused because the pathname is no longer the claim.
    assert!(
        error.contains("failed to create spool temp file"),
        "the generic finalize failure must still be reported: {error}"
    );
    assert!(
        error.contains("no longer resolves to the authoritative claimed artifact"),
        "the refused release must be reported: {error}"
    );
    let claim = claim_slot
        .lock()
        .expect("planted claim slot")
        .clone()
        .expect("the race plants exactly one claim pathname");
    assert_eq!(
        fs::read(&claim).unwrap(),
        PLANTED_CLAIM_SUBSTITUTE,
        "the generic finalize-error path must not rewrite the substitute"
    );
    assert!(
        !source.exists(),
        "the generic finalize-error release must not rename the substitute into the replayable namespace"
    );
    assert!(
        !spool_day_has_quarantine(&day),
        "the generic finalize-error path must not quarantine the substitute"
    );
    assert!(
        !meta_path.exists(),
        "partial metadata must not be published when its store is blocked"
    );
    assert!(
        dead_letter_payload_path(&source).exists(),
        "a payload published before the metadata failure remains recoverable"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn candidate_substituted_before_the_first_preflight_is_never_mutated() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-substitute-before-preflight")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let authoritative_bytes = fs::read(&source).unwrap();
    let before = spool.cached_stats_for_tests();
    let displaced = outside.path().join("displaced-authoritative-candidate.ndjson");

    let clear = ClearReplayHookOnDrop;
    let (fired, substituted) = install_claim_substitution_hook(
        spool.namespace_root_for_tests().to_path_buf(),
        displaced.clone(),
        SpoolReplayHookPoint::AfterCandidatePin,
    );

    // Authority exists before the FIRST mutation of the handoff, so the refusal
    // happens while the candidate is still at its durable name and no claim
    // rename, release, or quarantine has been attempted.
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("a substituted candidate is refused without aborting the tick");
    drop(clear);

    assert!(fired.load(Ordering::SeqCst));
    let observed = substituted
        .lock()
        .expect("planted candidate slot")
        .clone()
        .expect("the race plants exactly one candidate pathname");
    assert_eq!(
        observed, source,
        "the race must replace the durable candidate itself, before any claim"
    );
    assert_eq!(
        fs::read(&source).unwrap(),
        PLANTED_CLAIM_SUBSTITUTE,
        "the planted regular file must be byte- and pathname-identical"
    );
    assert!(
        !spool_day_has_quarantine(&day),
        "an unproven candidate pathname must never be quarantined"
    );
    assert_eq!(
        fs::read(&displaced).unwrap(),
        authoritative_bytes,
        "the displaced authoritative artifact must remain intact"
    );
    let after = spool.cached_stats_for_tests();
    assert!(
        after.files >= before.files && after.bytes >= before.bytes,
        "nothing may be accounted out for a candidate that stopped resolving to the pinned artifact"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn candidate_substituted_before_the_claim_rename_is_never_claimed() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-substitute-before-claim-rename")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let authoritative_bytes = fs::read(&source).unwrap();
    let displaced = outside.path().join("displaced-authoritative-candidate.ndjson");

    let clear = ClearReplayHookOnDrop;
    let (fired, substituted) = install_claim_substitution_hook(
        spool.namespace_root_for_tests().to_path_buf(),
        displaced.clone(),
        SpoolReplayHookPoint::BeforeBoundedPreflightValidation,
    );

    // The validated descriptor stays readable, so the complete bounded preflight
    // still succeeds — but the atomic claim rename is a mutation of a pathname
    // that no longer resolves to it, and is refused before it happens.
    let error = replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect_err("the atomic claim rename must refuse a substituted candidate");
    drop(clear);

    assert!(fired.load(Ordering::SeqCst));
    assert!(
        error.contains("no longer resolves to the authoritative claimed artifact"),
        "unexpected pre-claim refusal diagnostic: {error}"
    );
    let observed = substituted
        .lock()
        .expect("planted candidate slot")
        .clone()
        .expect("the race plants exactly one candidate pathname");
    assert_eq!(observed, source);
    assert_eq!(
        fs::read(&source).unwrap(),
        PLANTED_CLAIM_SUBSTITUTE,
        "the substitute must never be renamed into the claim namespace"
    );
    let entries: Vec<String> = fs::read_dir(&day)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec![source.file_name().unwrap().to_string_lossy().into_owned()],
        "no claim, quarantine, or dead-letter pathname may be created: {entries:?}"
    );
    assert_eq!(fs::read(&displaced).unwrap(), authoritative_bytes);
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn in_place_rewrite_with_restored_mtime_never_authorizes_the_terminal_removal() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-in-place-rewrite")])
        .unwrap();
    let day = source.parent().unwrap().to_path_buf();
    let before = spool.cached_stats_for_tests();

    // A same-UID writer rewrites the pinned inode with same-length bytes and
    // then restores mtime with `utimensat`. Node + length + mtime alone cannot
    // see that; ctime can, and no userland API can set it back.
    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    let rewritten: Arc<Mutex<Option<(std::path::PathBuf, bool)>>> = Arc::new(Mutex::new(None));
    let rewritten_for_hook = Arc::clone(&rewritten);
    set_spool_replay_hook_for_tests(Some(Arc::new(move |point, claimed| {
        if point != SpoolReplayHookPoint::BeforeReplayFinalize
            || !claimed.starts_with(&namespace_root)
        {
            return;
        }
        let mut slot = rewritten_for_hook.lock().expect("in-place rewrite slot");
        if slot.is_some() {
            return;
        }
        let original = fs::metadata(claimed).expect("the claimed artifact is stat-able");
        let mut replacement = vec![b' '; original.len() as usize];
        if let Some(first) = replacement.first_mut() {
            *first = b'#';
        }
        std::fs::OpenOptions::new()
            .write(true)
            .open(claimed)
            .expect("a same-UID writer can reopen the claimed inode")
            .write_all(&replacement)
            .expect("the in-place rewrite keeps the same inode and length");
        let times = [
            libc::timespec {
                tv_sec: original.atime(),
                tv_nsec: original.atime_nsec(),
            },
            libc::timespec {
                tv_sec: original.mtime(),
                tv_nsec: original.mtime_nsec(),
            },
        ];
        let raw = std::ffi::CString::new(claimed.as_os_str().as_bytes()).unwrap();
        let restored =
            unsafe { libc::utimensat(libc::AT_FDCWD, raw.as_ptr(), times.as_ptr(), 0) } == 0;
        let now = fs::metadata(claimed).expect("the claimed artifact is stat-able");
        let same_node = now.len() == original.len() && now.ino() == original.ino();
        let same_mtime =
            now.mtime() == original.mtime() && now.mtime_nsec() == original.mtime_nsec();
        let mtime_defeated = restored && same_node && same_mtime;
        *slot = Some((claimed.to_path_buf(), mtime_defeated));
    })));
    let clear = ClearReplayHookOnDrop;

    let error = replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect_err("an in-place rewrite must refuse the terminal claim removal");
    drop(clear);

    let (claim, mtime_defeated) = rewritten
        .lock()
        .expect("in-place rewrite slot")
        .clone()
        .expect("the race rewrites exactly one claim pathname");
    assert!(
        mtime_defeated,
        "the regression only proves anything if node, length, and mtime all still match"
    );
    assert!(
        error.contains("no longer resolves to the authoritative claimed artifact"),
        "an mtime-restored in-place rewrite must still fail closed: {error}"
    );
    assert!(
        claim.exists(),
        "the rewritten claim must not be unlinked as this handoff's artifact"
    );
    assert!(
        !source.exists(),
        "the rewritten claim must not be released back to the replayable name"
    );
    assert!(
        !spool_day_has_quarantine(&day),
        "the terminal refusal must not quarantine either"
    );
    let after = spool.cached_stats_for_tests();
    assert!(
        after.files >= before.files && after.bytes >= before.bytes,
        "no owned-file or owned-byte accounting may be released for a rewritten claim"
    );
}

#[cfg(unix)]
#[test]
fn streaming_replay_refuses_a_path_swap_after_bounded_preflight() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.ndjson");
    let replacement = temp.path().join("replacement.ndjson");
    fs::write(&source, b"{\"event_id\":\"validated-row\"}\n").unwrap();
    fs::write(&replacement, b"{\"event_id\":\"replaced-row!\"}\n").unwrap();
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);

    let error = probe_streaming_replay_path_swap_for_tests(&source, &replacement, ceiling)
        .expect("a replaced replay path must fail closed after preflight");

    assert!(error.contains("changed file identity"), "{error}");
    assert!(!error.contains("validated-row"), "{error}");
    assert!(!error.contains("replaced-row"), "{error}");
    assert_eq!(
        fs::read(&source).unwrap(),
        b"{\"event_id\":\"replaced-row!\"}\n"
    );
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn preallocated_payload_capacity_guard_refuses_undersized_reservations() {
    let ceiling = leaked_chargeback_test_ceiling(64 * 1024);
    probe_preallocated_payload_capacity_guard_for_tests(ceiling)
        .expect("capacity guard must refuse an undersized reservation");
    assert_eq!(ceiling.used(), 0);
}

#[tokio::test]
async fn spool_replay_quarantines_hostile_json_shapes_and_whitespace_only_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    for (ulid, payload, label) in [
        (
            "01ARZ3NDEKTSV4RRFFQ69G5FF1",
            &b"[1,2,3]\n"[..],
            "non-object JSONEachRow",
        ),
        (
            "01ARZ3NDEKTSV4RRFFQ69G5FF2",
            &b"{not-json}\n"[..],
            "malformed JSONEachRow",
        ),
        (
            "01ARZ3NDEKTSV4RRFFQ69G5FF3",
            &b"   "[..],
            "whitespace-only artifact",
        ),
    ] {
        let source = day.join(owned_data_name(ulid));
        fs::write(&source, payload).unwrap();
        replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
            .await
            .unwrap_or_else(|error| panic!("{label} must not become a retryable tick: {error}"));
        if label.contains("whitespace-only") {
            // Whitespace-only content yields zero billable rows and is removed.
            assert!(
                !source.exists(),
                "{label} must leave no durable claim behind"
            );
        } else {
            assert!(
                !source.exists(),
                "{label} must be removed from the replay set"
            );
            assert!(
                source
                    .with_file_name(format!(
                        "{}.corrupt",
                        source.file_name().unwrap().to_string_lossy()
                    ))
                    .exists(),
                "{label} must be quarantined for operator review"
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn spool_replay_fails_closed_on_non_file_hardlink_symlink_and_declared_zstd_size() {
    use std::fs::hard_link;
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let directory = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FF4"));
    fs::create_dir(&directory).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect(
            "a directory planted as a spool artifact is skipped/quarantine-failed without aborting the tick",
        );

    let linked = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FF5"));
    fs::write(&linked, br#"{"event_id":"hardlink"}"#).unwrap();
    let alias = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FF6"));
    hard_link(&linked, &alias).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("hard-linked artifacts are unreadable and must not abort later replay");
    assert!(
        linked
            .with_file_name(format!(
                "{}.corrupt",
                linked.file_name().unwrap().to_string_lossy()
            ))
            .exists()
            || alias
                .with_file_name(format!(
                    "{}.corrupt",
                    alias.file_name().unwrap().to_string_lossy()
                ))
                .exists()
            || (!linked.exists() && !alias.exists()),
        "at least one hard-linked name must leave the live replay set"
    );

    let outside = temp.path().join("outside-symlink-target");
    fs::write(&outside, br#"{"event_id":"symlink"}"#).unwrap();
    let linked_path = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FF7"));
    symlink(&outside, &linked_path).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("symlink inventory entries must not abort the tick");
    assert_eq!(fs::read(&outside).unwrap(), br#"{"event_id":"symlink"}"#);

    // A same-UID mode-000 data file still appears in inventory but fails the
    // secure open; that is an unreadable quarantine path, not a retry.
    let denied = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFB"));
    fs::write(&denied, br#"{"event_id":"mode-denied"}"#).unwrap();
    let mut denied_perms = fs::metadata(&denied).unwrap().permissions();
    denied_perms.set_mode(0o000);
    fs::set_permissions(&denied, denied_perms).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("permission-denied opens are unreadable, not retryable");
    let denied_corrupt = denied.with_file_name(format!(
        "{}.corrupt",
        denied.file_name().unwrap().to_string_lossy()
    ));
    let restore_path = if denied_corrupt.exists() {
        denied_corrupt
    } else {
        denied.clone()
    };
    if restore_path.exists() {
        let mut restore = fs::metadata(&restore_path).unwrap().permissions();
        restore.set_mode(0o600);
        fs::set_permissions(&restore_path, restore).unwrap();
    }

    let declared = day.join(format!(
        "01ARZ3NDEKTSV4RRFFQ69G5FF8.{}.ndjson.zst",
        default_test_owner_tag()
    ));
    let frame =
        encode_zstd_declaring_content_size_for_tests(spool_artifact_byte_limit_for_tests() + 1);
    fs::write(&declared, frame).unwrap();
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("an oversized declared zstd size is quarantined before decode");
    assert!(
        declared
            .with_file_name(format!(
                "{}.corrupt",
                declared.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "declared-size overflow must quarantine the planted frame"
    );
}

#[tokio::test]
async fn spool_replay_defers_when_ceiling_cannot_hold_stream_and_batch() {
    let temp = tempfile::tempdir().unwrap();
    // Between one small-file stream reservation (~row + 64 KiB reader) and the
    // full row+batch+index+worklist+dead-letter budget proven at open.
    let ceiling = leaked_chargeback_test_ceiling(100 * 1024);
    let spool = ceiling_spool(&temp, ceiling);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FF9"));
    fs::write(&source, br#"{"event_id":"ceiling-stream-batch"}"#).unwrap();

    let error = replay_spool_once_with_ceiling_for_tests(&spool, "http://127.0.0.1:1/", 4, ceiling)
        .await
        .expect_err("a ceiling that cannot hold one row and batch must defer");
    assert!(
        error.contains("ceiling") || error.contains("streaming"),
        "unexpected deferral diagnostic: {error}"
    );
    assert!(
        source.exists(),
        "ceiling deferral must leave the durable record claimable"
    );
    assert_eq!(ceiling.used(), 0);
}

#[tokio::test]
async fn spool_replay_defers_when_a_peer_reservation_starves_batch_admission() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let ceiling = leaked_chargeback_test_ceiling(2 * 1024 * 1024);
    let spool = ceiling_spool(&temp, ceiling);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFC"));
    fs::write(&source, br#"{"event_id":"peer-starved-batch"}"#).unwrap();

    // Leave enough headroom for the fixed stream reservation and dead-letter
    // tally, but not for the batch body the open path still sizes from max().
    let leave = 200 * 1024;
    let peer_hold = ceiling
        .try_acquire(ceiling.max().saturating_sub(leave))
        .expect("peer reservation must fit");

    let error = replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 4, ceiling)
        .await
        .expect_err("a peer-saturated ceiling must defer before delivery");
    assert!(
        error.contains("ceiling") || error.contains("deferred"),
        "unexpected peer-starvation diagnostic: {error}"
    );
    assert!(
        !error.to_ascii_lowercase().contains("peer-starved"),
        "deferral diagnostics must not echo charge-record fields: {error}"
    );
    assert!(source.exists(), "deferral must leave the claimable source");
    drop(peer_hold);
    assert_eq!(ceiling.used(), 0);

    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 4, ceiling)
        .await
        .expect("replay must recover after the peer reservation releases");
    assert!(!source.exists());
}

#[tokio::test]
async fn spool_replay_defers_when_a_peer_reservation_starves_dead_letter_tally() {
    let temp = tempfile::tempdir().unwrap();
    let ceiling = leaked_chargeback_test_ceiling(2 * 1024 * 1024);
    let spool = ceiling_spool(&temp, ceiling);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFD"));
    fs::write(&source, br#"{"event_id":"peer-starved-tally"}"#).unwrap();

    // Enough for the stream reservation alone after open, but not for the
    // fixed dead-letter tally that replay allocates before the first batch.
    let leave = 70 * 1024;
    let peer_hold = ceiling
        .try_acquire(ceiling.max().saturating_sub(leave))
        .expect("peer reservation must fit");

    let error = replay_spool_once_with_ceiling_for_tests(&spool, "http://127.0.0.1:1/", 4, ceiling)
        .await
        .expect_err("a peer-saturated ceiling must defer before isolation state exists");
    assert!(
        error.contains("ceiling") || error.contains("deferred"),
        "unexpected tally-starvation diagnostic: {error}"
    );
    assert!(source.exists());
    drop(peer_hold);
    assert_eq!(ceiling.used(), 0);
}

#[tokio::test]
async fn dead_letter_publish_faults_restore_the_authoritative_source() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[400, 400, 400, 400, 400, 400, 400, 400]).await;

    let temp = tempfile::tempdir().unwrap();
    let settings = spool_settings(temp.path(), 1024 * 1024);
    let clean = SpoolManager::for_tests(settings.clone(), "node-a").unwrap();
    let generation = clean.generation_for_tests();
    let source = clean
        .write_events(&[sample_event("evt-dead-letter-fault")])
        .unwrap();
    drop(clean);

    // Block create_new on the dead-letter payload temp.
    let blocked = SpoolManager::for_tests_with_owner_and_faults(
        settings.clone(),
        &test_owner_spec("node-a"),
        generation,
        SpoolFsFault::None,
    )
    .unwrap();
    let payload_final = dead_letter_payload_path(&source);
    let payload_temp = blocked
        .write_temp_path_for_tests(&payload_final)
        .expect("dead-letter temp path must resolve");
    fs::write(&payload_temp, b"blocker").unwrap();
    let error = replay_spool_once_for_tests(&blocked, &server.uri())
        .await
        .expect_err("a blocked dead-letter temp must fail closed");
    assert!(
        error.contains("failed to create dead-letter payload temp")
            || error.contains("dead-letter"),
        "unexpected create failure: {error}"
    );
    assert!(source.exists(), "source must remain authoritative");
    let _ = fs::remove_file(&payload_temp);
    drop(blocked);

    // Prior payload path occupied by a directory: replace/remove fails closed.
    let occupied = SpoolManager::for_tests_with_owner_and_faults(
        settings.clone(),
        &test_owner_spec("node-a"),
        generation,
        SpoolFsFault::None,
    )
    .unwrap();
    fs::create_dir(&payload_final).unwrap();
    let error = replay_spool_once_for_tests(&occupied, &server.uri())
        .await
        .expect_err("a directory planted at the dead-letter payload path must fail closed");
    assert!(
        error.contains("failed to replace prior dead-letter payload")
            || error.contains("dead-letter")
            || error.contains("Is a directory")
            || error.contains("directory"),
        "unexpected replace failure: {error}"
    );
    assert!(source.exists(), "source must remain authoritative");
    let _ = fs::remove_dir(&payload_final);
    drop(occupied);

    for fault in [
        SpoolFsFault::FileSync,
        #[cfg(unix)]
        SpoolFsFault::DirOpen,
        #[cfg(unix)]
        SpoolFsFault::DirSync,
    ] {
        let faulted = SpoolManager::for_tests_with_owner_and_faults(
            settings.clone(),
            &test_owner_spec("node-a"),
            generation,
            fault,
        )
        .unwrap();
        let error = match replay_spool_once_for_tests(&faulted, &server.uri()).await {
            Err(error) => error,
            Ok(()) => panic!("{fault:?} during dead-letter publish must fail the tick"),
        };
        assert!(
            error.contains("injected fault")
                || error.contains("dead-letter")
                || error.contains("fsync")
                || error.contains("directory"),
            "unexpected {fault:?} diagnostic: {error}"
        );
        assert!(
            source.exists(),
            "{fault:?} must restore the authoritative source claim"
        );
        drop(faulted);
    }

    let empty_probe = SpoolManager::for_tests_with_owner_and_faults(
        settings.clone(),
        &test_owner_spec("node-a"),
        generation,
        SpoolFsFault::None,
    )
    .unwrap();
    let empty_error = probe_empty_dead_letter_publish_for_tests(&empty_probe, &source)
        .expect_err("empty dead-letter payloads must not publish");
    assert!(
        empty_error.contains("refusing to publish an empty dead-letter payload"),
        "unexpected empty-publish diagnostic: {empty_error}"
    );
    assert!(source.exists());
    drop(empty_probe);

    // Recovery after the faulted attempts: a clean manager finishes the handoff.
    let recovered = SpoolManager::for_tests_with_owner_and_faults(
        settings,
        &test_owner_spec("node-a"),
        generation,
        SpoolFsFault::None,
    )
    .unwrap();
    replay_spool_once_for_tests(&recovered, &server.uri())
        .await
        .expect("dead-letter handoff must recover once the store is writable");
    assert_rejected_sidecar(&source, 400, "permanent_http");
}

#[tokio::test]
async fn spool_replay_continues_when_quarantine_rename_is_blocked() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();

    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFA"));
    fs::write(&source, b"{not-json}\n").unwrap();
    let quarantine = source.with_file_name(format!(
        "{}.corrupt",
        source.file_name().unwrap().to_string_lossy()
    ));
    fs::create_dir(&quarantine).unwrap();
    fs::write(quarantine.join("blocker"), b"x").unwrap();

    let newer = spool
        .write_events(&[sample_event("evt-after-quarantine-block")])
        .unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("a blocked quarantine must not abort the tick after the unreadable artifact");
    assert!(
        !source.exists(),
        "the unreadable artifact remains under its in-flight claim until prepare recovers it"
    );
    let retained_claims: Vec<_> = spool
        .list_owned_spool_files_for_tests()
        .unwrap()
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".inflight"))
        })
        .collect();
    assert_eq!(retained_claims.len(), 1);
    assert_eq!(fs::read(&retained_claims[0]).unwrap(), b"{not-json}\n");
    assert!(
        !newer.exists(),
        "later valid artifacts must still replay after a quarantine failure"
    );
    spool
        .prepare_live_storage_for_tests()
        .expect("the next prepare restores an abandoned same-process claim");
    assert!(
        source.exists(),
        "the unquarantinable poison row must return to its durable name for operator intervention"
    );
}

#[cfg(unix)]
#[test]
fn namespace_coordination_lock_rejects_nonempty_and_repairs_insecure_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 1024 * 1024), "node-a").unwrap();
    let lock = spool.namespace_root_for_tests().join(".spool-quota.lock");

    fs::write(&lock, b"not-empty").unwrap();
    let error = spool
        .write_events(&[sample_event("nonempty-quota-lock")])
        .expect_err("a non-empty coordination lock must fail closed");
    assert!(
        error.contains("not empty") || error.contains("coordination"),
        "unexpected nonempty-lock diagnostic: {error}"
    );
    fs::write(&lock, b"").unwrap();

    let mut perms = fs::metadata(&lock).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&lock, perms).unwrap();
    let written = spool
        .write_events(&[sample_event("insecure-mode-repaired")])
        .expect("an insecure but empty coordination lock must be repaired and admitted");
    assert!(written.exists());
    let repaired = fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
    assert_eq!(repaired, 0o600, "replay must restore private lock mode");
}

#[cfg(unix)]
#[test]
fn namespace_coordination_lock_open_refuses_a_directory_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 1024 * 1024), "node-a").unwrap();
    let lock = spool.namespace_root_for_tests().join(".spool-quota.lock");
    fs::remove_file(&lock).unwrap();
    fs::create_dir(&lock).unwrap();

    let error = spool
        .write_events(&[sample_event("directory-quota-lock")])
        .expect_err("a directory planted as the coordination lock must fail closed");
    assert!(
        error.contains("coordination")
            || error.contains("Is a directory")
            || error.contains("directory"),
        "unexpected directory-lock diagnostic: {error}"
    );
}

#[tokio::test]
async fn streaming_replay_quarantines_an_oversized_sparse_artifact_before_http() {
    let hard_limit = spool_artifact_byte_limit_for_tests();
    let temp = tempfile::tempdir().unwrap();
    let spool = SpoolManager::for_tests(
        spool_settings(temp.path(), hard_limit.saturating_mul(2)),
        "node-a",
    )
    .unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFE"));
    let file = fs::File::create(&source).unwrap();
    file.set_len(hard_limit.saturating_add(1)).unwrap();
    drop(file);

    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("an oversized sparse artifact is quarantined, not retried");
    assert!(!source.exists());
    assert!(
        source
            .with_file_name(format!(
                "{}.corrupt",
                source.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "streaming open must quarantine past the hard artifact bound"
    );
}

#[tokio::test]
async fn streaming_replay_quarantines_undecodable_zstd_frames_before_http() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
        SpoolManager::for_tests(spool_settings(temp.path(), 8 * 1024 * 1024), "node-a").unwrap();
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(format!(
        "01ARZ3NDEKTSV4RRFFQ69G5FFF.{}.ndjson.zst",
        default_test_owner_tag()
    ));
    // Valid-looking magic/header prefix that still fails decoder construction.
    fs::write(&source, [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xff, 0xff, 0xff]).unwrap();

    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("an undecodable zstd frame is quarantined without HTTP delivery");
    assert!(
        source
            .with_file_name(format!(
                "{}.corrupt",
                source.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "decoder open failure must quarantine the planted frame"
    );
}

#[test]
fn probe_helpers_fail_closed_on_ceiling_starvation_and_invalid_rows() {
    // Capacity guard reserves 8 bytes first; a one-byte ceiling refuses before
    // the undersized-reservation probe body runs.
    let exhausted = leaked_chargeback_test_ceiling(1);
    let capacity_error = probe_preallocated_payload_capacity_guard_for_tests(exhausted)
        .expect_err("a one-byte ceiling must refuse the preallocated probe");
    assert!(
        capacity_error.contains("ceiling") || capacity_error.contains("retained"),
        "unexpected capacity-guard diagnostic: {capacity_error}"
    );
    assert_eq!(exhausted.used(), 0);

    // Materialize the 64-byte probe body, then refuse the line-index reservation.
    let range_ceiling = leaked_chargeback_test_ceiling(64);
    let range_error = probe_streaming_replay_batch_range_errors_for_tests(range_ceiling)
        .expect_err("a 64-byte ceiling must refuse the batch index reservation");
    assert!(
        range_error.contains("ceiling") || range_error.contains("retained"),
        "unexpected range-probe diagnostic: {range_error}"
    );
    assert_eq!(range_ceiling.used(), 0);

    let temp = tempfile::tempdir().unwrap();
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let spool = ceiling_spool(&temp, ceiling);
    let source = spool
        .write_events(&[sample_event("evt-dead-letter-probe-bounds")])
        .unwrap();
    let empty_error = publish_dead_letter_payload_for_tests(&spool, &source, b"")
        .expect_err("empty dead-letter probe rows must fail closed");
    assert!(
        empty_error.contains("outside the hard row bound"),
        "unexpected empty-row diagnostic: {empty_error}"
    );
    let (row_limit, _, _, _) = spool_streaming_limits_for_tests();
    let oversized = vec![b'x'; row_limit + 1];
    let oversized_error = publish_dead_letter_payload_for_tests(&spool, &source, &oversized)
        .expect_err("oversized dead-letter probe rows must fail closed");
    assert!(
        oversized_error.contains("outside the hard row bound"),
        "unexpected oversized-row diagnostic: {oversized_error}"
    );

    let hold = ceiling
        .try_acquire(ceiling.max())
        .expect("spool ceiling must fill completely");
    let materialize_error = publish_dead_letter_payload_for_tests(&spool, &source, b"{\"a\":1}")
        .expect_err("a saturated ceiling must refuse dead-letter materialization");
    assert!(
        materialize_error.contains("ceiling")
            || materialize_error.contains("retained")
            || materialize_error.contains("materialize")
            || materialize_error.contains("reserve"),
        "unexpected materialize diagnostic: {materialize_error}"
    );
    drop(hold);

    let row = br#"{"a":1}"#;
    let leave = row.len();
    let hold = ceiling
        .try_acquire(ceiling.max().saturating_sub(leave))
        .expect("index-starvation hold must fit");
    let index_error = publish_dead_letter_payload_for_tests(&spool, &source, row)
        .expect_err("a ceiling that only fits the row must refuse the index reservation");
    assert!(
        index_error.contains("reserve")
            || index_error.contains("ceiling")
            || index_error.contains("index"),
        "unexpected index-reservation diagnostic: {index_error}"
    );
    drop(hold);
    assert_eq!(ceiling.used(), 0);
}

#[test]
fn stale_dead_letter_claim_cannot_delete_completed_handoff() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-stale-dead-letter-claim")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let stale_claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-stale-dead-letter-claim"}"#;

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &stale_claim_path, row)
        .expect("initial dead-letter payload should publish");
    let payload_name = payload_path.file_name().unwrap().to_string_lossy();
    let base = payload_name
        .strip_suffix(".rejected.ndjson")
        .expect("dead-letter payload suffix");
    let meta_path = payload_path.with_file_name(format!("{base}.rejected.meta"));
    fs::write(&meta_path, b"{}").expect("completed metadata should model a recovered peer handoff");
    fs::remove_file(&stale_claim_path).expect("completed handoff removes source claim");

    let error = publish_dead_letter_payload_for_tests(&spool, &stale_claim_path, row)
        .expect_err("stale claim must not reopen dead-letter writer");
    assert!(
        error.contains("no longer exists"),
        "unexpected stale-claim diagnostic: {error}"
    );
    assert!(
        payload_path.exists(),
        "stale peer must not delete completed rejected payload"
    );
    assert!(
        meta_path.exists(),
        "stale peer must not delete completed rejected metadata"
    );
}

#[test]
fn substituted_regular_file_at_claim_cannot_clear_completed_dead_letter_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-claim-identity-swap")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-claim-identity-swap"}"#;
    // Pinned exactly where replay pins it: while the claim path still names the
    // authoritative artifact the bounded preflight validated.
    let pinned = pin_dead_letter_claim_identity_for_tests(&claim_path);

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    let payload_name = payload_path.file_name().unwrap().to_string_lossy();
    let base = payload_name
        .strip_suffix(".rejected.ndjson")
        .expect("dead-letter payload suffix");
    let meta_path = payload_path.with_file_name(format!("{base}.rejected.meta"));
    let completed_payload = b"completed-rejected-payload\n";
    let completed_meta = b"{\"completed\":true}\n";
    fs::write(&payload_path, completed_payload).unwrap();
    fs::write(&meta_path, completed_meta).unwrap();

    // Same-UID substitution: a DIFFERENT regular file now occupies the claim
    // pathname. Shape alone (`metadata.is_file()`) would still read as
    // authoritative, so only exact identity can refuse this.
    fs::remove_file(&claim_path).unwrap();
    fs::write(&claim_path, b"planted-not-the-claimed-artifact\n").unwrap();
    assert!(
        claim_path.is_file(),
        "the substitute must be a regular file for this to be the identity case"
    );

    let error =
        probe_empty_dead_letter_publish_with_identity_for_tests(&spool, &claim_path, &pinned)
            .expect_err("empty publish must still be refused");
    assert!(
        error.contains("refusing to publish an empty"),
        "unexpected empty-publish diagnostic: {error}"
    );
    assert_eq!(
        fs::read(&payload_path).unwrap(),
        completed_payload,
        "a substituted regular file must not delete the completed rejected payload"
    );
    assert_eq!(
        fs::read(&meta_path).unwrap(),
        completed_meta,
        "a substituted regular file must not delete the completed rejected metadata"
    );
}

#[test]
fn exact_live_claim_identity_still_clears_prior_dead_letter_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-claim-identity-exact")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-claim-identity-exact"}"#;
    let pinned = pin_dead_letter_claim_identity_for_tests(&claim_path);

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    let payload_name = payload_path.file_name().unwrap().to_string_lossy();
    let base = payload_name
        .strip_suffix(".rejected.ndjson")
        .expect("dead-letter payload suffix");
    let meta_path = payload_path.with_file_name(format!("{base}.rejected.meta"));
    fs::write(&meta_path, b"{\"prior\":true}\n").unwrap();

    // The claim is untouched, so the pinned identity still matches and the
    // intended partial-handoff replacement must go ahead.
    let error =
        probe_empty_dead_letter_publish_with_identity_for_tests(&spool, &claim_path, &pinned)
            .expect_err("empty publish must still be refused");
    assert!(
        error.contains("refusing to publish an empty"),
        "unexpected empty-publish diagnostic: {error}"
    );
    assert!(
        !payload_path.exists(),
        "the exact live claim must still authorize clearing a prior rejected payload"
    );
    assert!(
        !meta_path.exists(),
        "the exact live claim must still authorize clearing a prior rejected metadata sibling"
    );
    assert!(claim_path.is_file(), "the live claim itself stays intact");
}

#[test]
fn substituted_regular_file_at_claim_cannot_account_out_prior_dead_letter_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-claim-identity-accounting")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-claim-identity-accounting"}"#;
    let pinned = pin_dead_letter_claim_identity_for_tests(&claim_path);

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    let meta_path = write_dead_letter_meta_for_tests(&spool, &claim_path, &payload_path, row, 1)
        .expect("initial dead-letter metadata should publish");

    // Same-UID substitution after a legitimate handoff established both siblings.
    fs::remove_file(&claim_path).unwrap();
    fs::write(&claim_path, b"planted-not-the-claimed-artifact\n").unwrap();

    let prior_payload = b"prior-rejected-payload-marker-bytes\n";
    let (republished, accounted_before_publish) =
        publish_dead_letter_payload_with_identity_for_tests(
            &spool,
            &claim_path,
            &pinned,
            row,
            Some(prior_payload),
        )
        .expect("substituted claim must not block constructive payload publication");
    assert_eq!(republished, payload_path);
    assert_eq!(fs::read(&payload_path).unwrap(), row);
    let after_payload = spool.cached_stats_for_tests();
    assert_eq!(
        after_payload.files,
        accounted_before_publish.files.saturating_add(1),
        "a substituted claim must not authorize account_sub of the prior rejected payload"
    );
    assert_eq!(
        after_payload.bytes,
        accounted_before_publish
            .bytes
            .saturating_add(row.len() as u64),
        "the prior payload's bytes stay charged; only the exact claim may release them"
    );

    let before_meta = spool.cached_stats_for_tests();
    let prior_meta_len = fs::metadata(&meta_path).unwrap().len();
    assert!(
        prior_meta_len > 0,
        "prior metadata must occupy accounted bytes"
    );
    write_dead_letter_meta_with_identity_for_tests(
        &spool,
        &claim_path,
        &pinned,
        &payload_path,
        row,
        2,
    )
    .expect("substituted claim must not block constructive metadata publication");
    let new_meta_len = fs::metadata(&meta_path).unwrap().len();
    let after_meta = spool.cached_stats_for_tests();
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(meta["rejected_rows"], 2);
    assert_eq!(
        after_meta.files,
        before_meta.files.saturating_add(1),
        "a substituted claim must not authorize account_sub of the prior rejected metadata"
    );
    assert_eq!(
        after_meta.bytes,
        before_meta.bytes.saturating_add(new_meta_len),
        "over-counting is deliberate; only the exact claim may release a prior record"
    );
    assert!(
        claim_path.is_file(),
        "refusing destructive cleanup must leave the planted claim file untouched"
    );
}

#[test]
fn directory_at_claim_publishes_evidence_without_clearing_prior_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-dir-claim-siblings")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-dir-claim-siblings"}"#;

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    let payload_name = payload_path.file_name().unwrap().to_string_lossy();
    let base = payload_name
        .strip_suffix(".rejected.ndjson")
        .expect("dead-letter payload suffix");
    let meta_path = payload_path.with_file_name(format!("{base}.rejected.meta"));
    let prior_payload = b"prior-rejected-payload-marker\n";
    let prior_meta = b"{\"prior\":true}\n";
    fs::write(&payload_path, prior_payload).unwrap();
    fs::write(&meta_path, prior_meta).unwrap();

    // Hostile race: claim path becomes a directory (present, wrong type), not
    // a completed-handoff disappearance.
    fs::remove_file(&claim_path).unwrap();
    fs::create_dir(&claim_path).unwrap();

    // Opening must not authorize destructive sibling cleanup.
    let empty_error = probe_empty_dead_letter_publish_for_tests(&spool, &claim_path)
        .expect_err("empty publish must still be refused");
    assert!(
        empty_error.contains("refusing to publish an empty"),
        "unexpected empty-publish diagnostic: {empty_error}"
    );
    assert_eq!(
        fs::read(&payload_path).unwrap(),
        prior_payload,
        "directory at claim must not delete a prior rejected payload"
    );
    assert_eq!(
        fs::read(&meta_path).unwrap(),
        prior_meta,
        "directory at claim must not delete a prior rejected metadata sibling"
    );

    // Constructive publication must still succeed for both artifacts.
    let published = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("directory at claim must not block payload publish");
    assert_eq!(published, payload_path);
    assert_eq!(fs::read(&payload_path).unwrap(), row);
    assert_eq!(
        fs::read(&meta_path).unwrap(),
        prior_meta,
        "payload publish must leave the prior meta sibling until metadata publish"
    );

    write_dead_letter_meta_for_tests(&spool, &claim_path, &payload_path, row, 1)
        .expect("directory at claim must not block metadata publish");
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(meta["rejected_rows"], 1);
    assert!(
        claim_path.is_dir(),
        "constructive handoff must leave the planted directory claim untouched"
    );
}

#[test]
fn dead_letter_open_fails_closed_when_prior_rejected_payload_is_a_directory() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-prior-payload-dir")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-prior-payload-dir"}"#;

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    // Hostile race: prior final is a directory while the claim remains a
    // regular file, so authorized cleanup must fail closed on remove_file.
    fs::remove_file(&payload_path).unwrap();
    fs::create_dir(&payload_path).unwrap();

    let error = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect_err("directory at prior rejected payload must fail open cleanup");
    assert!(
        error.contains("failed to remove prior partial dead-letter payload"),
        "unexpected prior-payload cleanup diagnostic: {error}"
    );
    assert!(
        claim_path.is_file(),
        "failed open cleanup must leave the live claim untouched"
    );
    assert!(
        payload_path.is_dir(),
        "failed open cleanup must leave the planted prior payload directory"
    );
}

#[test]
fn dead_letter_open_fails_closed_when_prior_rejected_meta_is_a_directory() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-prior-meta-dir")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-prior-meta-dir"}"#;

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    let payload_name = payload_path.file_name().unwrap().to_string_lossy();
    let base = payload_name
        .strip_suffix(".rejected.ndjson")
        .expect("dead-letter payload suffix");
    let meta_path = payload_path.with_file_name(format!("{base}.rejected.meta"));
    fs::create_dir(&meta_path).unwrap();

    let error = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect_err("directory at prior rejected meta must fail open cleanup");
    assert!(
        error.contains("failed to remove prior partial dead-letter metadata"),
        "unexpected prior-meta cleanup diagnostic: {error}"
    );
    assert!(
        claim_path.is_file(),
        "failed open cleanup must leave the live claim untouched"
    );
    assert!(
        meta_path.is_dir(),
        "failed open cleanup must leave the planted prior meta directory"
    );
}

#[test]
fn dead_letter_replace_decrements_usage_for_prior_rejected_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-replace-usage")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-replace-usage"}"#;
    let prior_payload = b"prior-rejected-payload-marker-bytes\n";
    let prior_payload_len = prior_payload.len() as u64;
    let before_payload = spool.cached_stats_for_tests();

    // Claim stays a regular file so publish authorizes replace. Open clears any
    // prior sibling, so the helper plants an accounted final between append and
    // publish — the only way to exercise publish's successful account_sub.
    let (payload_path, after_prior_payload) =
        publish_dead_letter_payload_replacing_prior_for_tests(
            &spool,
            &claim_path,
            row,
            prior_payload,
        )
        .expect("live claim must replace an accounted prior payload");
    assert_eq!(fs::read(&payload_path).unwrap(), row);
    assert_eq!(
        after_prior_payload.files,
        before_payload.files.saturating_add(1),
        "planted prior must enter the maintained file gauge before publish"
    );
    assert_eq!(
        after_prior_payload.bytes,
        before_payload.bytes.saturating_add(prior_payload_len),
        "planted prior must enter the maintained byte gauge before publish"
    );
    let after_payload = spool.cached_stats_for_tests();
    assert_eq!(
        after_payload.files, after_prior_payload.files,
        "payload replace must account_sub the prior file rather than stacking"
    );
    assert_eq!(
        after_payload.bytes,
        after_prior_payload
            .bytes
            .saturating_sub(prior_payload_len)
            .saturating_add(row.len() as u64),
        "payload replace must decrement exactly the prior length before adding the new payload"
    );

    let meta_path = write_dead_letter_meta_for_tests(&spool, &claim_path, &payload_path, row, 1)
        .expect("initial dead-letter metadata should publish");
    let before_meta = spool.cached_stats_for_tests();
    let prior_meta_len = fs::metadata(&meta_path).unwrap().len();
    assert!(
        prior_meta_len > 0,
        "prior metadata must occupy accounted bytes"
    );

    write_dead_letter_meta_for_tests(&spool, &claim_path, &payload_path, row, 2)
        .expect("live claim must replace prior dead-letter metadata");
    let new_meta_len = fs::metadata(&meta_path).unwrap().len();
    let after_meta = spool.cached_stats_for_tests();
    let meta: Value = serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(meta["rejected_rows"], 2);
    assert_eq!(
        after_meta.files, before_meta.files,
        "metadata replace must account_sub the prior file rather than stacking"
    );
    assert_eq!(
        after_meta.bytes,
        before_meta
            .bytes
            .saturating_sub(prior_meta_len)
            .saturating_add(new_meta_len),
        "metadata replace must decrement exactly the prior metadata length"
    );
    assert!(
        claim_path.is_file(),
        "replacement must leave the live claim untouched"
    );
}

#[test]
fn dead_letter_meta_publish_fails_closed_when_prior_meta_is_a_directory() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let source = spool
        .write_events(&[sample_event("evt-meta-replace-dir")])
        .unwrap();
    let claim = spool
        .hold_replay_claim_for_tests(&source)
        .unwrap()
        .expect("claim should be acquired");
    let claim_path = claim.claim_path_for_tests().to_path_buf();
    let row = br#"{"event_id":"evt-meta-replace-dir"}"#;

    let payload_path = publish_dead_letter_payload_for_tests(&spool, &claim_path, row)
        .expect("initial dead-letter payload should publish");
    let payload_name = payload_path.file_name().unwrap().to_string_lossy();
    let base = payload_name
        .strip_suffix(".rejected.ndjson")
        .expect("dead-letter payload suffix");
    let meta_path = payload_path.with_file_name(format!("{base}.rejected.meta"));
    // Claim remains a regular file so metadata publish authorizes prior-meta
    // replacement; a planted directory makes that remove_file fail closed.
    fs::create_dir(&meta_path).unwrap();

    let error = write_dead_letter_meta_for_tests(&spool, &claim_path, &payload_path, row, 1)
        .expect_err("directory at prior meta must fail metadata replace");
    assert!(
        error.contains("failed to replace dead-letter metadata"),
        "unexpected meta-replace diagnostic: {error}"
    );
    assert!(
        claim_path.is_file(),
        "failed meta replace must leave the live claim untouched"
    );
    assert!(
        meta_path.is_dir(),
        "failed meta replace must leave the planted prior meta directory"
    );
}

#[test]
fn decode_spool_helper_and_path_swap_probe_fail_closed_on_missing_inputs() {
    let missing = std::env::temp_dir().join(format!(
        "ferrum-chargeback-missing-{}.ndjson",
        std::process::id()
    ));
    let _ = fs::remove_file(&missing);
    let decode_error = decode_spool_file_for_tests(&missing)
        .expect_err("a missing spool path must fail closed before allocation");
    assert!(
        decode_error.contains("failed to open") || decode_error.contains("No such file"),
        "unexpected missing-decode diagnostic: {decode_error}"
    );

    #[cfg(unix)]
    {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.ndjson");
        let replacement = temp.path().join("missing-replacement.ndjson");
        fs::write(&source, b"{\"event_id\":\"validated-row\"}\n").unwrap();
        let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
        let error = probe_streaming_replay_path_swap_for_tests(&source, &replacement, ceiling)
            .expect_err("a missing replacement path must fail the identity probe setup");
        assert!(
            error.contains("failed to replace preflight path"),
            "unexpected path-swap setup diagnostic: {error}"
        );
        assert_eq!(ceiling.used(), 0);
    }
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn streaming_replay_refuses_a_post_preflight_path_swap_and_continues() {
    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFG"));
    fs::write(&source, br#"{"event_id":"validated-before-swap"}"#).unwrap();
    let replacement = temp.path().join("replacement-after-preflight.ndjson");
    fs::write(&replacement, br#"{"event_id":"smuggled-after-preflight"}"#).unwrap();
    let newer = spool
        .write_events(&[sample_event("evt-after-post-preflight-swap")])
        .unwrap();

    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    let replacement_for_hook = replacement.clone();
    let swapped_claim: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));
    let claim_slot = Arc::clone(&swapped_claim);
    set_spool_replay_hook_for_tests(Some(Arc::new(move |point, claimed| {
        if point != SpoolReplayHookPoint::AfterStreamingPreflight {
            return;
        }
        if !claimed.starts_with(&namespace_root) {
            return;
        }
        if fs::rename(&replacement_for_hook, claimed).is_ok() {
            *claim_slot.lock().expect("swapped claim slot") = Some(claimed.to_path_buf());
        }
    })));
    struct ClearReplayHook;
    impl Drop for ClearReplayHook {
        fn drop(&mut self) {
            set_spool_replay_hook_for_tests(None);
        }
    }
    let _clear = ClearReplayHook;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("a post-preflight identity change must refuse and continue the tick");

    // Quarantine is a rename, so it is bound too: the claim pathname now names a
    // substitute, not the pinned inode, and must therefore be left completely
    // untouched instead of relabelled under this owner's operator-visible name.
    let swapped = swapped_claim
        .lock()
        .expect("swapped claim slot")
        .clone()
        .expect("the swap replaces exactly one claim pathname");
    assert!(
        !fs::read_dir(&day)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".corrupt")),
        "a substituted claim pathname must never be quarantined"
    );
    assert_eq!(
        fs::read(&swapped).unwrap(),
        br#"{"event_id":"smuggled-after-preflight"}"#,
        "the substitute must be left byte- and pathname-identical"
    );
    assert!(
        !source.exists(),
        "the substitute must never be released back to the replayable name"
    );
    assert!(
        !newer.exists(),
        "later valid artifacts must still replay after a post-preflight identity refusal"
    );
    let bodies: Vec<String> = wait_for_requests(&server, 1)
        .await
        .into_iter()
        .map(|request| String::from_utf8(request.body).unwrap())
        .collect();
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("evt-after-post-preflight-swap")),
        "only the post-swap sibling may be delivered: {bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .all(|body| !body.contains("smuggled-after-preflight")),
        "a replaced artifact must never be delivered: {bodies:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn streaming_replay_defers_when_ceiling_starves_between_preflight_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let spool = ceiling_spool(&temp, ceiling);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFH"));
    fs::write(&source, br#"{"event_id":"ceiling-between-passes"}"#).unwrap();

    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    type TestReservation = ferrum_edge::plugins::utils::byte_budget::ProcessByteReservation;
    let peer_hold: Arc<Mutex<Option<TestReservation>>> = Arc::new(Mutex::new(None));
    let peer_slot = Arc::clone(&peer_hold);
    set_spool_replay_hook_for_tests(Some(Arc::new(move |point, claimed| {
        if point != SpoolReplayHookPoint::AfterStreamingPreflight {
            return;
        }
        if !claimed.starts_with(&namespace_root) {
            return;
        }
        let reservation = ceiling
            .try_acquire(ceiling.max())
            .expect("post-preflight peer must be able to saturate the ceiling");
        *peer_slot.lock().expect("peer hold mutex") = Some(reservation);
    })));
    struct ClearReplayHook;
    impl Drop for ClearReplayHook {
        fn drop(&mut self) {
            set_spool_replay_hook_for_tests(None);
        }
    }
    let _clear = ClearReplayHook;

    let error = replay_spool_once_with_ceiling_for_tests(&spool, "http://127.0.0.1:1/", 4, ceiling)
        .await
        .expect_err("ceiling starvation between passes must defer without quarantine");
    assert!(
        error.contains("ceiling") || error.contains("deferred"),
        "unexpected between-pass deferral diagnostic: {error}"
    );
    assert!(
        source.exists(),
        "between-pass ceiling deferral must leave the durable record claimable"
    );
    drop(_clear);
    drop(peer_hold.lock().expect("peer hold mutex").take());
    assert_eq!(ceiling.used(), 0);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    replay_spool_once_with_ceiling_for_tests(&spool, &server.uri(), 4, ceiling)
        .await
        .expect("replay must recover after the between-pass reservation releases");
    assert!(!source.exists());
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn streaming_replay_continues_when_an_authorized_quarantine_is_blocked() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let spool = test_spool(&temp);
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let source = day.join(owned_data_name("01ARZ3NDEKTSV4RRFFQ69G5FFI"));
    fs::write(
        &source,
        br#"{"event_id":"validated-before-blocked-quarantine"}"#,
    )
    .unwrap();
    // Quarantine renames to the durable base name + ".corrupt", never the
    // in-flight claim name. Plant the blocker on that durable path so the
    // authorized quarantine cannot complete.
    let quarantine = source.with_file_name(format!(
        "{}.corrupt",
        source.file_name().unwrap().to_string_lossy()
    ));
    fs::create_dir(&quarantine).unwrap();
    fs::write(quarantine.join("blocker"), b"x").unwrap();

    // The pinned inode is NOT replaced: only its mode changes, so the second
    // open fails while the claim pathname still resolves to the exact artifact
    // this replay opened. Quarantine is therefore authorized — and still fails,
    // because the durable quarantine name is occupied by a directory.
    let namespace_root = spool.namespace_root_for_tests().to_path_buf();
    let claim_slot: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));
    let claim_for_hook = Arc::clone(&claim_slot);
    set_spool_replay_hook_for_tests(Some(Arc::new(move |point, claimed| {
        if point != SpoolReplayHookPoint::AfterStreamingPreflight {
            return;
        }
        if !claimed.starts_with(&namespace_root) {
            return;
        }
        let mut slot = claim_for_hook.lock().expect("blocked claim slot");
        if slot.is_some() {
            return;
        }
        let mut denied = fs::metadata(claimed).unwrap().permissions();
        denied.set_mode(0o000);
        fs::set_permissions(claimed, denied).unwrap();
        *slot = Some(claimed.to_path_buf());
    })));
    struct ClearReplayHook;
    impl Drop for ClearReplayHook {
        fn drop(&mut self) {
            set_spool_replay_hook_for_tests(None);
        }
    }
    let _clear = ClearReplayHook;

    // The second open fails before any HTTP attempt, so no backend is needed.
    replay_spool_once_for_tests(&spool, "http://127.0.0.1:1/")
        .await
        .expect("a blocked quarantine reports and continues the tick");

    let blocked = claim_slot
        .lock()
        .expect("blocked claim slot")
        .clone()
        .expect("the hook blocks exactly one claim pathname");
    assert!(
        blocked.exists(),
        "a quarantine that could not complete must leave the claim exactly where it was"
    );
    assert_eq!(
        fs::read(quarantine.join("blocker")).unwrap(),
        b"x",
        "the blocking directory must never be replaced by the refused artifact"
    );
    assert!(
        !source.exists(),
        "a blocked quarantine must not release the claim back to the replayable name"
    );
    let mut restore = fs::metadata(&blocked).unwrap().permissions();
    restore.set_mode(0o600);
    fs::set_permissions(&blocked, restore).unwrap();
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

#[tokio::test]
async fn spool_replay_of_a_written_artifact_fits_under_the_proven_liveness_bound() {
    let server = MockServer::start().await;
    mount_status_sequence(&server, &[200]).await;

    let events = spool_replay_events(256);
    let write_ceiling = leaked_chargeback_test_ceiling(64 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = ceiling_spool(&temp, write_ceiling);
    let path = spool.write_events(&events).expect("artifact is admitted");

    // Replay against fixed streaming headroom rather than an artifact-sized
    // decoded-buffer formula.
    let ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
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
    assert!(ceiling.high_water() <= 6 * 1024 * 1024);
}

#[tokio::test]
async fn spool_replay_dead_letter_accounting_is_aggregated_not_per_row() {
    let server = MockServer::start().await;
    // Every node in the 64-row isolation tree rejects permanently: one
    // aggregate outcome is retained after 127 bounded attempts, not one
    // metadata allocation per row.
    let statuses = vec![400; 127];
    mount_status_sequence(&server, &statuses).await;

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

/// Shared-owner `SpoolJob::Events` recovery (#3029): when the delivery worker
/// cannot take unique ownership of the failed-batch Arc, it must reserve the
/// duplicate ChargeEvent payload against the process ceiling before cloning,
/// hold that reservation through the blocking write, and release it afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn shared_spool_batch_clone_reserves_duplicate_bytes_until_write_completes() {
    let spool_ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let clone_ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let spool = Arc::new(ceiling_spool(&temp, spool_ceiling));
    let events = vec![sample_event("shared-clone-admit")];

    let probe =
        probe_shared_spool_batch_clone_for_tests(Arc::clone(&spool), events, clone_ceiling).await;

    assert!(probe.clone_bytes > 0);
    let held = probe
        .ceiling_used_while_clone_held
        .expect("BeforeWrite must observe the clone reservation");
    assert!(
        held >= probe
            .ceiling_used_baseline
            .saturating_add(probe.clone_bytes),
        "clone reservation must charge the injected ceiling before the duplicate \
         payload is written; baseline={} held={} clone_bytes={}",
        probe.ceiling_used_baseline,
        held,
        probe.clone_bytes
    );
    assert_eq!(
        probe.ceiling_used_after, probe.ceiling_used_baseline,
        "clone reservation must release exactly once after the blocking write"
    );
    assert_eq!(
        probe.jobs_written, 1,
        "admitted shared clone must write once"
    );
    assert_eq!(
        probe.jobs_lost, 0,
        "admitted shared clone must not count as loss"
    );
    assert_eq!(
        probe.durable_owned_files, 1,
        "admitted shared clone must leave one durable spool artifact"
    );
    assert_eq!(
        spool_ceiling.used(),
        0,
        "spool artifact reservations release after the write completes"
    );
    assert_eq!(
        clone_ceiling.used(),
        0,
        "the isolated clone ceiling must return to zero"
    );
}

/// Shared-owner recovery must fail closed when its clone ceiling cannot admit
/// the duplicate payload: no durable write, one spool-job loss, no lasting charge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn shared_spool_batch_clone_refuses_with_an_isolated_saturated_ceiling() {
    let spool_ceiling = leaked_chargeback_test_ceiling(8 * 1024 * 1024);
    let clone_ceiling = leaked_chargeback_test_ceiling(1);
    let temp = tempfile::tempdir().unwrap();
    let spool = Arc::new(ceiling_spool(&temp, spool_ceiling));
    let events = vec![sample_event("shared-clone-refuse")];

    let probe =
        probe_shared_spool_batch_clone_for_tests(Arc::clone(&spool), events, clone_ceiling).await;

    assert!(probe.clone_bytes > 0);
    assert!(
        probe.ceiling_used_while_clone_held.is_none(),
        "refused clone must never reach the spool write hook"
    );
    assert_eq!(
        probe.jobs_written, 0,
        "ceiling refusal must not produce a durable write"
    );
    assert_eq!(
        probe.jobs_lost, 1,
        "ceiling refusal must record exactly one spool job loss"
    );
    assert_eq!(
        probe.durable_owned_files, 0,
        "ceiling refusal must leave no owned spool artifacts"
    );
    assert_eq!(
        probe.ceiling_used_after, probe.ceiling_used_baseline,
        "a refused clone must not leave a lasting injected-ceiling charge"
    );
    assert_eq!(clone_ceiling.used(), 0);
    assert_eq!(spool_ceiling.used(), 0);
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
            SpoolWriteHookPoint::BeforeNamespaceLock
            | SpoolWriteHookPoint::QuotaAdmissionReady
            | SpoolWriteHookPoint::QuotaInventoryTaken => {}
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
    // Ordinary one-shot artifacts carry a declared size, but replay still
    // applies the ratio limit because the frame header is unauthenticated.
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
fn a_declared_zstd_size_cannot_bypass_the_decompression_ratio_limit() {
    // Frame content sizes are unauthenticated. Even a truthful declaration
    // must not let a planted high-ratio archive bypass the ratio limit.
    let temp = tempfile::tempdir().unwrap();
    let plain = vec![b'\n'; 2 * 1024 * 1024];
    let encoded = encode_spool_bytes_without_ratio_padding_for_tests(&plain).unwrap();
    let ratio_bound = spool_decompression_limit_for_tests(encoded.len() as u64);
    assert!(
        ratio_bound < plain.len() as u64,
        "fixture must exceed the fallback ratio bound: ratio={ratio_bound} actual={}",
        plain.len()
    );

    let path = temp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FC3.ndjson.zst");
    fs::write(&path, encoded).unwrap();
    let err = decode_spool_file_for_tests(&path)
        .expect_err("a declared size must not bypass the decompression-ratio limit");
    assert!(
        err.contains("decompression bound"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_legitimate_high_ratio_batch_is_padded_and_remains_replayable() {
    let ceiling = leaked_chargeback_test_ceiling(16 * 1024 * 1024);
    let temp = tempfile::tempdir().unwrap();
    let mut settings = spool_settings(temp.path(), 4 * 1024 * 1024);
    settings.compression = SpoolCompression::Zstd;
    let spool = SpoolManager::for_tests_with_ceiling(settings, "node-a", ceiling).unwrap();
    let mut event = sample_event("evt-high-ratio");
    event.request_id = Some("\0".repeat(100 * 1024));
    let decoded_len = serialize_json_each_row(std::slice::from_ref(&event))
        .unwrap()
        .len() as u64;

    let path = spool
        .write_events(&[event])
        .expect("a legitimate high-ratio batch must remain durable");
    assert!(
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".ndjson.zst")),
        "a high-ratio batch must remain a zstd artifact: {}",
        path.display()
    );
    let encoded_len = fs::metadata(&path).unwrap().len();
    assert!(
        spool_decompression_limit_for_tests(encoded_len) >= decoded_len,
        "writer padding must make its own artifact satisfy the replay ratio"
    );
    let decoded = decode_spool_file_for_tests(&path).expect("the padded artifact must replay");
    assert!(
        decoded.contains("evt-high-ratio"),
        "the padded artifact must preserve the billing event"
    );
}

// ---------------------------------------------------------------------------
// Charge-event schema projection (issue #3313)
// ---------------------------------------------------------------------------

fn sink_config_with(extra: Value) -> Value {
    // Spool disabled so admission does not depend on creating the default
    // on-disk spool directory in the unit-test environment.
    let mut config = json!({
        "mode": "per_event",
        "clickhouse": { "url": "https://clickhouse.example:8443" },
        "spool": { "enabled": false },
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.01 }],
        "pricing_version": "test-v1",
        "currency": "USD"
    });
    if let Some(object) = extra.as_object() {
        for (key, value) in object {
            config[key.as_str()] = value.clone();
        }
    }
    config
}

fn projected_row(schema: Value, event: &ChargeEvent) -> Value {
    let projection =
        compile_charge_event_projection(&sink_config_with(json!({ "schema": schema })))
            .expect("schema compiles")
            .expect("schema present");
    let rendered =
        serialize_json_each_row_projected(std::slice::from_ref(event), Some(&projection))
            .expect("row serializes");
    serde_json::from_str(&rendered).expect("row is valid JSON")
}

#[test]
fn charge_event_default_wire_shape_is_unprojected() {
    // No schema configured — the native JSONEachRow representation is
    // byte-for-byte what it has always been.
    let event = sample_event("evt-native");
    let native = serialize_json_each_row(std::slice::from_ref(&event)).expect("native row");
    assert_eq!(
        native,
        serde_json::to_string(&event).expect("serde round trip")
    );
    let value: Value = serde_json::from_str(&native).unwrap();
    assert_eq!(value["proxy_id"], json!("proxy-a"));
    assert_eq!(value["received_at"], json!(event.received_at));
    // Absent optionals stay absent.
    assert!(value.get("trace_id").is_none());
    assert!(value.get("snapshot_id").is_none());
}

#[test]
fn charge_event_projection_renames_omits_and_adds_fields() {
    let event = sample_event("evt-projected");
    let value = projected_row(
        json!({
            "rename": { "proxy_id": "route_key", "charge_total": "amount" },
            "omit": ["node_id", "pricing_version"],
            "static_fields": { "ledger": "prod", "shard": 3 },
            "derived_fields": [
                { "name": "status_group", "kind": "status_class" },
                { "name": "record_kind", "kind": "summary_kind" },
                { "name": "call_outcome", "kind": "outcome" }
            ]
        }),
        &event,
    );
    assert_eq!(value["route_key"], json!("proxy-a"));
    assert!(value.get("proxy_id").is_none());
    assert_eq!(value["amount"], json!(event.charge_total));
    assert!(value.get("node_id").is_none());
    assert!(value.get("pricing_version").is_none());
    assert_eq!(value["ledger"], json!("prod"));
    assert_eq!(value["shard"], json!(3));
    assert_eq!(value["status_group"], json!("2xx"));
    assert_eq!(value["record_kind"], json!("charge_event"));
    assert_eq!(value["call_outcome"], json!("ok"));
    // Billing identity fields keep their values — only key naming moved.
    assert_eq!(value["consumer_id"], json!("alice"));
    assert_eq!(value["charge_call"], json!(event.charge_call));
}

#[test]
fn charge_event_projection_preserves_optional_member_presence_and_orders_output() {
    let mut event = sample_event("evt-optional");
    event.trace_id = Some("trace-9".to_string());
    let projection = compile_charge_event_projection(&sink_config_with(json!({
        "schema": { "order": ["event_id", "charge_total", "*"] }
    })))
    .expect("schema compiles")
    .expect("schema present");
    let rendered =
        serialize_json_each_row_projected(std::slice::from_ref(&event), Some(&projection))
            .expect("row serializes");
    let event_at = rendered.find("\"event_id\"").expect("event_id present");
    let charge_at = rendered
        .find("\"charge_total\"")
        .expect("charge_total present");
    let node_at = rendered.find("\"node_id\"").expect("node_id present");
    assert!(event_at < charge_at && charge_at < node_at, "{rendered}");
    let value: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["trace_id"], json!("trace-9"));
    // `snapshot_id` is still None and stays out of the row.
    assert!(value.get("snapshot_id").is_none());
}

#[test]
fn charge_event_projection_outcome_marks_grpc_and_server_errors() {
    let mut event = sample_event("evt-grpc");
    event.grpc_status = Some(13);
    let schema = json!({ "derived_fields": [{ "name": "call_outcome", "kind": "outcome" }] });
    assert_eq!(
        projected_row(schema.clone(), &event)["call_outcome"],
        json!("error")
    );
    let mut event = sample_event("evt-5xx");
    event.status_code = 503;
    event.grpc_status = None;
    assert_eq!(
        projected_row(schema, &event)["call_outcome"],
        json!("error")
    );
}

#[test]
fn charge_event_projection_reservation_bound_still_covers_the_body() {
    // The retained-byte reservation is taken before serialization, so it must
    // account for the renamed keys and injected members up front.
    let ceiling: &'static RetainedByteCeiling =
        Box::leak(Box::new(RetainedByteCeiling::new(16 * 1024 * 1024)));
    let events: Vec<ChargeEvent> = (0..8).map(|i| sample_event(&format!("evt-{i}"))).collect();
    let projection = Arc::new(
        compile_charge_event_projection(&sink_config_with(json!({
            "schema": {
                "rename": { "proxy_id": "a_much_longer_destination_column_name" },
                "static_fields": { "ledger": "production-billing-ledger" },
                "derived_fields": [{ "name": "status_group", "kind": "status_class" }]
            }
        })))
        .expect("schema compiles")
        .expect("schema present"),
    );
    let (bound, held, after) = probe_charge_body_materialization_with_projection_for_tests(
        ceiling,
        &events,
        Some(Arc::clone(&projection)),
    )
    .expect("projected body materializes under the ceiling");
    let rendered = serialize_json_each_row_projected(&events, Some(projection.as_ref())).unwrap();
    assert!(
        bound >= rendered.len(),
        "reservation {bound} must cover the projected body {}",
        rendered.len()
    );
    assert!(held >= rendered.len(), "body stays charged while held");
    assert_eq!(after, 0, "reservation released on drop");
    assert!(projection.row_overhead_bytes() > 0);
}

#[test]
fn charge_event_schema_rejects_unrepresentable_shapes() {
    for (schema, needle) in [
        (
            json!({ "summary_type": "http" }),
            "'summary_type' is not supported",
        ),
        (
            json!({ "timestamp_format": "epoch_ms" }),
            "'timestamp_format' is not supported",
        ),
        (
            json!({ "metadata": { "mode": "flatten" } }),
            "'metadata' policy is not supported",
        ),
        (
            json!({ "derived_fields": [{ "name": "host", "kind": "backend_host" }] }),
            "not representable from a chargeback charge event",
        ),
        (
            json!({ "omit": ["latency_total_ms"] }),
            "schema omit references unknown field 'latency_total_ms'",
        ),
        (
            json!({ "rename": { "consumer_id": "api_secret" } }),
            "matches a sensitive-data substring",
        ),
        (
            json!({ "rename": { "proxy_id": "namespace" } }),
            "duplicate output key 'namespace'",
        ),
    ] {
        let err = compile_charge_event_projection(&sink_config_with(json!({ "schema": schema })))
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {schema}"));
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

#[test]
fn charge_event_schema_and_schema_ref_are_mutually_exclusive() {
    let err = compile_charge_event_projection(&sink_config_with(json!({
        "schema": {},
        "schema_ref": "shared"
    })))
    .err()
    .unwrap();
    assert!(err.contains("mutually exclusive"), "got: {err}");
}

#[test]
fn charge_event_dangling_schema_ref_fails_closed() {
    let err = compile_charge_event_projection(&sink_config_with(json!({
        "schema_ref": "definitely-not-defined"
    })))
    .err()
    .unwrap();
    assert!(
        err.contains("references unknown schema 'definitely-not-defined'"),
        "got: {err}"
    );
}

#[test]
fn sink_constructor_accepts_and_rejects_schemas_at_construction() {
    ApiChargebackSink::new(
        &sink_config_with(json!({ "schema": { "rename": { "proxy_id": "route_key" } } })),
        PluginHttpClient::default(),
        "ferrum",
    )
    .expect("valid schema is admitted at construction");
    let err = ApiChargebackSink::new(
        &sink_config_with(json!({ "schema": { "summary_type": "http" } })),
        PluginHttpClient::default(),
        "ferrum",
    )
    .err()
    .expect("unrepresentable schema is rejected at construction");
    assert!(
        err.contains("'summary_type' is not supported"),
        "got: {err}"
    );
}

#[test]
fn spool_usage_counters_track_write_evict_and_reconcile_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("usage-lifecycle-1");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    assert_eq!(
        encoded_len,
        encoded_event_len(&sample_event("usage-lifecycle-2"), SpoolCompression::None),
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
    assert!(
        spool.inventory_walks_for_tests() >= 1,
        "startup prepare must seed gauges from one bounded inventory"
    );
    let walks_before_cached_read = spool.inventory_walks_for_tests();
    let _ = spool.cached_stats_for_tests();
    assert_eq!(
        spool.inventory_walks_for_tests(),
        walks_before_cached_read,
        "cached gauge reads must not inventory the spool"
    );

    spool
        .write_events(std::slice::from_ref(&event))
        .expect("first write");
    let after_write = spool.cached_stats_for_tests();
    assert_eq!(after_write.files, 1);
    assert_eq!(after_write.bytes, encoded_len);

    spool
        .write_events(&[sample_event("usage-lifecycle-2")])
        .expect("evicting second write");
    let after_evict = spool.cached_stats_for_tests();
    assert_eq!(after_evict.files, 1);
    assert_eq!(after_evict.bytes, encoded_len);
    assert_eq!(
        after_evict.bytes,
        disk_owned_bytes(&default_test_namespace_root(temp.path())),
        "maintained bytes must match on-disk owned usage after eviction"
    );

    // Plant an owned corrupt artifact outside the writer path; gauges stay at
    // last-good until a bounded reconcile publishes absolute truth.
    let day = spool.namespace_root_for_tests().join("20260524");
    fs::create_dir_all(&day).unwrap();
    let planted_len = 128u64;
    fs::write(
        day.join("00000000000000000000000000.ndjson.corrupt"),
        vec![0u8; planted_len as usize],
    )
    .unwrap();
    assert_eq!(
        spool.cached_stats_for_tests().files,
        1,
        "status gauges must not synchronously discover planted files"
    );
    let reconciled = spool.reconcile_cached_usage_for_tests().expect("reconcile");
    assert_eq!(reconciled.files, 2);
    assert_eq!(
        reconciled.bytes,
        encoded_len.saturating_add(planted_len),
        "reconcile must publish planted owned bytes"
    );
    assert_eq!(spool.cached_stats_for_tests(), reconciled);

    let again = spool
        .reconcile_cached_usage_for_tests()
        .expect("second reconcile");
    assert_eq!(again, reconciled);
}

#[tokio::test]
async fn spool_usage_counters_track_successful_replay_deletion() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("usage-replay-delete-1");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 1024 * 1024,
        replay_interval_secs: 60,
        delivery_queue_capacity: 4096,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    spool
        .write_events(std::slice::from_ref(&event))
        .expect("write spool event");
    let after_write = spool.cached_stats_for_tests();
    assert_eq!(after_write.files, 1);
    assert_eq!(after_write.bytes, encoded_len);

    replay_spool_once_for_tests(&spool, &server.uri())
        .await
        .expect("successful replay");

    let after_replay = spool.cached_stats_for_tests();
    assert_eq!(
        after_replay.files, 0,
        "successful delivery must subtract the removed claim from maintained gauges"
    );
    assert_eq!(after_replay.bytes, 0);
    let reconciled = spool
        .reconcile_cached_usage_for_tests()
        .expect("reconcile after replay");
    assert_eq!(
        reconciled, after_replay,
        "reconcile must confirm replay deletion left an empty owned spool"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn large_spool_status_and_prometheus_use_cached_gauges_without_inventory() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let mut config = valid_config(temp.path());
    config["clickhouse"]["url"] = json!(server.uri());
    // Keep the background replayer from racing reconciles during the scrape
    // window under test; the explicit test seam owns refresh.
    config["spool"]["replay_interval_secs"] = json!(3600);

    let plugin = ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
    plugin.start_background_tasks().expect("chargeback start");
    plugin.commit_background_tasks();

    let mut namespace_root = None;
    for _ in 0..200 {
        namespace_root = find_spool_namespace_root(temp.path());
        if namespace_root.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let namespace_root = namespace_root.expect("committed spool namespace");
    // Let the startup prepare/reconcile tick finish so later walk-count
    // assertions are not racing the first replay interval fire.
    for _ in 0..50 {
        let before = active_spool_inventory_walks_for_tests();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let after = active_spool_inventory_walks_for_tests();
        // The first committed tick performs one prepare inventory and then one
        // absolute reconcile inventory. Waiting for both avoids mistaking the
        // short gap between them for quiescence and makes the later zero-growth
        // assertion independent of scheduler timing.
        if after == before && before >= 2 {
            break;
        }
    }
    assert!(
        active_spool_inventory_walks_for_tests() >= 2,
        "startup prepare and reconcile inventories must complete before the scrape proof"
    );

    let day = namespace_root.join("20260524");
    fs::create_dir_all(&day).unwrap();

    // Large owned spool: enough files that a synchronous scrape walk would be
    // expensive, without relying on wall-clock flake thresholds.
    const PLANTED: u64 = 2_500;
    const FILE_BYTES: u64 = 64;
    for idx in 0..PLANTED {
        let name = format!("{idx:026}.ndjson.corrupt");
        fs::write(day.join(name), vec![0u8; FILE_BYTES as usize]).unwrap();
    }
    reconcile_active_spool_usage_for_tests();

    let expected_bytes = PLANTED.saturating_mul(FILE_BYTES);
    let status_before = serde_json::from_str::<Value>(&render_status_json()).expect("status");
    assert_eq!(
        status_before["totals"]["spool"]["files"].as_u64(),
        Some(PLANTED)
    );
    assert_eq!(
        status_before["totals"]["spool"]["bytes"].as_u64(),
        Some(expected_bytes)
    );

    let walks_baseline = active_spool_inventory_walks_for_tests();
    // Structural proxy-progress proof: scrapes over a large spool must not
    // inventory/stat the tree. Zero walk growth means the prior blocking FS
    // work is absent from the admin/metrics path (no flaky wall-clock bound).
    let status = render_status_json();
    let prom = render_prometheus();
    let status2 = render_status_json();
    let prom2 = render_prometheus();
    assert_eq!(
        active_spool_inventory_walks_for_tests(),
        walks_baseline,
        "status/Prometheus rendering must not inventory the spool; this deterministic walk count proves scrapes do not block proxy progress with large-spool filesystem walks"
    );
    assert!(
        status.contains(&format!("\"files\":{PLANTED}")),
        "status must report planted files from cached gauges; got {status}"
    );
    assert!(
        prom.contains(&format!("chargeback_sink_spool_files {PLANTED}\n")),
        "prometheus must report planted files from cached gauges; got {prom}"
    );
    assert_eq!(status, status2);
    assert_eq!(prom, prom2);

    // Plant one more file without reconciling: scrapes must keep last-good
    // values, proving they are not walking the tree for freshness.
    fs::write(
        day.join(format!("{:026}.ndjson.corrupt", PLANTED)),
        vec![0u8; FILE_BYTES as usize],
    )
    .unwrap();
    let stale = serde_json::from_str::<Value>(&render_status_json()).expect("stale status");
    assert_eq!(
        stale["totals"]["spool"]["files"].as_u64(),
        Some(PLANTED),
        "without reconcile, scrapes must retain last-good file count"
    );
    assert_eq!(
        active_spool_inventory_walks_for_tests(),
        walks_baseline,
        "observing stale last-good must not walk"
    );
    drop(plugin);
}
