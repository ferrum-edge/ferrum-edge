use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use ferrum_edge::plugins::api_chargeback_sink::{
    ApiChargebackSink, ApiChargebackSinkConfig, ChargeEvent, SnapshotAccumulator, SpoolCompression,
    SpoolManager, SpoolSettings, SpoolWriteHookPoint,
    classify_clickhouse_acknowledgement_for_tests, classify_clickhouse_http_status_for_tests,
    clickhouse_insert_url_for_tests, decode_spool_file_for_tests, encode_spool_bytes_for_tests,
    new_ulid, render_prometheus, render_status_json, replay_spool_once_for_tests,
    replay_spool_once_with_batch_size_for_tests, serialize_json_each_row,
    set_spool_write_hook_for_tests, write_private_file_atomically_for_tests,
};
use ferrum_edge::plugins::chargeback::pricing::{ChargeComputation, MAX_UNIT_PRICE, PricingConfig};
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

fn disk_owned_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let owned = name.ends_with(".ndjson.tmp")
                || name.ends_with(".ndjson.zst.tmp")
                || name.ends_with(".ndjson.rejected.meta.tmp")
                || name.ends_with(".ndjson.zst.rejected.meta.tmp")
                || name.ends_with(".ndjson.corrupt")
                || name.ends_with(".ndjson.zst.corrupt")
                || name.ends_with(".ndjson.rejected.meta")
                || name.ends_with(".ndjson.zst.rejected.meta")
                || ((name.ends_with(".ndjson.zst") || name.ends_with(".ndjson"))
                    && !name.ends_with(".tmp")
                    && !name.ends_with(".corrupt")
                    && !name.ends_with(".rejected")
                    && !name.ends_with(".meta"));
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
        disk_owned_bytes(&temp.path().join("node-a")),
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
    assert_eq!(disk_owned_bytes(&temp.path().join("node-a")), 0);
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
    assert_eq!(stats.bytes, disk_owned_bytes(&temp.path().join("node-a")));

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
    assert_eq!(stats.bytes, disk_owned_bytes(&temp.path().join("node-a")));

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
    let corrupt_dir = temp.path().join("node-a").join("20260524");
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
    assert_eq!(before.bytes, disk_owned_bytes(&temp.path().join("node-a")));

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
    let day = temp.path().join("node-a").join("20260524");
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
    assert_eq!(disk_owned_bytes(&temp.path().join("node-a")), 0);
}

#[test]
fn spool_counts_tmp_files_toward_quota_before_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let event = sample_event("evt-tmp-budget");
    let encoded_len = encoded_event_len(&event, SpoolCompression::None);
    let day = temp.path().join("node-a").join("20260524");
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
    assert_eq!(stats.bytes, disk_owned_bytes(&temp.path().join("node-a")));

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
        disk_owned_bytes(&temp.path().join("node-a")),
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
        let mut node_dirs = Vec::new();
        for _ in 0..200 {
            node_dirs = fs::read_dir(temp.path())
                .unwrap()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            if node_dirs.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            node_dirs.len(),
            1,
            "committed spool should create exactly one node directory"
        );
        let day = node_dirs[0].join("20260524");
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
    let day = temp.path().join("node-a").join("20260524");
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

    let err = write_private_file_atomically_for_tests(&tmp_path, &final_path, b"{\"ok\":true}\n")
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
    let corrupt_dir = temp.path().join("node-a").join("20260524");
    fs::create_dir_all(&corrupt_dir).unwrap();
    let corrupt = corrupt_dir.join("00000000000000000000000000.ndjson");
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
            .with_file_name("00000000000000000000000000.ndjson.corrupt")
            .exists(),
        "corrupt spool file should be quarantined"
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

/// Clears the process-global spool write hook and opens any held release gate
/// even if the test panics mid-block.
struct ClearSpoolWriteHookOnDrop {
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl Drop for ClearSpoolWriteHookOnDrop {
    fn drop(&mut self) {
        {
            let (lock, cv) = &*self.release;
            if let Ok(mut guard) = lock.lock() {
                *guard = true;
                cv.notify_all();
            }
        }
        set_spool_write_hook_for_tests(None);
    }
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

    let entered = Arc::new((Mutex::new(false), Condvar::new()));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let finished = Arc::new((Mutex::new(false), Condvar::new()));
    let _clear_hook = ClearSpoolWriteHookOnDrop {
        release: Arc::clone(&release),
    };
    let block_first = Arc::new(AtomicBool::new(true));

    let entered_for_hook = Arc::clone(&entered);
    let release_for_hook = Arc::clone(&release);
    let finished_for_hook = Arc::clone(&finished);
    set_spool_write_hook_for_tests(Some(Arc::new(move |point| match point {
        SpoolWriteHookPoint::BeforeWrite => {
            if block_first.swap(false, Ordering::SeqCst) {
                {
                    let (lock, cv) = &*entered_for_hook;
                    let mut guard = lock.lock().expect("entered gate lock");
                    *guard = true;
                    cv.notify_all();
                }
                let (lock, cv) = &*release_for_hook;
                let mut guard = lock.lock().expect("release gate lock");
                while !*guard {
                    guard = cv.wait(guard).expect("release gate wait");
                }
            }
        }
        SpoolWriteHookPoint::AfterWrite => {
            let (lock, cv) = &*finished_for_hook;
            let mut guard = lock.lock().expect("finished gate lock");
            *guard = true;
            cv.notify_all();
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

    wait_condvar_flag(Arc::clone(&entered)).await;

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
        !*finished.0.lock().expect("finished gate lock"),
        "blocked spool write must not finish before release"
    );

    let enqueued_during_gate = enqueued_after_hook - enqueued_baseline;

    {
        let (lock, cv) = &*release;
        let mut guard = lock.lock().expect("release gate lock");
        *guard = true;
        cv.notify_all();
    }

    wait_condvar_flag(Arc::clone(&finished)).await;

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
