use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::plugins::api_chargeback_sink::{
    ApiChargebackSink, ApiChargebackSinkConfig, ChargeEvent, SnapshotAccumulator, SpoolCompression,
    SpoolManager, SpoolSettings, decode_spool_file_for_tests, encode_spool_bytes_for_tests,
    new_ulid, render_prometheus, replay_spool_once_for_tests, serialize_json_each_row,
    write_private_file_atomically_for_tests,
};
use ferrum_edge::plugins::chargeback::pricing::ChargeComputation;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, TransactionSummary, WsDisconnectContext};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

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

    let mut events = accumulator.compute_deltas(&config, "node-a", 100, "snap-grpc");
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

    let events = accumulator.compute_deltas(&config, "node-a", 100, "snap-grpc");
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

    // OpenAPI cannot express max_delay_ms >= initial_delay_ms; document and
    // cover both layers so inverted retry bounds stay constructor-gated.
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
    let first = accumulator.compute_deltas(&config, "node-a", 100, "snap-1");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].call_count, 3);
    assert_eq!(first[0].bytes_received, 200);

    let second = accumulator.compute_deltas(&config, "node-a", 200, "snap-2");
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
    let third = accumulator.compute_deltas(&config, "node-a", 300, "snap-3");
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].call_count, 2);
    assert_eq!(third[0].bytes_sent, 50);

    config.snapshot.emit_zero_deltas = true;
    let zero = accumulator.compute_deltas(&config, "node-a", 400, "snap-4");
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
            let owned = name.ends_with(".ndjson")
                || name.ends_with(".ndjson.zst")
                || name.ends_with(".ndjson.tmp")
                || name.ends_with(".ndjson.zst.tmp")
                || name.ends_with(".ndjson.corrupt")
                || name.ends_with(".ndjson.zst.corrupt");
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

    // ACTIVE_SINK is process-global; retry briefly if a parallel sink test races
    // the published runtime between construction and scrape.
    let mut matched_prom = None;
    let mut held_plugin = None;
    for _ in 0..20 {
        let plugin =
            ApiChargebackSink::new(&config, PluginHttpClient::default(), "ferrum").unwrap();
        let node_dirs: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        assert_eq!(
            node_dirs.len(),
            1,
            "enabled spool should create exactly one node directory"
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
        "ACTIVE_SINK never observed this sink's quarantined owned bytes in prometheus output",
    );
    assert!(
        prom.contains(
            "# HELP chargeback_sink_spool_bytes Chargeback sink on-disk owned spool bytes (active, temp, and quarantined files)."
        ),
        "prometheus HELP must describe the owned-byte ceiling contract"
    );
    assert!(
        prom.contains(
            "# HELP chargeback_sink_spool_files Chargeback sink on-disk owned spool file count (active, temp, and quarantined files)."
        ),
        "prometheus HELP must describe owned file accounting"
    );
    assert!(
        prom.contains("chargeback_sink_spool_files 1\n"),
        "prometheus must count quarantined files toward spool.files; got:\n{prom}"
    );
    assert_eq!(
        disk_owned_bytes(temp.path()),
        corrupt_bytes,
        "on-disk owned usage must include the planted .corrupt file"
    );
    drop(held_plugin);
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
    assert!(plugin.requires_ws_disconnect_hooks());

    plugin
        .on_ws_disconnect(&WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: "ws-proxy".to_string(),
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
            .len(),
        1
    );

    assert_eq!(accumulator.cleanup_stale_for_tests(0), 1);
    assert!(
        accumulator
            .compute_deltas(&config, "node-a", 200, "snap-2")
            .is_empty()
    );
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
