use std::path::Path;

use ferrum_edge::plugins::api_chargeback_sink::{
    ApiChargebackSink, ApiChargebackSinkConfig, ChargeEvent, SnapshotAccumulator, SpoolCompression,
    SpoolManager, SpoolSettings, decode_spool_file_for_tests, new_ulid, serialize_json_each_row,
};
use ferrum_edge::plugins::chargeback::pricing::ChargeComputation;
use ferrum_edge::plugins::{Plugin, PluginHttpClient};
use serde_json::{Value, json};

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

#[test]
fn json_each_row_serialization_is_line_delimited_and_omits_none() {
    let events = vec![sample_event("evt-1"), sample_event("evt-2")];
    let body = serialize_json_each_row(&events).unwrap();

    assert!(!body.ends_with('\n'));
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["event_id"], "evt-1");
    assert!(first.get("consumer_name").is_none());
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

#[test]
fn spool_write_round_trip_and_oldest_eviction() {
    let temp = tempfile::tempdir().unwrap();
    let settings = SpoolSettings {
        enabled: true,
        dir: temp.path().to_path_buf(),
        max_bytes: 1,
        replay_interval_secs: 60,
        compression: SpoolCompression::None,
    };
    let spool = SpoolManager::for_tests(settings, "node-a").unwrap();
    let event = sample_event("evt-1");

    let first = spool.write_events(std::slice::from_ref(&event)).unwrap();
    let decoded = decode_spool_file_for_tests(&first).unwrap();
    assert_eq!(
        decoded,
        serialize_json_each_row(std::slice::from_ref(&event)).unwrap()
    );

    let second = spool.write_events(&[sample_event("evt-2")]).unwrap();
    assert!(second.exists());
    assert!(
        !first.exists(),
        "oldest spool file should be evicted before second write"
    );
    let stats = spool.scan_stats().unwrap();
    assert_eq!(stats.files, 1);
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
