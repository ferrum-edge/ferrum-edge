//! Tests for the `proxy_alerts` plugin.
//!
//! Coverage:
//! - Config validation (empty channels/rules, unknown channel refs, range
//!   checks per rule type, severity strings, error class strings).
//! - Bucketed sliding-window correctness (record/snapshot under synthetic
//!   `now_ms`).
//! - Cooldown gate per `(rule_id, proxy_id, channel_id)`.
//! - Recovery state machine transitions (Healthy → Active → Recovering →
//!   Healthy / Recovering → Active flap).
//! - Plugin construction wires everything end-to-end.

use chrono::{TimeZone, Utc};
use ferrum_edge::plugins::proxy_alerts::ProxyAlerts;
use ferrum_edge::plugins::proxy_alerts::config::QuietHourWindow;
use ferrum_edge::plugins::proxy_alerts::cooldown::{
    CooldownGate, LifecycleOutcome, RecoveryGate, RuleState,
};
use ferrum_edge::plugins::proxy_alerts::rules::SampleInput;
use ferrum_edge::plugins::proxy_alerts::windows::{
    BucketedCounter, BucketedLatencyHistogram, WindowStore,
};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, Plugin, TransactionSummary, WsDisconnectContext,
};
use ferrum_edge::proxy::tcp_proxy::StreamIoSide;
use ferrum_edge::retry::ErrorClass;
use serde_json::json;

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn minimal_config() -> serde_json::Value {
    json!({
        "channels": {
            "ops_slack": {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/services/x/y/z"
            }
        },
        "rules": [
            {
                "name": "proxy_5xx",
                "type": "error_rate",
                "status_codes": [500, 502, 503],
                "window_seconds": 60,
                "threshold_percent": 5.0,
                "min_request_count": 10,
                "channels": ["ops_slack"]
            }
        ]
    })
}

// ----------------------------------------------- Construction / config validation

#[test]
fn rejects_non_object_config() {
    let err = ProxyAlerts::new(&json!([]), http_client()).unwrap_err();
    assert!(err.contains("must be an object"), "got: {err}");
}

#[test]
fn rejects_missing_channels() {
    let err = ProxyAlerts::new(&json!({ "rules": [] }), http_client()).unwrap_err();
    assert!(err.contains("'channels' is required"), "got: {err}");
}

#[test]
fn rejects_empty_channels() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {},
            "rules": []
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("at least one channel"), "got: {err}");
}

#[test]
fn rejects_missing_rules() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {
                "ops_slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            }
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("'rules' is required"), "got: {err}");
}

#[test]
fn rejects_empty_rules_array() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {
                "ops_slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": []
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("at least one rule"), "got: {err}");
}

#[test]
fn rejects_unknown_channel_reference() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["channels"] = json!(["does_not_exist"]);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown channel"), "got: {err}");
}

#[test]
fn rejects_duplicate_rule_name() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "name": "r1", "type": "error_rate", "status_codes": [500],
                "threshold_percent": 5.0, "channels": ["c"]
            },
            {
                "name": "r1", "type": "error_rate", "status_codes": [500],
                "threshold_percent": 5.0, "channels": ["c"]
            }
        ]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("duplicate rule name"), "got: {err}");
}

#[test]
fn disabled_malformed_rules_are_skipped_before_validation() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "enabled": false,
                "type": "totally_unknown"
            },
            {
                "name": "active", "type": "error_rate", "status_codes": [500],
                "threshold_percent": 5.0, "channels": ["c"]
            }
        ]
    });
    ProxyAlerts::new(&cfg, http_client()).unwrap();
}

#[test]
fn disabled_duplicate_rule_names_do_not_collide_with_active_rules() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "name": "shared", "enabled": false, "type": "error_rate",
                "status_codes": [500], "threshold_percent": 5.0, "channels": ["c"]
            },
            {
                "name": "shared", "type": "error_rate", "status_codes": [500],
                "threshold_percent": 5.0, "channels": ["c"]
            }
        ]
    });
    ProxyAlerts::new(&cfg, http_client()).unwrap();
}

#[test]
fn rejects_window_seconds_out_of_range() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["window_seconds"] = json!(2);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("'window_seconds' must be"), "got: {err}");
}

#[test]
fn rejects_threshold_percent_out_of_range() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["threshold_percent"] = json!(150.0);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("'threshold_percent' must be"), "got: {err}");
}

#[test]
fn rejects_zero_threshold_percent() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["threshold_percent"] = json!(0.0);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(
        err.contains("'threshold_percent' must be in (0.0, 100.0]"),
        "got: {err}"
    );
}

#[test]
fn rejects_latency_threshold_above_histogram_range() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "name": "too_long", "type": "latency_percentile",
                "metric": "stream_duration_ms", "percentile": 95,
                "threshold_ms": 300001, "channels": ["c"]
            }
        ]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("'threshold_ms' must be <="), "got: {err}");
}

#[test]
fn rejects_unknown_severity() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["severity"] = json!("urgent");
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown severity"), "got: {err}");
}

#[test]
fn rejects_unknown_error_class_in_rule() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "name": "r1", "type": "error_class",
                "classes": ["timewarp"],
                "threshold_count": 5,
                "channels": ["c"]
            }
        ]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown error class"), "got: {err}");
}

#[test]
fn rejects_invalid_quiet_hours_time() {
    let mut cfg = minimal_config();
    cfg["quiet_hours_utc"] = json!([{ "from": "25:00", "to": "06:00" }]);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("hour 25"), "got: {err}");
}

#[test]
fn rejects_non_padded_quiet_hours_time() {
    let mut cfg = minimal_config();
    cfg["quiet_hours_utc"] = json!([{ "from": "1:00", "to": "06:00" }]);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("expected HH:MM"), "got: {err}");
}

#[test]
fn wrapped_quiet_hours_weekday_applies_to_window_start_day() {
    let window = QuietHourWindow {
        from_minute: 23 * 60,
        to_minute: 6 * 60,
        weekdays: vec![0], // Sunday-starting windows only.
    };

    assert!(window.matches(Utc.with_ymd_and_hms(2026, 5, 17, 23, 30, 0).unwrap()));
    assert!(window.matches(Utc.with_ymd_and_hms(2026, 5, 18, 2, 0, 0).unwrap()));
    assert!(
        !window.matches(Utc.with_ymd_and_hms(2026, 5, 17, 2, 0, 0).unwrap()),
        "early Sunday belongs to Saturday night's wrapped window"
    );
    assert!(
        !window.matches(Utc.with_ymd_and_hms(2026, 5, 18, 23, 30, 0).unwrap()),
        "Monday night starts a Monday window, not a Sunday one"
    );
}

#[tokio::test]
async fn accepts_valid_minimal_config() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    assert_eq!(plugin.name(), "proxy_alerts");
    assert_eq!(plugin.priority(), 9250);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(!plugin.is_authorize_plugin());
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["hooks.slack.com".to_string()]
    );
}

#[test]
fn accepts_valid_minimal_config_without_tokio_runtime() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    assert_eq!(plugin.name(), "proxy_alerts");
}

#[tokio::test]
async fn accepts_all_rule_types() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "r1", "type": "error_rate", "status_codes": [500],
              "threshold_percent": 5.0, "channels": ["c"] },
            { "name": "r2", "type": "status_code_count", "status_codes": [401, 403],
              "threshold_count": 100, "channels": ["c"] },
            { "name": "r3", "type": "latency_percentile", "metric": "backend_total_ms",
              "percentile": 95, "threshold_ms": 1000, "channels": ["c"] },
            { "name": "r4", "type": "error_class", "classes": ["connection_refused", "tls_error"],
              "threshold_count": 10, "channels": ["c"] },
            { "name": "r5", "type": "stream_disconnect_cause", "causes": ["backend_error"],
              "threshold_count": 5, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, http_client()).unwrap();
    assert_eq!(plugin.name(), "proxy_alerts");
}

#[tokio::test]
async fn websocket_disconnect_rules_opt_into_disconnect_hook() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "ws_errors", "type": "error_class", "classes": ["connection_reset"],
              "threshold_count": 1, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, http_client()).unwrap();
    assert!(plugin.requires_ws_disconnect_hooks());
}

#[tokio::test]
async fn http_only_rules_do_not_opt_into_websocket_disconnect_hook() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    assert!(!plugin.requires_ws_disconnect_hooks());
}

#[test]
fn websocket_disconnect_context_feeds_stream_rules() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "ws_disconnects", "type": "stream_disconnect_cause",
              "causes": ["backend_error"], "threshold_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 123.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: Some(Direction::BackendToClient),
        io_side: Some(StreamIoSide::Read),
        error_class: Some(ErrorClass::ConnectionReset),
        consumer_username: None,
        auth_method: None,
        metadata: Default::default(),
    };
    let observation = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("websocket sample should apply");
    assert!(observation.breach);
    assert_eq!(observation.sample_count, 1);
}

#[test]
fn websocket_disconnect_cause_distinguishes_client_write_failures() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "client_disconnects", "type": "stream_disconnect_cause",
              "causes": ["recv_error"], "threshold_count": 1, "channels": ["c"] },
            { "name": "backend_disconnects", "type": "stream_disconnect_cause",
              "causes": ["backend_error"], "threshold_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 123.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 0,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: Some(Direction::BackendToClient),
        io_side: Some(StreamIoSide::Write),
        error_class: Some(ErrorClass::ConnectionReset),
        consumer_username: None,
        auth_method: None,
        metadata: Default::default(),
    };

    let recv_error = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("websocket sample should apply");
    let backend_error = parsed.rules[1]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("websocket sample should apply");

    assert!(recv_error.breach);
    assert!(!backend_error.breach);
}

#[test]
fn http_error_class_rules_match_body_error_class_when_request_error_is_also_set() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "body_errors", "type": "error_class",
              "classes": ["response_body_too_large"], "threshold_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_name: Some("api".to_string()),
        response_status_code: 502,
        error_class: Some(ErrorClass::ConnectionReset),
        body_error_class: Some(ErrorClass::ResponseBodyTooLarge),
        ..TransactionSummary::default()
    };

    let observation = parsed.rules[0]
        .observe(SampleInput::Http(&summary), &store, 1_000)
        .expect("http sample should apply");
    assert!(observation.breach);
    assert_eq!(observation.sample_count, 1);
}

#[test]
fn latency_sentinel_sample_keeps_existing_breach() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "slow_ws", "type": "latency_percentile",
              "metric": "stream_duration_ms", "percentile": 95,
              "threshold_ms": 1000, "min_request_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let mut ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 1500.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        metadata: Default::default(),
    };
    let first = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("first sample should apply");
    assert!(first.breach);

    ctx.duration_ms = -1.0;
    let sentinel = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 2_000)
        .expect("sentinel sample should still return snapshot");
    assert!(sentinel.breach);
    assert_eq!(sentinel.sample_count, 1);
}

#[test]
fn latency_boundary_threshold_does_not_fire_previous_bucket() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "almost_too_slow", "type": "latency_percentile",
              "metric": "stream_duration_ms", "percentile": 95,
              "threshold_ms": 300000, "min_request_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 299_999.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        metadata: Default::default(),
    };
    let observation = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("latency sample should apply");
    assert_eq!(observation.render(&parsed.rules[0]).observed, "300000ms");
    assert!(
        !observation.breach,
        "the 300000ms bucket label covers samples below the 300000ms threshold"
    );
}

#[test]
fn latency_non_boundary_threshold_fires_within_estimated_bucket() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "slow_ws", "type": "latency_percentile",
              "metric": "stream_duration_ms", "percentile": 95,
              "threshold_ms": 1500, "min_request_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 2_000.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        metadata: Default::default(),
    };
    let observation = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("latency sample should apply");
    assert_eq!(observation.render(&parsed.rules[0]).observed, "2500ms");
    assert!(
        observation.breach,
        "a 1500ms threshold should fire when the percentile lands in the 2500ms bucket"
    );
}

#[test]
fn latency_overflow_bucket_reports_configured_max_bound() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "very_slow_ws", "type": "latency_percentile",
              "metric": "stream_duration_ms", "percentile": 95,
              "threshold_ms": 300000, "min_request_count": 1, "channels": ["c"] }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let ctx = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "p1".to_string(),
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 301_000.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        metadata: Default::default(),
    };
    let observation = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ctx), &store, 1_000)
        .expect("overflow latency sample should apply");
    assert!(observation.breach);
    assert_eq!(observation.render(&parsed.rules[0]).observed, ">300000ms");
}

// -------------------------------------------------------------- BucketedCounter

#[test]
fn bucketed_counter_records_and_aggregates_within_window() {
    let counter = BucketedCounter::new(60); // 60s = 6s buckets * 10
    let base = 1_000_000u64;
    counter.record(true, base);
    counter.record(false, base + 10);
    counter.record(true, base + 1000);
    let (matched, total) = counter.snapshot(base + 1500);
    assert_eq!(matched, 2);
    assert_eq!(total, 3);
}

#[test]
fn bucketed_counter_drops_buckets_older_than_window() {
    let counter = BucketedCounter::new(10); // 10s window, 1s buckets
    let base = 1_000_000u64;
    counter.record(true, base);
    // Roll forward past the entire window. Each bucket reset clears its
    // counters individually as new tags arrive.
    let (matched_inside, total_inside) = counter.snapshot(base + 5_000);
    assert_eq!(matched_inside, 1);
    assert_eq!(total_inside, 1);
    // Record a new sample 30s later; the only currently-valid bucket is the
    // one we just wrote to (older buckets were never re-tagged so they
    // appear stale to snapshot()).
    counter.record(false, base + 30_000);
    let (matched_after, total_after) = counter.snapshot(base + 30_500);
    assert_eq!(matched_after, 0, "old matched count must drop out");
    assert_eq!(total_after, 1);
}

// ----------------------------------------------- BucketedLatencyHistogram

#[test]
fn latency_histogram_estimates_p95_within_known_bucket() {
    let h = BucketedLatencyHistogram::new(60);
    let base = 2_000_000u64;
    // 100 samples: 95 small (<= 100ms) + 5 large (>= 1000ms).
    for i in 0..95 {
        h.record(50.0, base + i);
    }
    for i in 0..5 {
        h.record(1500.0, base + 95 + i);
    }
    let (p95, total) = h.percentile(95, base + 1000);
    assert_eq!(total, 100);
    // The 95th sample falls in bucket [50, 100) (95 samples at 50ms land
    // in that bucket). The estimate returned is the bucket's upper bound:
    // 100ms — i.e., "p95 is at most 100ms." This is a conservative
    // overestimate compared to the true p95 (50ms), which is the right
    // direction for alerting (slight bias against firing).
    assert_eq!(p95, Some(100.0));
}

#[test]
fn latency_histogram_returns_none_when_empty() {
    let h = BucketedLatencyHistogram::new(60);
    let (p, total) = h.percentile(95, 100);
    assert_eq!(p, None);
    assert_eq!(total, 0);
}

// ------------------------------------------------------------- CooldownGate

#[test]
fn cooldown_gate_first_acquire_succeeds() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100));
}

#[test]
fn cooldown_gate_blocks_within_window() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100));
    assert!(!gate.try_acquire(1, "p1", 10, 60_000, 100 + 30_000));
}

#[test]
fn cooldown_gate_releases_after_window() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100));
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100 + 60_001));
}

#[test]
fn cooldown_gate_per_channel_independent() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100));
    // Same rule, different channel: should not be blocked.
    assert!(gate.try_acquire(1, "p1", 11, 60_000, 100 + 1));
}

#[test]
fn cooldown_gate_per_proxy_independent() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100));
    assert!(gate.try_acquire(1, "p2", 10, 60_000, 100 + 1));
}

// -------------------------------------------------------------- RecoveryGate

#[test]
fn recovery_healthy_to_active_emits_trigger() {
    let gate = RecoveryGate::new();
    let outcome = gate.observe(1, "p", true, 60_000, 1_000);
    assert_eq!(outcome, LifecycleOutcome::Trigger);
    assert_eq!(
        gate.current_state(1, "p"),
        Some(RuleState::Active { fired_at_ms: 1_000 })
    );
}

#[test]
fn recovery_active_to_active_returns_still_active() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000);
    let outcome = gate.observe(1, "p", true, 60_000, 2_000);
    assert_eq!(outcome, LifecycleOutcome::StillActive);
}

#[test]
fn recovery_active_to_recovering_then_resolve() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000);
    let entering = gate.observe(1, "p", false, 60_000, 2_000);
    assert_eq!(entering, LifecycleOutcome::EnteringRecovery);
    // Same call within recovery window: still quiet.
    let quiet = gate.observe(1, "p", false, 60_000, 30_000);
    assert_eq!(quiet, LifecycleOutcome::Quiet);
    // After recovery window has elapsed (resolved_window_ms = 60_000 from
    // the EnteringRecovery timestamp 2_000): observe at 2_000 + 60_000 =
    // 62_000.
    let resolve = gate.observe(1, "p", false, 60_000, 62_000);
    assert_eq!(resolve, LifecycleOutcome::Resolve);
    assert_eq!(gate.current_state(1, "p"), Some(RuleState::Healthy));
}

#[test]
fn recovery_recovering_to_active_when_breach_returns_during_window() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000); // Active
    gate.observe(1, "p", false, 60_000, 2_000); // Recovering
    let reactivate = gate.observe(1, "p", true, 60_000, 3_000);
    assert_eq!(reactivate, LifecycleOutcome::Reactivate);
    assert!(matches!(
        gate.current_state(1, "p"),
        Some(RuleState::Active { .. })
    ));
}

#[test]
fn recovery_disabled_when_recovery_ms_is_zero() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 0, 1_000);
    let below = gate.observe(1, "p", false, 0, 2_000);
    assert_eq!(below, LifecycleOutcome::Quiet);
    assert_eq!(gate.current_state(1, "p"), Some(RuleState::Healthy));
    let next_breach = gate.observe(1, "p", true, 0, 1_000_000);
    assert_eq!(next_breach, LifecycleOutcome::Trigger);
}
