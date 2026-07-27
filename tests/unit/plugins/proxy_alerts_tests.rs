//! Tests for the `proxy_alerts` plugin.
//!
//! Coverage:
//! - Config validation (empty channels/rules, unknown channel refs, range
//!   checks per rule type, severity strings, error class strings,
//!   grpc_statuses 0..=16 / OTHER).
//! - Bucketed sliding-window correctness (record/snapshot under synthetic
//!   `now_ms`).
//! - Cooldown gate per `(rule_id, proxy_id, channel_id)`.
//! - Recovery state machine transitions (Healthy → Active → Recovering →
//!   Healthy / Recovering → Active flap).
//! - Lifecycle retention: prune removed proxies, expire cooldown rows, drop
//!   terminal Healthy recovery state, and clear inherited ID-reuse state.
//! - gRPC terminal-status count/rate rules across buffered, streamed,
//!   trailers-only, H2/H3, and gateway-rejection summary shapes.
//! - Plugin construction wires everything end-to-end.

use chrono::{TimeZone, Utc};
use ferrum_edge::plugins::proxy_alerts::ProxyAlerts;
use ferrum_edge::plugins::proxy_alerts::config::QuietHourWindow;
use ferrum_edge::plugins::proxy_alerts::cooldown::{
    CooldownGate, LifecycleOutcome, RecoveryGate, RuleState,
};
use ferrum_edge::plugins::proxy_alerts::rules::SampleInput;
use ferrum_edge::plugins::proxy_alerts::windows::{
    BucketedCounter, BucketedLatencyHistogram, RuleWindowSpec, WindowKind, WindowStore,
};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, Plugin, PluginFailurePolicy, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext, plugin_failure_policy,
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

#[test]
fn configured_proxy_alerts_remains_optional_fail_open() {
    assert_eq!(
        plugin_failure_policy("proxy_alerts"),
        Some(PluginFailurePolicy::OptionalFailOpen)
    );
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
fn rejects_config_with_only_disabled_draft_rules() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {
                "ops_slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "enabled": false,
                "unknown_draft_field": true
            }]
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("no rules left to evaluate"), "got: {err}");
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
fn error_class_rules_accept_and_observe_every_runtime_label() {
    let classes = [
        ErrorClass::ConnectionTimeout,
        ErrorClass::ConnectionRefused,
        ErrorClass::ConnectionReset,
        ErrorClass::ConnectionClosed,
        ErrorClass::DnsLookupError,
        ErrorClass::TlsError,
        ErrorClass::ReadWriteTimeout,
        ErrorClass::ClientDisconnect,
        ErrorClass::ProtocolError,
        ErrorClass::ResponseBodyTooLarge,
        ErrorClass::RequestBodyTooLarge,
        ErrorClass::ConnectionPoolError,
        ErrorClass::PortExhaustion,
        ErrorClass::GracefulRemoteClose,
        ErrorClass::DispatchPolicyRejected,
        ErrorClass::RequestError,
    ];
    let labels: Vec<&str> = classes.iter().map(ErrorClass::as_str).collect();
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "runtime_errors",
            "type": "error_class",
            "classes": labels,
            "threshold_count": 1,
            "channels": ["c"]
        }]
    }))
    .expect("every runtime ErrorClass label should compile as an alert rule");

    let specs = parsed
        .rules
        .iter()
        .map(|rule| (rule.id(), rule.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    for class in classes {
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            error_class: Some(class),
            ..TransactionSummary::default()
        };
        let observation = parsed.rules[0]
            .observe(SampleInput::Http(&summary), &store, 1_000)
            .expect("configured runtime error class should be observed");
        assert!(
            observation.breach,
            "{} should trigger the rule",
            class.as_str()
        );
    }
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

#[test]
fn rejects_unknown_top_level_and_nested_keys_with_paths() {
    for (config, needle, expect_suggestion) in [
        (
            json!({
                "enabledd": false,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "config.enabledd",
            true,
        ),
        (
            json!({
                "max_concurent_dispatches": 1,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "config.max_concurent_dispatches",
            true,
        ),
        (
            json!({
                "quiet_hours_utc": [{
                    "from": "23:00",
                    "to": "06:00",
                    "weekdayss": [0]
                }],
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "quiet_hours_utc[0].weekdayss",
            true,
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x",
                        "channel_overide": "#low-volume"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "channels.ops.channel_overide",
            true,
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "cooldown_second": 3600,
                    "channels": ["ops"]
                }]
            }),
            "rules[0].cooldown_second",
            true,
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"],
                    "recovery": { "resolved_window_second": 300 }
                }]
            }),
            "rules[0].recovery.resolved_window_second",
            true,
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "threshold_count": 10,
                    "channels": ["ops"]
                }]
            }),
            "rules[0].threshold_count",
            false,
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "teams",
                        "webhook_url": "https://outlook.office.com/x",
                        "channel_override": "#alerts"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "status_code_count",
                    "status_codes": [500],
                    "threshold_count": 10,
                    "channels": ["ops"]
                }]
            }),
            "channels.ops.channel_override",
            false,
        ),
    ] {
        let err = ProxyAlerts::new(&config, http_client())
            .expect_err("unknown configuration keys must fail closed");
        assert!(
            err.contains("unknown configuration key"),
            "missing unknown-key wording: {err}"
        );
        assert!(
            err.contains(needle),
            "error did not identify {needle}: {err}"
        );
        if expect_suggestion {
            assert!(
                err.contains("did you mean"),
                "typo diagnostics should include a suggestion: {err}"
            );
        }
    }
}

#[test]
fn rejects_unknown_rule_type_with_variant_fields_reports_type() {
    let cfg = json!({
        "channels": {
            "ops": {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/x"
            }
        },
        "rules": [{
            "name": "errors",
            "type": "error_ratee",
            "status_codes": [500],
            "threshold_percent": 5.0,
            "channels": ["ops"]
        }]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(
        err.contains("unknown type 'error_ratee'"),
        "unknown discriminator must be the primary error: {err}"
    );
    assert!(
        !err.contains("unknown configuration key"),
        "variant fields must not be mislabeled as unknown keys: {err}"
    );
}

#[test]
fn rejects_typo_required_name_and_type_keys_with_suggestions() {
    for (rule, needle) in [
        (
            json!({
                "namee": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }),
            "did you mean 'name' instead of 'namee'",
        ),
        (
            json!({
                "name": "errors",
                "typee": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }),
            "did you mean 'type' instead of 'typee'",
        ),
    ] {
        let err = ProxyAlerts::new(
            &json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [rule]
            }),
            http_client(),
        )
        .unwrap_err();
        assert!(
            err.contains(needle),
            "missing required-key suggestion ({needle}): {err}"
        );
    }
}

#[test]
fn accepts_enabled_false_draft_rule_with_incomplete_fields() {
    let cfg = json!({
        "channels": {
            "ops": {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/x"
            }
        },
        "rules": [
            {
                "enabled": false,
                "name": "draft",
                "type": "error_rate",
                "unknown_draft_field": true
            },
            {
                "name": "active",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, http_client()).expect("disabled drafts must be skipped");
    assert_eq!(plugin.name(), "proxy_alerts");
}

#[test]
fn rejects_malformed_optional_proxy_alerts_scalars() {
    for (config, needle) in [
        (
            json!({
                "enabled": "false",
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'enabled' must be a boolean",
        ),
        (
            json!({
                "enabled": null,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'enabled' must be a boolean",
        ),
        (
            json!({
                "max_concurrent_dispatches": 0,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'max_concurrent_dispatches' must be >= 1",
        ),
        (
            json!({
                "max_concurrent_dispatches": "8",
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'max_concurrent_dispatches' must be an unsigned integer",
        ),
        (
            json!({
                "max_concurrent_dispatches": null,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'max_concurrent_dispatches' must be an unsigned integer",
        ),
        (
            json!({
                "quiet_hours_utc": null,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'quiet_hours_utc' must be an array",
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "enabled": "false",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "rules[0].enabled must be a boolean",
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "enabled": null,
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "rules[0].enabled must be a boolean",
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "min_request_count": "100",
                    "channels": ["ops"]
                }]
            }),
            "'min_request_count' must be an unsigned integer",
        ),
        (
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "latency",
                    "type": "latency_percentile",
                    "metric": "backend_total_ms",
                    "percentile": 95,
                    "threshold_ms": 1500,
                    "min_request_count": true,
                    "channels": ["ops"]
                }]
            }),
            "'min_request_count' must be an unsigned integer",
        ),
    ] {
        let err = ProxyAlerts::new(&config, http_client())
            .expect_err("malformed optional values must fail closed");
        assert!(err.contains(needle), "expected `{needle}` in error: {err}");
    }
}

#[test]
fn rejects_invalid_top_level_defaults_even_when_rules_override_them() {
    for (key, value, needle) in [
        (
            "default_cooldown_seconds",
            json!(0),
            "'default_cooldown_seconds' must be in [1, 86400]",
        ),
        (
            "default_cooldown_seconds",
            json!(86_401),
            "'default_cooldown_seconds' must be in [1, 86400]",
        ),
        (
            "default_min_request_count",
            json!(0),
            "'default_min_request_count' must be >= 1",
        ),
        (
            "default_window_seconds",
            json!(4),
            "'default_window_seconds' must be in [5, 3600]",
        ),
        (
            "default_window_seconds",
            json!(3_601),
            "'default_window_seconds' must be in [5, 3600]",
        ),
        (
            "default_resolved_window_seconds",
            json!(4),
            "'default_resolved_window_seconds' must be in [5, 86400]",
        ),
        (
            "default_resolved_window_seconds",
            json!(86_401),
            "'default_resolved_window_seconds' must be in [5, 86400]",
        ),
    ] {
        let mut config = minimal_config();
        config[key] = value;
        config["rules"][0]["cooldown_seconds"] = json!(300);
        config["rules"][0]["recovery"] = json!({"resolved_window_seconds": 300});

        let err = ProxyAlerts::new(&config, http_client())
            .expect_err("invalid unused defaults must fail admission eagerly");
        assert!(err.contains(needle), "expected `{needle}` in error: {err}");
    }
}

#[test]
fn shared_validator_rejects_malformed_optional_proxy_alerts_values() {
    let err = ferrum_edge::plugins::validate_plugin_config(
        "proxy_alerts",
        &json!({
            "enabled": "false",
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
    )
    .expect_err("shared validation must reject malformed enabled");
    assert!(
        err.contains("'enabled' must be a boolean"),
        "shared validator path missing: {err}"
    );
}

#[test]
fn shared_validator_rejects_unknown_proxy_alerts_keys() {
    let err = ferrum_edge::plugins::validate_plugin_config(
        "proxy_alerts",
        &json!({
            "enabledd": false,
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
    )
    .expect_err("shared validation must reject unknown keys");
    assert!(
        err.contains("config.enabledd"),
        "shared validator path missing: {err}"
    );
}

#[test]
fn accepts_arbitrary_channel_names_and_webhook_header_names() {
    let plugin = ProxyAlerts::new(
        &json!({
            "channels": {
                "team-alpha_42": {
                    "type": "webhook",
                    "url": "https://example.com/hooks",
                    "headers": {
                        "X-Custom-Trace": "abc",
                        "X-Routing-Key": "rk"
                    },
                    "body_template": "{\"ok\":true}"
                }
            },
            "rules": [{
                "name": "errors",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["team-alpha_42"]
            }]
        }),
        http_client(),
    )
    .expect("arbitrary channel and header names must remain valid");
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
              "threshold_count": 5, "channels": ["c"] },
            { "name": "r6", "type": "grpc_status_count", "grpc_statuses": [14, "OTHER"],
              "threshold_count": 10, "channels": ["c"] },
            { "name": "r7", "type": "grpc_status_rate", "grpc_statuses": [13, 14],
              "threshold_percent": 5.0, "min_request_count": 10, "channels": ["c"] }
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
        proxy_lifecycle_generation: None,
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 123.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: Some(Direction::BackendToClient),
        io_side: Some(StreamIoSide::Read),
        error_class: Some(ErrorClass::ConnectionReset),
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
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
        proxy_lifecycle_generation: None,
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 123.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 0,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: Some(Direction::BackendToClient),
        io_side: Some(StreamIoSide::Write),
        error_class: Some(ErrorClass::ConnectionReset),
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
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
        proxy_lifecycle_generation: None,
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 1500.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
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
        proxy_lifecycle_generation: None,
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 299_999.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
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
        proxy_lifecycle_generation: None,
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 2_000.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
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
        proxy_lifecycle_generation: None,
        proxy_name: Some("api".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 301_000.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
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

#[test]
fn bucketed_counter_excludes_future_bucket_after_backward_jump() {
    let counter = BucketedCounter::new(10);
    counter.record(true, 20_000);

    assert_eq!(counter.snapshot(5_000), (0, 0));
    assert_eq!(counter.snapshot(20_000), (1, 1));
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

#[test]
fn latency_histogram_excludes_future_bucket_after_backward_jump() {
    let histogram = BucketedLatencyHistogram::new(10);
    histogram.record(50.0, 20_000);

    assert_eq!(histogram.percentile(95, 5_000), (None, 0));
    assert_eq!(histogram.percentile(95, 20_000), (Some(100.0), 1));
}

// ------------------------------------------------------------- CooldownGate

#[test]
fn cooldown_gate_first_acquire_succeeds() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100, 0));
}

#[test]
fn cooldown_gate_blocks_within_window() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100, 0));
    assert!(!gate.try_acquire(1, "p1", 10, 60_000, 100 + 30_000, 0));
}

#[test]
fn cooldown_gate_releases_after_window() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100, 0));
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100 + 60_001, 0));
}

#[test]
fn cooldown_gate_rebases_backward_jump_and_tracks_new_epoch() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100_000, 0));
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 10_000, 0));
    assert!(!gate.try_acquire(1, "p1", 10, 60_000, 10_001, 0));
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 70_000, 0));
}

#[test]
fn cooldown_gate_per_channel_independent() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100, 0));
    // Same rule, different channel: should not be blocked.
    assert!(gate.try_acquire(1, "p1", 11, 60_000, 100 + 1, 0));
}

#[test]
fn cooldown_gate_per_proxy_independent() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100, 0));
    assert!(gate.try_acquire(1, "p2", 10, 60_000, 100 + 1, 0));
}

// -------------------------------------------------------------- RecoveryGate

#[test]
fn recovery_healthy_to_active_emits_trigger() {
    let gate = RecoveryGate::new();
    let outcome = gate.observe(1, "p", true, 60_000, 1_000, 0);
    assert_eq!(outcome, LifecycleOutcome::Trigger);
    assert_eq!(
        gate.current_state(1, "p", 0),
        Some(RuleState::Active { fired_at_ms: 1_000 })
    );
}

#[test]
fn recovery_active_to_active_returns_still_active() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000, 0);
    let outcome = gate.observe(1, "p", true, 60_000, 2_000, 0);
    assert_eq!(outcome, LifecycleOutcome::StillActive);
}

#[test]
fn recovery_active_to_recovering_then_resolve() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000, 0);
    let entering = gate.observe(1, "p", false, 60_000, 2_000, 0);
    assert_eq!(entering, LifecycleOutcome::EnteringRecovery);
    // Same call within recovery window: still quiet.
    let quiet = gate.observe(1, "p", false, 60_000, 30_000, 0);
    assert_eq!(quiet, LifecycleOutcome::Quiet);
    // After recovery window has elapsed (resolved_window_ms = 60_000 from
    // the EnteringRecovery timestamp 2_000): observe at 2_000 + 60_000 =
    // 62_000.
    let resolve = gate.observe(1, "p", false, 60_000, 62_000, 0);
    assert_eq!(resolve, LifecycleOutcome::Resolve);
    assert_eq!(gate.current_state(1, "p", 0), Some(RuleState::Healthy));
}

#[test]
fn recovery_rebases_backward_jump_before_resolving() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 100_000, 0);
    gate.observe(1, "p", false, 60_000, 110_000, 0);

    assert_eq!(
        gate.observe(1, "p", false, 60_000, 10_000, 0),
        LifecycleOutcome::Quiet
    );
    assert_eq!(
        gate.current_state(1, "p", 0),
        Some(RuleState::Recovering {
            left_threshold_at_ms: 10_000
        })
    );
    assert_eq!(
        gate.observe(1, "p", false, 60_000, 70_000, 0),
        LifecycleOutcome::Resolve
    );
}

#[test]
fn recovery_recovering_to_active_when_breach_returns_during_window() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000, 0); // Active
    gate.observe(1, "p", false, 60_000, 2_000, 0); // Recovering
    let reactivate = gate.observe(1, "p", true, 60_000, 3_000, 0);
    assert_eq!(reactivate, LifecycleOutcome::Reactivate);
    assert!(matches!(
        gate.current_state(1, "p", 0),
        Some(RuleState::Active { .. })
    ));
}

#[test]
fn recovery_disabled_when_recovery_ms_is_zero() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 0, 1_000, 0);
    let below = gate.observe(1, "p", false, 0, 2_000, 0);
    assert_eq!(below, LifecycleOutcome::Quiet);
    assert_eq!(gate.current_state(1, "p", 0), Some(RuleState::Healthy));
    let next_breach = gate.observe(1, "p", true, 0, 1_000_000, 0);
    assert_eq!(next_breach, LifecycleOutcome::Trigger);
}

// ----------------------------------------- Lifecycle retain / bounded history

#[test]
fn cooldown_retain_proxies_drops_removed_proxy_rows() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "gone", 10, 60_000, 100, 0));
    assert!(gate.try_acquire(1, "keep", 10, 60_000, 100, 0));
    gate.retain_proxies(&std::collections::HashMap::from([("keep", 0)]));
    assert!(!gate.contains_proxy("gone"));
    assert!(gate.contains_proxy("keep"));
    // Removed proxy must not inherit the old cooldown after ID reuse.
    assert!(gate.try_acquire(1, "gone", 10, 60_000, 100 + 1, 0));
}

#[test]
fn recovery_retain_proxies_drops_removed_proxy_rows() {
    let gate = RecoveryGate::new();
    gate.observe(1, "gone", true, 60_000, 1_000, 0);
    gate.observe(1, "keep", true, 60_000, 1_000, 0);
    gate.retain_proxies(&std::collections::HashMap::from([("keep", 0)]));
    assert_eq!(gate.current_state(1, "gone", 0), None);
    assert!(matches!(
        gate.current_state(1, "keep", 0),
        Some(RuleState::Active { .. })
    ));
    assert_eq!(
        gate.observe(1, "gone", true, 60_000, 2_000, 0),
        LifecycleOutcome::Trigger,
        "recreated proxy ID must start Healthy rather than inherit Active"
    );
}

#[test]
fn cooldown_evict_stale_drops_expired_timestamps() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100, 0));
    gate.evict_stale(100 + 60_000, 60_000);
    assert!(!gate.contains_proxy("p1"));
}

#[test]
fn cooldown_evict_stale_drops_future_timestamp_after_backward_jump() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, "p1", 10, 60_000, 100_000, 0));
    gate.evict_stale(10_000, 60_000);
    assert!(!gate.contains_proxy("p1"));
}

#[test]
fn window_evict_stale_drops_future_record_after_backward_jump() {
    let store = WindowStore::new(std::collections::HashMap::from([(
        1,
        RuleWindowSpec {
            window_seconds: 10,
            kind: WindowKind::Counter,
        },
    )]));
    store.record_count(1, "p1", 0, true, 100_000);

    store.evict_stale(10_000, 60_000);
    assert!(!store.contains_proxy("p1"));
}

#[test]
fn recovery_evict_resolved_drops_only_healthy_rows() {
    let gate = RecoveryGate::new();
    gate.observe(1, "active", true, 60_000, 1_000, 0);
    gate.observe(1, "resolved", true, 60_000, 1_000, 0);
    gate.observe(1, "resolved", false, 0, 2_000, 0); // Active → Healthy when recovery_ms=0
    assert_eq!(
        gate.current_state(1, "resolved", 0),
        Some(RuleState::Healthy)
    );
    gate.evict_resolved();
    assert_eq!(gate.current_state(1, "resolved", 0), None);
    assert!(matches!(
        gate.current_state(1, "active", 0),
        Some(RuleState::Active { .. })
    ));
}

#[test]
fn proxy_alerts_retain_proxies_clears_all_lifecycle_stores() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.seed_lifecycle_state_for_test("gone", 1);
    plugin.seed_lifecycle_state_for_test("keep", 1);
    assert!(plugin.has_lifecycle_state_for_test("gone"));
    assert!(plugin.has_lifecycle_state_for_test("keep"));

    plugin.retain_proxies(&std::collections::HashMap::from([("keep", 1)]));

    assert!(!plugin.has_lifecycle_state_for_test("gone"));
    assert!(plugin.has_lifecycle_state_for_test("keep"));
}

#[tokio::test]
async fn old_generation_sample_cannot_repopulate_after_removal() {
    // Lifecycle identity is namespace-qualified (`namespace|id`), so the
    // seed/publish/check keys carry the summary's namespace.
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.retain_proxies(&std::collections::HashMap::from([
        ("ferrum|p1", 1),
        ("ferrum|p2", 1),
    ]));
    plugin.seed_lifecycle_state_for_test("ferrum|p1", 1);
    assert!(plugin.has_lifecycle_state_for_test("ferrum|p1"));

    // Removal publish retires p1 rows and disarms generation 1.
    plugin.retain_proxies(&std::collections::HashMap::from([("ferrum|p2", 1)]));
    assert!(!plugin.has_lifecycle_state_for_test("ferrum|p1"));

    // Old in-flight sample admitted under generation 1 finishes after retain.
    let summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(1),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    Plugin::log(&plugin, &summary).await;
    assert!(
        !plugin.has_lifecycle_state_for_test("ferrum|p1"),
        "old-generation completion after removal must not recreate lifecycle rows"
    );
}

#[tokio::test]
async fn old_generation_sample_cannot_inherit_after_identical_id_recreate() {
    // Namespace-qualified lifecycle identity throughout (`namespace|id`).
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.retain_proxies(&std::collections::HashMap::from([("ferrum|p1", 1)]));
    plugin.seed_lifecycle_state_for_test("ferrum|p1", 1);
    assert!(plugin.has_lifecycle_state_for_test("ferrum|p1"));

    // Delete then recreate the same proxy ID with a new ownership generation.
    plugin.retain_proxies(&std::collections::HashMap::new());
    plugin.retain_proxies(&std::collections::HashMap::from([("ferrum|p1", 2)]));
    assert!(
        !plugin.has_lifecycle_state_for_test("ferrum|p1"),
        "recreate must not keep prior rows"
    );

    let stale = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(1),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    Plugin::log(&plugin, &stale).await;
    assert!(
        !plugin.has_lifecycle_state_for_test("ferrum|p1"),
        "stale generation must not write into the replacement incarnation"
    );

    let fresh = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(2),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    Plugin::log(&plugin, &fresh).await;
    // A single sample may only touch windows; seed-equivalent cooldown needs
    // breach+dispatch. Window ownership alone proves the new generation can write.
    assert!(
        plugin.has_lifecycle_state_for_generation_for_test("ferrum|p1", 2),
        "replacement generation must be able to record fresh lifecycle state"
    );
}

#[test]
fn retain_proxies_drops_generation_mismatched_same_id_rows() {
    let cooldown = CooldownGate::new();
    assert!(cooldown.try_acquire(1, "p1", 10, 60_000, 100, 1));
    cooldown.retain_proxies(&std::collections::HashMap::from([("p1", 2)]));
    assert!(
        !cooldown.contains_proxy_generation("p1", 1),
        "same-ID generation advance must retire prior cooldown ownership"
    );
    assert!(!cooldown.contains_proxy("p1"));

    let recovery = RecoveryGate::new();
    recovery.observe(1, "p1", true, 60_000, 1_000, 1);
    recovery.retain_proxies(&std::collections::HashMap::from([("p1", 2)]));
    assert_eq!(recovery.current_state(1, "p1", 1), None);
    assert!(!recovery.contains_proxy("p1"));

    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 1)]));
    plugin.seed_lifecycle_state_for_test("p1", 1);
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 2)]));
    assert!(
        !plugin.has_lifecycle_state_for_generation_for_test("p1", 1),
        "generation-mismatched retain must clear prior incarnation rows"
    );
    assert!(!plugin.has_lifecycle_state_for_test("p1"));
}

#[test]
fn old_generation_direct_write_after_replacement_cannot_affect_new_generation() {
    // Explicit interleaving without timing: seed gen1, publish gen2, then write
    // under gen1 via the store API (bypassing the admission precheck) to prove
    // generation-keyed isolation for the TOCTOU race.
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 1)]));
    plugin.seed_lifecycle_state_for_test("p1", 1);
    assert!(plugin.has_lifecycle_state_for_generation_for_test("p1", 1));

    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 2)]));
    assert!(
        !plugin.has_lifecycle_state_for_generation_for_test("p1", 1),
        "replacement publication must retire gen1 rows"
    );
    assert!(!plugin.has_lifecycle_state_for_generation_for_test("p1", 2));

    plugin.write_lifecycle_state_for_test("p1", 1);
    assert!(
        plugin.has_lifecycle_state_for_generation_for_test("p1", 1),
        "stale writer may create an isolated old-generation orphan"
    );
    assert!(
        !plugin.has_lifecycle_state_for_generation_for_test("p1", 2),
        "stale gen1 write must not populate replacement generation state"
    );

    // New generation begins clean and can write independently.
    plugin.write_lifecycle_state_for_test("p1", 2);
    assert!(plugin.has_lifecycle_state_for_generation_for_test("p1", 2));

    // The periodic ownership sweep must bound the isolated orphan created by
    // the stale writer without expiring the replacement's live incident.
    plugin.sweep_lifecycle_ownership_for_test();
    assert!(
        !plugin.has_lifecycle_state_for_generation_for_test("p1", 1),
        "background ownership retention must prune a late old-generation write"
    );
    assert!(
        plugin.has_lifecycle_state_for_generation_for_test("p1", 2),
        "background ownership retention must preserve current-generation state"
    );

    // Cooldown armed under gen1 must not suppress gen2.
    let cooldown = CooldownGate::new();
    assert!(cooldown.try_acquire(1, "p1", 10, 60_000, 100, 1));
    assert!(
        cooldown.try_acquire(1, "p1", 10, 60_000, 100 + 1, 2),
        "new generation must not inherit prior cooldown"
    );
}

#[test]
fn generation_stable_reload_preserves_lifecycle_state() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 7), ("p2", 7)]));
    plugin.seed_lifecycle_state_for_test("p1", 7);
    plugin.seed_lifecycle_state_for_test("p2", 7);
    assert!(plugin.has_lifecycle_state_for_generation_for_test("p1", 7));
    assert!(plugin.has_lifecycle_state_for_generation_for_test("p2", 7));

    // Stable reload republishes the same ownership generations.
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 7), ("p2", 7)]));
    assert!(plugin.has_lifecycle_state_for_generation_for_test("p1", 7));
    assert!(plugin.has_lifecycle_state_for_generation_for_test("p2", 7));
}

#[test]
fn absent_id_cannot_repopulate_after_armed_retain() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    plugin.retain_proxies(&std::collections::HashMap::from([("keep", 1)]));
    plugin.write_lifecycle_state_for_test("gone", 1);
    // Direct store write can create an orphan under an absent ID, but retain
    // and the armed precheck must keep it out of the active ownership set.
    plugin.retain_proxies(&std::collections::HashMap::from([("keep", 1)]));
    assert!(!plugin.has_lifecycle_state_for_test("gone"));
}

#[test]
fn retention_serialization_keeps_latest_rows_across_stale_sweep() {
    // Deterministic serialization contract without sleeps:
    // 1. Hold the cold-path retention lock (as a commit retain would).
    // 2. Publish a newer ownership map and write current-generation rows.
    // 3. Spawn a sweep that must block until the lock is released.
    // 4. After release, the sweep loads the latest map and must preserve
    //    current-generation rows (the old race deleted them).
    let plugin = std::sync::Arc::new(ProxyAlerts::new(&minimal_config(), http_client()).unwrap());
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 1)]));
    plugin.seed_lifecycle_state_for_test("p1", 1);

    let (sweep_started_tx, sweep_started_rx) = std::sync::mpsc::channel::<()>();
    let (lock_held_tx, lock_held_rx) = std::sync::mpsc::channel::<()>();
    let plugin_sweep = std::sync::Arc::clone(&plugin);
    let sweep = std::thread::spawn(move || {
        sweep_started_tx.send(()).unwrap();
        lock_held_rx.recv().unwrap();
        plugin_sweep.sweep_lifecycle_ownership_for_test();
    });

    sweep_started_rx.recv().unwrap();
    plugin.with_retention_lock_for_test(|| {
        plugin.publish_proxy_generations_for_test(&std::collections::HashMap::from([("p1", 2)]));
        plugin.write_lifecycle_state_for_test("p1", 2);
        assert!(plugin.has_lifecycle_state_for_generation_for_test("p1", 2));
        // Sweep is waiting to enter retain; it must not be able to take the lock.
        assert!(
            !plugin.try_retention_lock_for_test(),
            "commit retention guard must serialize the background ownership sweep"
        );
        lock_held_tx.send(()).unwrap();
        // Hold the lock until the sweep is observably blocked on it. The
        // try_lock check above already proved mutual exclusion; releasing
        // after the signal lets the sweep proceed against the latest map.
    });
    sweep.join().expect("ownership sweep thread");

    assert!(
        plugin.has_lifecycle_state_for_generation_for_test("p1", 2),
        "serialized sweep must retain against the latest published map"
    );
    assert!(
        !plugin.has_lifecycle_state_for_generation_for_test("p1", 1),
        "serialized sweep may still prune the retired generation"
    );
}

#[test]
fn concurrent_commit_retain_and_sweep_preserve_final_generation() {
    let plugin = std::sync::Arc::new(ProxyAlerts::new(&minimal_config(), http_client()).unwrap());
    plugin.retain_proxies(&std::collections::HashMap::from([("p1", 1)]));
    plugin.write_lifecycle_state_for_test("p1", 1);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let commit_plugin = std::sync::Arc::clone(&plugin);
    let commit_barrier = std::sync::Arc::clone(&barrier);
    let commit = std::thread::spawn(move || {
        commit_barrier.wait();
        for generation in 2u64..=32 {
            commit_plugin.retain_proxies(&std::collections::HashMap::from([("p1", generation)]));
            commit_plugin.write_lifecycle_state_for_test("p1", generation);
        }
    });
    let sweep_plugin = std::sync::Arc::clone(&plugin);
    let sweep_barrier = std::sync::Arc::clone(&barrier);
    let sweep = std::thread::spawn(move || {
        sweep_barrier.wait();
        for _ in 0..64 {
            sweep_plugin.sweep_lifecycle_ownership_for_test();
        }
    });
    barrier.wait();
    commit.join().expect("commit retain thread");
    sweep.join().expect("sweep thread");

    plugin.sweep_lifecycle_ownership_for_test();
    assert!(
        plugin.has_lifecycle_state_for_generation_for_test("p1", 32),
        "latest published generation rows must survive interleaved retain/sweep"
    );
    assert!(!plugin.has_lifecycle_state_for_generation_for_test("p1", 1));
}

#[test]
fn generation_map_shares_cooldown_atomic_across_concurrent_acquires() {
    // Compact generation storage must keep concurrent same-generation writers
    // on one AtomicU64 (no lost inserts / duplicate rows).
    let gate = std::sync::Arc::new(CooldownGate::new());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let gate = std::sync::Arc::clone(&gate);
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            gate.try_acquire(1, "p1", 10, 60_000, 100, 7)
        }));
    }
    let successes: usize = handles
        .into_iter()
        .map(|handle| usize::from(handle.join().expect("cooldown acquire thread")))
        .sum();
    assert_eq!(
        successes, 1,
        "one shared cooldown atomic must admit exactly one acquire at now_ms=100"
    );
    assert!(gate.contains_proxy_generation("p1", 7));
    assert!(!gate.try_acquire(1, "p1", 10, 60_000, 100 + 1, 7));
}

#[test]
fn stream_duration_percentile_observes_monotonic_producer_duration() {
    // End-to-end: upstream summaries carry Instant/mono-derived duration_ms
    // even when civil-clock disconnect precedes connect (wall rollback).
    // proxy_alerts must sample that duration unchanged for stream_duration_ms.
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "slow_stream", "type": "latency_percentile",
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

    let connected = Utc.with_ymd_and_hms(2026, 7, 21, 12, 0, 0).unwrap();
    let disconnected = connected - chrono::Duration::hours(1);
    let summary = StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "udp-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("udp".to_string()),
        client_ip: "10.0.0.9".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.50:5353".to_string(),
        backend_resolved_ip: Some("10.0.0.50".to_string()),
        protocol: "udp".to_string(),
        listen_port: 5353,
        duration_ms: 1_500.0,
        bytes_sent: 32,
        bytes_received: 64,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: connected.to_rfc3339(),
        timestamp_disconnected: disconnected.to_rfc3339(),
        sni_hostname: None,
        metadata: Default::default(),
    };

    let observation = parsed.rules[0]
        .observe(SampleInput::Stream(&summary), &store, 1_000)
        .expect("stream sample should apply");
    assert!(
        observation.breach,
        "1500ms mono duration must breach 1000ms"
    );
    assert_eq!(observation.sample_count, 1);

    // TCP-parity WebSocket sample with the same mono duration / wall skew.
    let ws = WsDisconnectContext {
        namespace: "ferrum".to_string(),
        proxy_id: "ws-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("ws".to_string()),
        client_ip: "10.0.0.8".to_string(),
        backend_target: "ws://backend".to_string(),
        listen_port: 443,
        duration_ms: 1_500.0,
        frames_client_to_backend: 1,
        frames_backend_to_client: 1,
        bytes_client_to_backend: 0,
        bytes_backend_to_client: 0,
        timestamp_connected: connected.to_rfc3339(),
        timestamp_disconnected: disconnected.to_rfc3339(),
        direction: None,
        io_side: None,
        error_class: None,
        consumer_username: None,
        auth_method: None,
        connection_id: 0,
        metadata: Default::default(),
    };
    let ws_observation = parsed.rules[0]
        .observe(SampleInput::WebSocket(&ws), &store, 2_000)
        .expect("websocket sample should apply");
    assert!(ws_observation.breach);
    assert_eq!(ws_observation.sample_count, 1);
}

// ---------------------------------------------------- gRPC status count/rate

fn grpc_summary(
    proxy_id: &str,
    grpc_status: Option<&str>,
    streamed: bool,
    body_completed: bool,
    rejection: bool,
) -> TransactionSummary {
    let mut summary = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some("grpc-api".to_string()),
        response_status_code: 200,
        response_streamed: streamed,
        body_completed,
        ..TransactionSummary::default()
    };
    summary
        .metadata
        .insert("request_protocol".to_string(), "grpc".to_string());
    if let Some(status) = grpc_status {
        summary
            .metadata
            .insert("grpc_status".to_string(), status.to_string());
    }
    if rejection {
        summary
            .metadata
            .insert("rejection_phase".to_string(), "authorize".to_string());
    }
    summary
}

#[test]
fn rejects_out_of_range_grpc_status_selector() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "bad",
            "type": "grpc_status_count",
            "grpc_statuses": [17],
            "threshold_count": 1,
            "channels": ["c"]
        }]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(
        err.contains("not in [0, 16]") && err.contains("OTHER"),
        "got: {err}"
    );
}

#[test]
fn rejects_unknown_grpc_status_selector_string() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "bad",
            "type": "grpc_status_count",
            "grpc_statuses": ["UNAVAILABLE"],
            "threshold_count": 1,
            "channels": ["c"]
        }]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown 'grpc_statuses' entry"), "got: {err}");
}

#[test]
fn rejects_lowercase_other_grpc_status_selector_to_match_openapi() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "bad",
            "type": "grpc_status_count",
            "grpc_statuses": ["other"],
            "threshold_count": 1,
            "channels": ["c"]
        }]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown 'grpc_statuses' entry"), "got: {err}");
}

#[test]
fn grpc_status_count_keeps_http_status_distinct_across_shapes() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "grpc_failures",
            "type": "grpc_status_count",
            "grpc_statuses": [14, 13, 16, "OTHER"],
            "threshold_count": 1,
            "channels": ["c"]
        }]
    }))
    .unwrap();

    for (case, status, streamed, body_completed, rejection, expect_match) in [
        ("buffered_h2_ok", Some("0"), false, true, false, false),
        (
            "buffered_h2_unavailable",
            Some("14"),
            false,
            true,
            false,
            true,
        ),
        (
            "trailers_only_internal",
            Some("13"),
            false,
            true,
            false,
            true,
        ),
        ("streamed_h2_ok", Some("0"), true, true, false, false),
        (
            "streamed_h2_unavailable",
            Some("14"),
            true,
            true,
            false,
            true,
        ),
        ("native_h3_ok", Some("0"), true, true, false, false),
        ("native_h3_internal", Some("13"), true, true, false, true),
        (
            "bridge_h3_unauthenticated",
            Some("16"),
            true,
            true,
            false,
            true,
        ),
        ("gateway_rejection", Some("16"), false, true, true, true),
        ("missing_terminal_unknown", None, true, true, false, false),
        ("malformed_other", Some("bad"), true, true, false, true),
    ] {
        let specs = parsed
            .rules
            .iter()
            .map(|r| (r.id(), r.window_spec()))
            .collect();
        let store = WindowStore::new(specs);
        let summary = grpc_summary("p1", status, streamed, body_completed, rejection);
        assert_eq!(
            summary.response_status_code, 200,
            "{case}: HTTP status must stay 200"
        );
        let expected_status = match status {
            Some(value) => value.parse::<u32>().unwrap_or(u32::MAX),
            None => 2, // missing terminal on known gRPC → UNKNOWN
        };
        assert_eq!(
            summary.grpc_status(),
            Some(expected_status),
            "{case}: authoritative grpc_status contract"
        );
        let observation = parsed.rules[0]
            .observe(SampleInput::Http(&summary), &store, 1_000)
            .expect("http/gRPC sample should apply");
        assert_eq!(
            observation.breach, expect_match,
            "{case}: breach={} expected={expect_match}",
            observation.breach
        );
        assert_eq!(
            observation.sample_count,
            if expect_match { 1 } else { 0 },
            "{case}: matched count"
        );
        let rendered = observation.render(&parsed.rules[0]);
        assert!(
            rendered.reason.contains("gRPC transactions"),
            "{case}: reason should name gRPC, got {}",
            rendered.reason
        );
    }

    // Plain HTTP 500 never matches a gRPC-status selector.
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let plain = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        response_status_code: 500,
        ..TransactionSummary::default()
    };
    let plain_obs = parsed.rules[0]
        .observe(SampleInput::Http(&plain), &store, 1_000)
        .expect("plain HTTP still ages the count window");
    assert!(!plain_obs.breach);
    assert_eq!(plain_obs.sample_count, 0);
    assert!(plain.grpc_status().is_none());
}

#[test]
fn grpc_status_rate_uses_grpc_only_denominator_and_respects_min_count() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "grpc_error_rate",
            "type": "grpc_status_rate",
            "grpc_statuses": [14],
            "threshold_percent": 50.0,
            "min_request_count": 4,
            "channels": ["c"]
        }]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);

    // Three UNAVAILABLE + one OK would be 75%, but min_request_count=4 needs
    // a fourth gRPC sample before breach can fire.
    for (idx, status) in ["14", "14", "14"].into_iter().enumerate() {
        let summary = grpc_summary("p1", Some(status), idx % 2 == 0, true, false);
        let obs = parsed.rules[0]
            .observe(SampleInput::Http(&summary), &store, 1_000 + idx as u64)
            .unwrap();
        assert!(
            !obs.breach,
            "below min_request_count must not breach (sample {})",
            idx + 1
        );
    }

    // Plain HTTP must not dilute or satisfy the denominator.
    let plain = TransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: Some("p1".to_string()),
        response_status_code: 200,
        ..TransactionSummary::default()
    };
    let after_plain = parsed.rules[0]
        .observe(SampleInput::Http(&plain), &store, 5_000)
        .unwrap();
    assert_eq!(after_plain.sample_count, 3);
    assert!(!after_plain.breach);

    let fourth = grpc_summary("p1", Some("0"), true, true, false);
    let breached = parsed.rules[0]
        .observe(SampleInput::Http(&fourth), &store, 6_000)
        .unwrap();
    assert_eq!(breached.sample_count, 4);
    assert!(
        breached.breach,
        "3/4 UNAVAILABLE (75%) must breach 50% once min_request_count is met"
    );
    let rendered = breached.render(&parsed.rules[0]);
    assert!(rendered.observed.contains('%'));
    assert!(rendered.reason.contains("3/4"));
}

#[test]
fn grpc_status_count_zero_ok_can_be_selected_explicitly() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "grpc_ok_spike",
            "type": "grpc_status_count",
            "grpc_statuses": [0],
            "threshold_count": 2,
            "channels": ["c"]
        }]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);

    let first = grpc_summary("p1", Some("0"), false, true, false);
    let obs1 = parsed.rules[0]
        .observe(SampleInput::Http(&first), &store, 1_000)
        .unwrap();
    assert!(!obs1.breach);
    assert_eq!(obs1.sample_count, 1);

    let second = grpc_summary("p1", Some("0"), true, true, false);
    let obs2 = parsed.rules[0]
        .observe(SampleInput::Http(&second), &store, 2_000)
        .unwrap();
    assert!(obs2.breach);
    assert_eq!(obs2.sample_count, 2);

    let fail = grpc_summary("p1", Some("14"), true, true, false);
    let obs3 = parsed.rules[0]
        .observe(SampleInput::Http(&fail), &store, 3_000)
        .unwrap();
    assert!(obs3.breach);
    assert_eq!(
        obs3.sample_count, 2,
        "non-OK must not increase an OK-only matched count"
    );
}

#[test]
fn grpc_status_rules_ignore_stream_and_websocket_samples() {
    let parsed = ferrum_edge::plugins::proxy_alerts::config::ProxyAlertsConfig::parse(&json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            {
                "name": "count",
                "type": "grpc_status_count",
                "grpc_statuses": [14],
                "threshold_count": 1,
                "channels": ["c"]
            },
            {
                "name": "rate",
                "type": "grpc_status_rate",
                "grpc_statuses": [14],
                "threshold_percent": 1.0,
                "min_request_count": 1,
                "channels": ["c"]
            }
        ]
    }))
    .unwrap();
    let specs = parsed
        .rules
        .iter()
        .map(|r| (r.id(), r.window_spec()))
        .collect();
    let store = WindowStore::new(specs);
    let stream = StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-1".to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: Some("tcp".to_string()),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "10.0.0.2:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 9000,
        duration_ms: 10.0,
        bytes_sent: 0,
        bytes_received: 0,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
        timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
        sni_hostname: None,
        metadata: Default::default(),
    };
    assert!(
        parsed.rules[0]
            .observe(SampleInput::Stream(&stream), &store, 1_000)
            .is_none()
    );
    assert!(
        parsed.rules[1]
            .observe(SampleInput::Stream(&stream), &store, 1_000)
            .is_none()
    );
    assert!(!parsed.rules[0].observes_ws_disconnect());
    assert!(!parsed.rules[1].observes_ws_disconnect());
}

#[test]
fn grpc_status_count_trigger_and_resolve_via_recovery_gate() {
    let gate = RecoveryGate::new();
    // Trigger on breach.
    assert_eq!(
        gate.observe(1, "grpc-p", true, 60_000, 1_000, 0),
        LifecycleOutcome::Trigger
    );
    // Still active while above threshold.
    assert_eq!(
        gate.observe(1, "grpc-p", true, 60_000, 2_000, 0),
        LifecycleOutcome::StillActive
    );
    // Drop below threshold → recovering, then resolve after quiet window.
    assert_eq!(
        gate.observe(1, "grpc-p", false, 60_000, 3_000, 0),
        LifecycleOutcome::EnteringRecovery
    );
    assert_eq!(
        gate.observe(1, "grpc-p", false, 60_000, 63_000, 0),
        LifecycleOutcome::Resolve
    );
}

#[tokio::test]
async fn grpc_status_http_only_rules_do_not_opt_into_websocket_disconnect_hook() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [{
            "name": "grpc_failures",
            "type": "grpc_status_count",
            "grpc_statuses": [14],
            "threshold_count": 1,
            "channels": ["c"]
        }]
    });
    let plugin = ProxyAlerts::new(&cfg, http_client()).unwrap();
    assert!(!plugin.requires_ws_disconnect_hooks());
}
