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
