//! Config contracts for logging, metrics, tracing, alerting, and chargeback
//! built-ins (issue #6616 sweep).
//!
//! Flat-config plugins (`ws_frame_logging`, `prometheus_metrics`,
//! `__mesh_bpf_metrics`) have no nested object and use the default contract.
use ferrum_edge::plugins::PluginConfigContract;
use serde_json::{Value, json};

/// A transaction-summary log schema that populates every nested object the
/// shared compiler (`src/plugins/utils/log_schema/`) reads: `metadata`,
/// `derived_fields[]`, and each `transforms.<field>` spec.
fn transaction_schema() -> Value {
    json!({
        "summary_type": "http",
        "omit": ["request_user_agent"],
        "rename": {"proxy_id": "route_id"},
        "static_fields": {"source": "ferrum-edge"},
        "derived_fields": [{"name": "status_family", "kind": "status_class"}],
        "metadata": {"mode": "flatten", "prefix": "meta_", "on_collision": "skip"},
        "timestamp_format": "rfc3339",
        "transforms": {
            "client_ip": {"type": "ip_prefix", "ipv4_bits": 24, "ipv6_bits": 48},
            "request_path": {"type": "truncate", "max_bytes": 64}
        }
    })
}

pub(super) fn contract(name: &str) -> Option<PluginConfigContract> {
    Some(match name {
        "transaction_log_schema" => PluginConfigContract::closed(vec![json!({
            "schemas": {
                "rich": transaction_schema(),
                "plain": {"summary_type": "both"}
            }
        })])
        // `schemas` is keyed by operator-chosen schema names; `static_fields`
        // keys are operator-chosen output field names.
        .with_free_form_objects(&["schemas", "schemas.*.static_fields"]),
        "stdout_logging" => PluginConfigContract::closed(vec![
            json!({
                "filter": {"status_code_min": 400, "min_latency_ms": 10, "errors_only": false},
                "sampling": {"rate": 0.5, "always_log_errors": true},
                "schema": transaction_schema()
            }),
            json!({
                "filter": {
                    "expression": {
                        "op": "or",
                        "left": {
                            "op": "and",
                            "left": {"op": "status_code_min", "value": 500},
                            "right": {"op": "min_latency_ms", "value": 100}
                        },
                        "right": {"op": "errors_only"}
                    }
                }
            }),
        ])
        // `static_fields` keys are operator-chosen output field names.
        .with_free_form_objects(&["schema.static_fields"]),
        "http_logging" => PluginConfigContract::closed(vec![json!({
            "endpoint_url": "http://127.0.0.1:9200/logs",
            "custom_headers": {"X-Tenant": "acme"},
            "schema": transaction_schema()
        })])
        // Header names and `static_fields` output names are operator-chosen.
        .with_free_form_objects(&["custom_headers", "schema.static_fields"]),
        "tcp_logging" => PluginConfigContract::closed(vec![json!({
            "host": "127.0.0.1",
            "port": 5140,
            "schema": transaction_schema()
        })])
        // `static_fields` keys are operator-chosen output field names.
        .with_free_form_objects(&["schema.static_fields"]),
        "udp_logging" => PluginConfigContract::closed(vec![json!({
            "host": "127.0.0.1",
            "port": 9514,
            "schema": transaction_schema()
        })])
        // `static_fields` keys are operator-chosen output field names.
        .with_free_form_objects(&["schema.static_fields"]),
        "kafka_logging" => PluginConfigContract::closed(vec![json!({
            "broker_list": "127.0.0.1:9092",
            "topic": "ferrum-logs",
            "producer_config": {"linger.ms": "50"},
            "schema": transaction_schema()
        })])
        // `static_fields` keys are operator-chosen output field names.
        // `producer_config` stays probed: an unknown librdkafka property is
        // refused at admission (string-typed values, `rd_kafka_conf_set`).
        .with_free_form_objects(&["schema.static_fields"]),
        "ws_logging" => PluginConfigContract::closed(vec![json!({
            "endpoint_url": "ws://127.0.0.1:9300/logs",
            "custom_headers": {"X-Tenant": "acme"},
            "schema": transaction_schema()
        })])
        // Header names and `static_fields` output names are operator-chosen.
        .with_free_form_objects(&["custom_headers", "schema.static_fields"]),
        "statsd_logging" => PluginConfigContract::closed(vec![json!({
            "host": "127.0.0.1",
            "port": 8125,
            "global_tags": {"env": "prod"},
            "schema": transaction_schema()
        })])
        // Tag keys and `static_fields` output names are operator-chosen.
        .with_free_form_objects(&["global_tags", "schema.static_fields"]),
        "loki_logging" => PluginConfigContract::closed(vec![json!({
            "endpoint_url": "http://127.0.0.1:3100/loki/api/v1/push",
            "labels": {"env": "prod"},
            "custom_headers": {"X-Scope-OrgID": "tenant-a"},
            "schema": transaction_schema()
        })])
        // Loki label names, header names, and `static_fields` output names are
        // operator-chosen.
        .with_free_form_objects(&["labels", "custom_headers", "schema.static_fields"]),
        "transaction_debugger" => PluginConfigContract::closed(vec![json!({
            "schema": {
                "summary_type": "http",
                "omit": ["latency_plugin_ms"],
                "rename": {"path": "http.url"},
                "static_fields": {"service": "ferrum-edge"},
                "derived_fields": [{"name": "status_group", "kind": "status_class"}],
                "metadata": {"mode": "flatten", "prefix": "meta."}
            }
        })])
        // `static_fields` keys are operator-chosen output field names.
        .with_free_form_objects(&["schema.static_fields"]),
        "otel_tracing" => PluginConfigContract::closed(vec![json!({
            "endpoint": "http://127.0.0.1:4318/v1/traces",
            "headers": {"x-tenant": "acme"}
        })])
        // Export header names are operator-chosen.
        .with_free_form_objects(&["headers"]),
        "proxy_alerts" => PluginConfigContract::closed(vec![json!({
            "quiet_hours_utc": [{"from": "22:00", "to": "06:00", "weekdays": [0, 6]}],
            "channels": {
                "ops": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x",
                    "channel_override": "#ops",
                    "username": "ferrum",
                    "icon_emoji": ":rotating_light:"
                },
                "teams": {"type": "teams", "webhook_url": "https://example.com/teams"},
                "discord": {
                    "type": "discord",
                    "webhook_url": "https://example.com/discord",
                    "username": "ferrum"
                },
                "hook": {
                    "type": "webhook",
                    "url": "https://example.com/hooks",
                    "method": "POST",
                    "headers": {"X-Routing-Key": "rk"},
                    "body_template": "{\"ok\":true}"
                },
                "mail": {
                    "type": "email",
                    "smtp_host": "smtp.example.com",
                    "from": "ferrum@example.com",
                    "to": ["oncall@example.com"]
                }
            },
            "rules": [
                {
                    "name": "r1", "type": "error_rate", "status_codes": [500, 503],
                    "threshold_percent": 5.0, "min_request_count": 10,
                    "window_seconds": 60, "cooldown_seconds": 300, "severity": "high",
                    "channels": ["ops", "hook"],
                    "recovery": {"resolved_window_seconds": 300}
                },
                {
                    "name": "r2", "type": "status_code_count", "status_codes": [401, 403],
                    "threshold_count": 100, "channels": ["teams"]
                },
                {
                    "name": "r3", "type": "latency_percentile", "metric": "backend_total_ms",
                    "percentile": 95, "threshold_ms": 1000, "channels": ["discord"],
                    "recovery": {"resolved_window_seconds": 120}
                },
                {
                    "name": "r4", "type": "error_class",
                    "classes": ["connection_refused", "tls_error"],
                    "threshold_count": 10, "channels": ["mail"]
                },
                {
                    "name": "r5", "type": "stream_disconnect_cause", "causes": ["backend_error"],
                    "threshold_count": 5, "channels": ["ops"]
                },
                {
                    "name": "r6", "type": "grpc_status_count", "grpc_statuses": [14, "OTHER"],
                    "threshold_count": 10, "channels": ["ops"]
                },
                {
                    "name": "r7", "type": "grpc_status_rate", "grpc_statuses": [13, 14],
                    "threshold_percent": 5.0, "min_request_count": 10, "channels": ["ops"]
                }
            ]
        })])
        // `channels` is keyed by operator-chosen channel names; webhook
        // `headers` is keyed by HTTP header names.
        .with_free_form_objects(&["channels", "channels.*.headers"]),
        "workload_metrics" => PluginConfigContract::closed(vec![
            json!({
                "node_id": "node-a",
                "topology": "sidecar",
                "namespace": "default",
                "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/reviews",
                "labels": {"app": "reviews"},
                "trusted_hbone_assertors": [
                    "ztunnel",
                    {"assertor": "waypoint", "scope": "same_namespace"}
                ],
                "trust_domain_aliases": ["cluster.local"],
                "sampling_percentage": 10.0,
                "custom_tags": {"team": "payments"},
                "custom_header_tags": {"region": "x-region"},
                "safe_tag_sources": ["x-region"],
                "metrics": {
                    "disabled_metrics": ["REQUEST_SIZE"],
                    "tag_overrides": [
                        {
                            "metric": "REQUEST_COUNT",
                            "name": "destination_service",
                            "operation": {"type": "set", "value": "reviews"}
                        },
                        {"name": "source_principal", "operation": {"type": "remove"}},
                        {
                            "metric": "REQUEST_DURATION",
                            "name": "source_workload",
                            "operation": {"type": "rename", "new_name": "source_app"}
                        },
                        {
                            "metric": "REQUEST_DURATION",
                            "name": "response_code",
                            "operation": {"type": "set_expr", "cel": "string(response.code)"}
                        },
                        {
                            "metric": "RESPONSE_SIZE",
                            "name": "destination_workload",
                            "operation": {
                                "type": "set_expr",
                                "expression": {
                                    "op": "has_then_else",
                                    "attribute": "request_host",
                                    "then_expr": {"op": "attribute", "name": "request_host"},
                                    "else_expr": {"op": "literal", "value": "unknown"}
                                }
                            }
                        }
                    ]
                },
                "tracing_providers": [
                    {"kind": "zipkin", "config": {"url": "http://127.0.0.1:9411/api/v2/spans"}},
                    {
                        "kind": "datadog",
                        "config": {"agent_url": "http://127.0.0.1:8126", "service": "reviews"}
                    },
                    {
                        "kind": "opentelemetry",
                        "config": {"endpoint": "http://127.0.0.1:4318/v1/traces"}
                    }
                ],
                "direction_emit": {"server": true, "client": true},
                "service_name": "reviews",
                "deployment_environment": "staging"
            }),
            // Singular provider variant (Lightstep's token reference is only
            // shape-checked while span reporting is disabled).
            json!({
                "tracing_provider": {
                    "kind": "lightstep",
                    "config": {
                        "collector_url": "https://example.com/v1/traces",
                        "access_token_env": "FERRUM_PLUGIN_SECRET_LIGHTSTEP_TOKEN"
                    }
                },
                "span_reporting_disabled": true
            }),
            // Mesh-injected conjunctive baggage gates.
            json!({
                "_effective_mesh_authz_baggage_gates": [{
                    "trusted_hbone_assertors": [
                        "waypoint",
                        {"assertor": "ztunnel", "scope": "same_namespace"}
                    ],
                    "trust_domain_aliases": ["cluster.local"]
                }]
            }),
        ])
        // Kubernetes label keys and custom tag names are operator-chosen.
        .with_free_form_objects(&["labels", "custom_tags", "custom_header_tags"]),
        "api_chargeback" => PluginConfigContract::closed(vec![json!({
            "currency": "USD",
            "pricing_tiers": [{"status_codes": [200, 201], "price_per_call": 0.001}],
            "bandwidth_pricing": {
                "price_per_byte_sent": 0.000001,
                "price_per_byte_received": 0.000001
            },
            "stream_connection_pricing": {"price_per_connection": 0.01},
            "schema": {
                "rename": {"proxy_id": "route_id"},
                "static_fields": {"ledger": "edge"},
                "derived_fields": [{"name": "record_kind", "kind": "summary_kind"}]
            }
        })])
        // `static_fields` keys are operator-chosen output field names.
        .with_free_form_objects(&["schema.static_fields"]),
        "api_chargeback_sink" => PluginConfigContract::closed(vec![json!({
            "clickhouse": {
                "url": "http://127.0.0.1:8123",
                "database": "default",
                "table": "ferrum_charge_events",
                "tls": {"verify_hostname": true},
                "insert_query_params": {"max_insert_block_size": "1048576"},
                "timeout_ms": 5000
            },
            "batch": {"size": 100},
            "retry": {"jitter": true},
            "spool": {"enabled": false},
            "snapshot": {"emit_zero_deltas": false},
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}],
            "bandwidth_pricing": {"price_per_byte_sent": 0.000001},
            "stream_connection_pricing": {"price_per_connection": 0.001},
            "schema": {
                "rename": {"proxy_id": "a_much_longer_destination_column_name"},
                "static_fields": {"ledger": "production-billing-ledger"},
                "derived_fields": [{"name": "status_group", "kind": "status_class"}]
            }
        })])
        // ClickHouse setting names and `static_fields` output names are
        // operator-chosen.
        .with_free_form_objects(&["clickhouse.insert_query_params", "schema.static_fields"]),
        _ => return None,
    })
}
