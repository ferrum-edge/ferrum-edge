use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugins::mesh::service_graph::global_service_graph;
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::{
    Plugin, RequestContext, TransactionSummary, log_with_mirror, validate_plugin_config,
};
use serde_json::{Value, json};

use super::plugin_utils::{make_plugin_config_with_json, make_proxy};

#[test]
fn malformed_fields_fail_constructor_and_shared_admin_admission() {
    let mut cases = vec![json!(null), json!(17), json!([]), json!("config")];
    for field in [
        "node_id",
        "topology",
        "namespace",
        "workload_spiffe_id",
        "service_name",
        "deployment_environment",
    ] {
        for value in [json!(null), json!(17), json!([]), json!({})] {
            cases.push(json!({field: value}));
        }
    }
    for field in [
        "labels",
        "custom_tags",
        "custom_header_tags",
        "custom_env_tags",
    ] {
        for value in [json!(null), json!([]), json!("tags"), json!({"region": 17})] {
            cases.push(json!({field: value}));
        }
    }
    for field in [
        "span_reporting_disabled",
        "disable_span_reporting",
        "disableSpanReporting",
    ] {
        for value in [json!("true"), json!(null), json!(1)] {
            cases.push(json!({field: value}));
        }
    }
    cases.push(json!({"span_reporting_disabled": true, "disableSpanReporting": "false"}));
    for field in [
        "batch_size",
        "flush_interval_ms",
        "buffer_capacity",
        "buffer_max_bytes",
        "max_retries",
        "retry_delay_ms",
    ] {
        for value in [json!(null), json!("1"), json!(1.5), json!(-1)] {
            cases.push(json!({field: value}));
        }
    }
    for config in cases {
        assert!(WorkloadMetrics::new(&config).is_err(), "{config}");
        assert!(
            validate_plugin_config("workload_metrics", &config).is_err(),
            "{config}"
        );
    }
}

#[test]
fn explicit_default_contracts_remain_accepted() {
    for config in [
        json!({}),
        json!({"direction_emit": null}),
        json!({"tracing_provider": null}),
        json!({"tracing_providers": null}),
        json!({"trusted_hbone_assertors": null, "trust_domain_aliases": null}),
        json!({"node_id": "", "workload_spiffe_id": " ", "labels": {}}),
        json!({"span_reporting_disabled": true}),
        json!({"disable_span_reporting": true}),
        json!({"disableSpanReporting": true}),
    ] {
        assert!(WorkloadMetrics::new(&config).is_ok(), "{config}");
    }
}

fn instance(id: &str, config: Value, scope: PluginScope) -> PluginConfig {
    make_plugin_config_with_json(id, "workload_metrics", config, scope, None)
}

fn cache(instances: Vec<PluginConfig>) -> PluginCache {
    let ids: Vec<_> = instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    PluginCache::new(&GatewayConfig {
        proxies: vec![
            make_proxy("p1", "/api", ids.clone()),
            make_proxy("p2", "/other", ids),
        ],
        plugin_configs: instances,
        ..Default::default()
    })
    .expect("workload metrics chain")
}

async fn annotate(plugins: &[Arc<dyn Plugin>], method: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), method.into(), "/api".into());
    for plugin in plugins {
        plugin.on_request_received(&mut ctx).await;
    }
    let mut headers = HashMap::from([("x-region".into(), "header".into())]);
    for plugin in plugins {
        plugin.before_proxy(&mut ctx, &mut headers).await;
    }
    ctx
}

#[tokio::test]
async fn effective_instances_record_one_graph_observation_with_final_grpc_status() {
    let unique = uuid::Uuid::new_v4().to_string();
    let mut expected = Vec::new();
    for (index, (count, scope, triggered, protocol, grpc_status, http_status, mirror)) in [
        (1, PluginScope::Global, false, "http", None, 200, false),
        (2, PluginScope::Global, false, "http", None, 503, false),
        (
            2,
            PluginScope::ProxyGroup,
            false,
            "grpc",
            Some("13"),
            200,
            false,
        ),
        (
            2,
            PluginScope::ProxyGroup,
            false,
            "grpc",
            Some("7"),
            200,
            false,
        ),
        (2, PluginScope::Global, false, "grpc", Some("0"), 200, false),
        (2, PluginScope::Global, false, "grpc", None, 200, false),
        (2, PluginScope::Global, true, "http", None, 200, false),
        (1, PluginScope::Global, true, "http", None, 200, false),
        (2, PluginScope::Global, false, "http", None, 503, true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut instances: Vec<_> = (0..count)
            .map(|number| instance(&format!("wm-{number}"), json!({}), scope.clone()))
            .collect();
        if triggered {
            instances[0].trigger = Some(
                serde_json::from_value(json!({"when": {"match": {"method": ["POST"]}}}))
                    .expect("method trigger"),
            );
        }
        if scope == PluginScope::ProxyGroup {
            instances.push(instance("replaced-global", json!({}), PluginScope::Global));
        }
        let cache = cache(instances);
        let plugins = cache.get_plugins("ferrum", "p1");
        assert_eq!(plugins.len(), count);
        let mut ctx = annotate(&plugins, "GET").await;
        let source = format!("{unique}-{index}");
        ctx.metadata
            .insert("mesh.source.workload".into(), source.clone());
        ctx.metadata
            .insert("request_protocol".into(), protocol.into());
        ctx.metadata.insert(
            "mesh.request_protocol".into(),
            if index == 3 { "grpc-web" } else { protocol }.into(),
        );
        if let Some(status) = grpc_status {
            // The terminal carrier is shared by native trailers, trailers-only
            // errors, and translated gRPC-Web replies.
            ctx.metadata.insert("grpc_status".into(), status.into());
        }
        let summary = TransactionSummary {
            metadata: ctx.metadata.clone(),
            response_status_code: http_status,
            latency_total_ms: 12.5,
            mirror,
            ..Default::default()
        };
        log_with_mirror(&plugins, &summary, &ctx).await;
        let mut requests = u64::from(!mirror && !(triggered && count == 1));
        if scope == PluginScope::ProxyGroup {
            let shared_plugins = cache.get_plugins("ferrum", "p2");
            log_with_mirror(&shared_plugins, &summary, &ctx).await;
            requests += 1;
        }
        let errors = requests
            * u64::from(http_status >= 500 || summary.grpc_status().is_some_and(|s| s != 0));
        expected.push((source, requests, errors));
    }
    // A final positive observation is a publication barrier for the preceding
    // zero-count cases; use unique edge labels so parallel suites cannot reset
    // or perturb this test's registry entries.
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(WorkloadMetrics::new(&json!({})).unwrap())];
    let mut ctx = annotate(&plugins, "GET").await;
    ctx.metadata
        .insert("mesh.source.workload".into(), unique.clone());
    let summary = TransactionSummary {
        metadata: ctx.metadata.clone(),
        response_status_code: 200,
        ..Default::default()
    };
    log_with_mirror(&plugins, &summary, &ctx).await;
    let snapshot = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = global_service_graph().snapshot();
            if snapshot
                .edges
                .iter()
                .any(|edge| edge.source_workload == unique)
            {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("service graph snapshot publication");
    for (source, requests, errors) in expected {
        let edge = snapshot
            .edges
            .iter()
            .find(|edge| edge.source_workload == source);
        if requests == 0 {
            assert!(edge.is_none(), "unexpected graph observation for {source}");
        } else {
            let edge = edge.expect("graph edge");
            assert_eq!(edge.requests_total, requests);
            assert_eq!(edge.errors_total, errors);
            assert_eq!(edge.duration_ms_total, 12.5 * requests as f64);
        }
    }
}

#[test]
fn effective_custom_tag_union_is_bounded_even_for_triggered_instances() {
    for conditional in [false, true] {
        let tags: serde_json::Map<String, Value> = (0..32)
            .map(|index| (format!("tag_{index}"), json!("value")))
            .collect();
        let first = instance("first", json!({"custom_tags": tags}), PluginScope::Global);
        let mut second = instance(
            "second",
            json!({"custom_header_tags": {"extra": "x-region"}}),
            PluginScope::Global,
        );
        if conditional {
            second.trigger = Some(
                serde_json::from_value(json!({"when": {"match": {"method": ["POST"]}}})).unwrap(),
            );
        }
        let config = GatewayConfig {
            proxies: vec![make_proxy("p1", "/api", vec![])],
            plugin_configs: vec![first, second],
            ..Default::default()
        };
        let error = PluginCache::new(&config).err().expect("aggregate tag cap");
        assert!(error.contains("effective custom tags exceed 32"));
        let mut overlapping = config;
        overlapping.plugin_configs[1].config = json!({"custom_header_tags": {"tag_0": "x-region"}});
        assert!(PluginCache::new(&overlapping).is_ok());
    }
}

#[tokio::test]
async fn custom_tags_compose_across_sources_hooks_and_skipped_instances() {
    let env = ferrum_edge::_test_support::workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"region": "FERRUM_TEST_REGION"},
            "safe_tag_sources": ["FERRUM_TEST_REGION"]
        }),
        |_| Ok("environment".into()),
    )
    .unwrap();
    let mut skipped = instance(
        "skipped",
        json!({"custom_tags": {"skipped": "hidden"}}),
        PluginScope::Global,
    );
    skipped.trigger =
        Some(serde_json::from_value(json!({"when": {"match": {"method": ["POST"]}}})).unwrap());
    let cache = cache(vec![skipped]);
    let mut plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(WorkloadMetrics::new(&json!({"custom_tags": {"first": "first"}})).unwrap()),
        Arc::new(env),
        Arc::new(
            WorkloadMetrics::new(&json!({
                "custom_tags": {"first": "later"},
                "custom_header_tags": {"region": "x-region"},
                "safe_tag_sources": ["x-region"]
            }))
            .unwrap(),
        ),
        Arc::new(WorkloadMetrics::new(&json!({})).unwrap()),
    ];
    plugins.extend(cache.get_plugins("ferrum", "p1").iter().cloned());
    let ctx = annotate(&plugins, "GET").await;
    let attributes = ferrum_edge::plugins::mesh::mesh_trace_attributes(&ctx.metadata);
    assert!(attributes.contains(&("first".into(), "later".into())));
    assert!(attributes.contains(&("region".into(), "header".into())));
    assert!(!attributes.iter().any(|(name, _)| name == "skipped"));
    assert_eq!(
        ctx.metadata["workload_metrics.trace_attributes"],
        "first,region"
    );
}

#[tokio::test]
async fn metrics_only_instances_preserve_shared_http_trace_context() {
    for metrics_only_index in 0..3 {
        for (incoming_headers, sampled) in [
            (json!({}), "true"),
            (
                json!({"traceparent": "00-abcdef1234567890abcdef1234567890-1234567890abcdef-01"}),
                "true",
            ),
            (
                json!({"traceparent": "00-abcdef1234567890abcdef1234567890-1234567890abcdef-00"}),
                "false",
            ),
            (
                json!({"b3": "abcdef1234567890abcdef1234567890-1234567890abcdef-1"}),
                "true",
            ),
            (
                json!({"b3": "abcdef1234567890abcdef1234567890-1234567890abcdef-0"}),
                "false",
            ),
        ] {
            let mut plugins = vec![
                WorkloadMetrics::new(&json!({"sampling_percentage": 100})).unwrap(),
                WorkloadMetrics::new(&json!({"sampling_percentage": 100})).unwrap(),
            ];
            plugins.insert(
                metrics_only_index,
                WorkloadMetrics::new(&json!({"custom_tags": {"region": "metrics-only"}})).unwrap(),
            );
            let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/api".into());
            ctx.headers = serde_json::from_value(incoming_headers).unwrap();
            for plugin in &plugins {
                plugin.on_request_received(&mut ctx).await;
            }
            let mut headers = ctx.headers.clone();
            for (index, plugin) in plugins.iter().enumerate() {
                let before = ctx.metadata.clone();
                plugin.before_proxy(&mut ctx, &mut headers).await;
                if index == metrics_only_index {
                    for key in ["trace_id", "span_id", "parent_span_id", "traceparent"] {
                        assert_eq!(ctx.metadata.get(key), before.get(key), "{key}");
                    }
                }
            }
            assert!(ctx.metadata.contains_key("trace_id"));
            assert!(ctx.metadata.contains_key("span_id"));
            assert_eq!(ctx.metadata["trace_sampled"], sampled);
            assert_eq!(ctx.metadata["region"], "metrics-only");
            assert_eq!(ctx.metadata["workload_metrics.trace_attributes"], "region");
        }
    }
}

#[test]
fn provider_operation_and_default_schema_matches_constructor_admission() {
    let spec: Value = serde_yaml::from_str(include_str!("../../../openapi.yaml")).unwrap();
    let schema = json!({
        "$ref": "#/components/schemas/WorkloadMetricsConfig",
        "components": spec["components"]
    });
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let provider = json!({
        "kind": "opentelemetry",
        "config": {"endpoint": "http://127.0.0.1:4318/v1/traces"}
    });
    let mut cases = vec![
        (json!({}), true),
        (json!(null), false),
        (json!({"span_reporting_disabled": "true"}), false),
        (json!({"labels": {"app": 17}}), false),
        (json!({"custom_tags": {"bad name": "value"}}), false),
        (
            json!({"custom_header_tags": {"region": "bad header"}}),
            false,
        ),
        (json!({"direction_emit": null}), true),
        (json!({"direction_emit": {"unused": true}}), false),
        (
            json!({"direction_emit": {"server": true, "clinet": true}}),
            false,
        ),
        (json!({"direction_emit": {"server": null}}), false),
        (
            json!({"tracing_provider": null, "tracing_providers": null}),
            true,
        ),
        (
            json!({"tracing_provider": {"ignored": true}, "tracing_providers": null}),
            true,
        ),
        (json!({"tracing_provider": {}}), false),
        (json!({"tracing_provider": provider}), true),
        (json!({"tracing_providers": [provider]}), true),
        (
            json!({"tracing_provider": {
                "kind": "opentelemetry",
                "config": {"endpoint": "http://127.0.0.1:4318/v1/traces"},
                "extra": true
            }}),
            false,
        ),
        (
            json!({"tracing_providers": [{
                "kind": "opentelemetry",
                "config": {"endpoint": "http://127.0.0.1:4318/v1/traces", "endpont": "x"}
            }]}),
            false,
        ),
        (json!({"metrics": {"tag_overides": []}}), false),
        (
            json!({"metrics": {"tag_overrides": [{
                "name": "source_workload", "operation": {"type": "remove"}, "metirc": "REQUEST_COUNT"
            }]}}),
            false,
        ),
        (
            json!({"tracing_provider": {"kind": "zipkin", "config": {}}}),
            false,
        ),
        (
            json!({"tracing_provider": {"kind": "unknown", "config": {}}}),
            false,
        ),
        (json!({"_effective_mesh_authz_baggage_gates": []}), false),
        (json!({"_effective_mesh_authz_baggage_gates": [{}]}), true),
        (
            json!({"_effective_mesh_authz_baggage_gates": vec![json!({}); 17]}),
            false,
        ),
        (
            json!({"_effective_mesh_authz_baggage_gates": [{
                "trusted_hbone_assertors": ["waypoint"], "trust_domain_aliases": null
            }]}),
            true,
        ),
    ];
    for operation in [
        json!({"type": "remove"}),
        json!({"type": "rename", "new_name": "source_app"}),
        json!({"type": "set", "value": "reviews"}),
        json!({"type": "set_expr", "cel": "string(response.code)"}),
        json!({"type": "set_expr", "expression": {"op": "literal", "value": "reviews"}}),
        json!({"type": "set_expr", "expression": {
            "op": "has_then_else", "attribute": "request_host",
            "then_expr": {"op": "attribute", "name": "request_host"},
            "else_expr": {"op": "literal", "value": "unknown"}
        }}),
    ] {
        cases.push((metric_operation(operation), true));
    }
    for operation in [
        json!({"type": "rename"}),
        json!({"type": "set"}),
        json!({"type": "set_expr"}),
        json!({"type": "set_expr", "expression": {}}),
        json!({"type": "set_expr", "expression": {"op": "attribute", "name": "response_code"}}),
        json!({"type": "set_expr", "expression": {"op": "literal", "value": "x", "extra": 1}}),
        // Operations are closed per `type`: unknown keys and keys another
        // operation reads are both refused rather than silently ignored.
        json!({"type": "remove", "typo": true}),
        json!({"type": "remove", "value": "reviews"}),
        json!({"type": "rename", "new_name": "source_app", "value": "reviews"}),
        json!({"type": "set", "value": "reviews", "new_name": "source_app"}),
        json!({"type": "set_expr", "cel": "string(response.code)", "value": "reviews"}),
        json!({
            "type": "set_expr",
            "cel": "string(response.code)",
            "expression": {"op": "literal", "value": "reviews"}
        }),
    ] {
        cases.push((metric_operation(operation), false));
    }
    cases.push((
        json!({"metrics": {"tag_overrides": [{
            "metric": null, "name": "source_workload", "operation": {"type": "remove"}
        }]}}),
        true,
    ));
    for (field, minimum, maximum) in [
        ("batch_size", 1, 10000),
        ("flush_interval_ms", 100, 600000),
        ("buffer_capacity", 1, 100000),
        ("buffer_max_bytes", 65536, 268435456),
        ("max_retries", 0, 10),
        ("retry_delay_ms", 0, 60000),
    ] {
        for value in [minimum, maximum] {
            cases.push((json!({"tracing_provider": provider, field: value}), true));
        }
        cases.push((
            json!({"tracing_provider": provider, field: maximum + 1}),
            false,
        ));
        cases.push((
            json!({"tracing_provider": provider, field: minimum - 1}),
            false,
        ));
        cases.push((json!({field: maximum + 1}), true));
        for alias in [
            "span_reporting_disabled",
            "disable_span_reporting",
            "disableSpanReporting",
        ] {
            cases.push((
                json!({"tracing_provider": provider, alias: true, field: maximum + 1}),
                true,
            ));
        }
    }
    for selected in [
        json!({"kind": "zipkin", "config": {"url": "https://example.com/api/v2/spans"}}),
        json!({"kind": "datadog", "config": {
            "agent_url": "http://127.0.0.1:8126", "service": null
        }}),
        json!({"kind": "lightstep", "config": {
            "collector_url": "https://example.com/v1/traces",
            "accessTokenEnv": "FERRUM_PLUGIN_SECRET_LIGHTSTEP_TOKEN"
        }}),
    ] {
        cases.push((
            json!({"tracing_provider": selected, "span_reporting_disabled": true}),
            true,
        ));
    }
    // The Lightstep bearer token may only come from the plugin-secret
    // namespace; any other variable (including gateway-owned `FERRUM_*`
    // secrets) is refused at admission, even while span reporting is disabled.
    for token_env in [
        "FERRUM_ADMIN_JWT_SECRET",
        "FERRUM_DB_URL",
        "LIGHTSTEP_TOKEN",
        "FERRUM_PLUGIN_SECRET_",
        "FERRUM_PLUGIN_SECRET_lowercase",
        "FERRUM_PLUGIN_SECRET_LIGHTSTEP_TOKEN_FILE",
    ] {
        for key in ["access_token_env", "accessTokenEnv"] {
            cases.push((
                json!({
                    "tracing_provider": {"kind": "lightstep", "config": {
                        "collector_url": "https://example.com/v1/traces",
                        key: token_env
                    }},
                    "span_reporting_disabled": true
                }),
                false,
            ));
        }
    }
    for (config, accepted) in cases {
        assert_eq!(validator.is_valid(&config), accepted, "schema: {config}");
        assert_eq!(
            WorkloadMetrics::new(&config).is_ok(),
            accepted,
            "constructor: {config}"
        );
    }
}

fn metric_operation(operation: Value) -> Value {
    json!({"metrics": {"tag_overrides": [{
        "metric": "REQUEST_COUNT", "name": "source_workload", "operation": operation
    }]}})
}

#[test]
fn standalone_documented_configuration_is_admitted() {
    let docs = include_str!("../../../docs/plugins.md");
    let section = docs.split("### `workload_metrics`").nth(1).unwrap();
    let yaml = section
        .split("```yaml\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(PluginCache::new(&config).is_ok());
    let spec: Value = serde_yaml::from_str(include_str!("../../../openapi.yaml")).unwrap();
    let schema = json!({
        "$ref": "#/components/schemas/WorkloadMetricsConfig",
        "components": spec["components"]
    });
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    assert!(validator.is_valid(&config.plugin_configs[0].config));
}

#[test]
fn unknown_effective_baggage_gate_keeps_index_and_withholds_supplied_key() {
    let unknown = "'MESH_GATE_KEY_MARKER`\"\\\n";
    let config = json!({
        "_effective_mesh_authz_baggage_gates": [{}, {unknown: "MESH_GATE_VALUE_MARKER"}]
    });
    let error = WorkloadMetrics::new(&config)
        .err()
        .expect("the unknown gate key must still be rejected");
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    for expected in [
        "workload_metrics",
        "`_effective_mesh_authz_baggage_gates[1]`",
        "unknown configuration key(s)",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected:?}: {rendered}"
        );
    }
    for withheld in ["MESH_GATE_KEY_MARKER", "MESH_GATE_VALUE_MARKER"] {
        assert!(
            !rendered.contains(withheld),
            "leaked {withheld}: {rendered}"
        );
    }
}

#[test]
fn exporter_diagnostics_keep_batch_bounds_and_later_provider_endpoint() {
    let provider = json!({
        "kind": "zipkin", "config": {"url": "https://collector-marker-5594.example/spans"}
    });
    let cases = [
        (
            json!({"tracing_provider": provider, "batch_size": 0}),
            vec!["workload_metrics", "`batch_size`", "must be between 1 and"],
        ),
        (
            json!({"tracing_providers": [provider, {
                "kind": "datadog", "config": {"agent_url": "https:///endpoint-marker-5594"}
            }]}),
            vec![
                "workload_metrics",
                "`tracing_providers[1].config`",
                "`agent_url`",
                "must include a hostname",
            ],
        ),
    ];
    for (config, expected) in cases {
        let error = WorkloadMetrics::new(&config)
            .err()
            .expect("invalid exporter config");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for fragment in expected {
            assert!(rendered.contains(fragment), "{rendered}");
        }
        for hidden in ["collector-marker-5594", "endpoint-marker-5594", "got: 0"] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}

/// Every tracing provider URL is screened for cleartext off a loopback IP
/// literal (configured spelling); the opt-in admits it and is typed always.
#[test]
fn tracing_provider_cleartext_needs_opt_in_off_loopback() {
    let provider = |kind: &str, url: &str| -> Value {
        match kind {
            "zipkin" => json!({"kind": "zipkin", "config": {"url": url}}),
            "datadog" => json!({"kind": "datadog", "config": {"agent_url": url}}),
            _ => json!({"kind": "opentelemetry", "config": {"endpoint": url}}),
        }
    };
    let build = |kind: &str, url: &str, opt_in: Option<Value>| {
        let mut config = json!({"tracing_providers": [provider(kind, url)]});
        if let Some(flag) = opt_in {
            config["allow_plaintext"] = flag;
        }
        WorkloadMetrics::new(&config)
    };
    // Lightstep shares the same endpoint screen but resolves its token from
    // the process environment first, so it is covered through the shared
    // validator rather than here.
    for kind in ["zipkin", "datadog", "opentelemetry"] {
        for (url, opt_in) in [
            ("http://collector.internal:9411/api", None),
            ("http://collector.internal:9411/api", Some(json!(false))),
            ("http://localhost:9411/api", None),
            ("http://127.1:9411/api", None),
            ("http://[0:0:0:0:0:0:0:1]:9411/api", None),
        ] {
            let error = match build(kind, url, opt_in.clone()) {
                Ok(_) => panic!("{kind} {url} {opt_in:?} must be refused"),
                Err(error) => error,
            };
            assert!(error.contains("allow_plaintext"), "{kind} {url}: {error}");
        }
        for (url, opt_in) in [
            ("http://collector.internal:9411/api", Some(json!(true))),
            ("http://127.0.0.1:9411/api", None),
            ("http://[::1]:9411/api", None),
            ("https://collector.internal/api", None),
        ] {
            assert!(
                build(kind, url, opt_in.clone()).is_ok(),
                "{kind} {url} {opt_in:?} must be admitted"
            );
        }
    }
    // Typed whenever supplied, even with no provider at all.
    for flag in [json!("yes"), Value::Null] {
        let error = match WorkloadMetrics::new(&json!({"allow_plaintext": flag})) {
            Ok(_) => panic!("non-boolean allow_plaintext must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("allow_plaintext"), "{error}");
    }
}

const WORKLOAD_METRICS_SOURCE: &str = include_str!("../../../src/plugins/mesh/workload_metrics.rs");

/// The production half of `workload_metrics.rs` (its inline test module and
/// everything after it excluded).
fn workload_metrics_production_source() -> &'static str {
    WORKLOAD_METRICS_SOURCE
        .split_once("#[cfg(test)]\nmod tests {")
        .map_or(WORKLOAD_METRICS_SOURCE, |(production, _)| production)
}

/// The text of `source` from `start` up to the first `end` after it.
fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("source must contain {start:?}"));
    let rest = &source[from..];
    let to = rest
        .find(end)
        .unwrap_or_else(|| panic!("{start:?} must be followed by {end:?}"));
    &rest[..to]
}

/// workload_metrics-SOL-2: propagation-only instances (span reporting
/// disabled, or no exporter) must decide BEFORE building a `SpanData`, not
/// build every sampled span's owned IDs and attributes and then drop it.
#[test]
fn inactive_span_export_is_checked_before_span_construction() {
    let source = workload_metrics_production_source();
    for (hook, builder) in [
        (
            "async fn log_span(",
            "SpanData::from_transaction_summary_with_kind(",
        ),
        (
            "async fn on_stream_disconnect(",
            "SpanData::from_stream_summary_with_kind(",
        ),
    ] {
        let before_builder = source_between(source, hook, builder);
        assert!(
            before_builder.contains("self.span_export_active()"),
            "{hook} must check span_export_active() before {builder}"
        );
    }
}

/// workload_metrics-MUSE-4: the instance-immutable disabled-metrics marker
/// and per-family tag-override plans (up to 16 KiB) are written only when the
/// stamped value differs, so the repeat stamp copies nothing.
#[test]
fn immutable_metric_plans_are_not_recopied_on_every_stamp() {
    let source = workload_metrics_production_source();
    let stamp = source_between(
        source,
        "fn apply_telemetry_metadata_with_probe<",
        "fn should_export_metadata<",
    );
    assert!(
        stamp.contains(
            "insert_metadata_if_changed(metadata, MESH_METRICS_DISABLED_METADATA, marker)"
        ),
        "disabled-metrics marker must use insert_metadata_if_changed"
    );
    assert!(
        stamp
            .contains("insert_metadata_if_changed(metadata, family.override_metadata_key(), plan)"),
        "tag-override plans must use insert_metadata_if_changed"
    );
    assert!(
        !stamp.contains("plan.clone()") && !stamp.contains("marker.clone()"),
        "no unconditional clone of the marker or plans"
    );
}

#[tokio::test]
async fn repeated_stamps_keep_metric_plans_byte_identical() {
    let plugin = WorkloadMetrics::new(&json!({
        "metrics": {
            "disabled_metrics": ["REQUEST_SIZE"],
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set", "value": "reviews"}
            }]
        }
    }))
    .expect("metric plan config");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    plugin.on_request_received(&mut ctx).await;
    let first = ctx.metadata.clone();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    for key in [
        "mesh.metrics.disabled",
        "mesh.metrics.request_count.tag_overrides",
    ] {
        assert!(first.contains_key(key), "{key} stamped");
        assert_eq!(first.get(key), ctx.metadata.get(key), "{key}");
    }
}

fn traceparent_parts(traceparent: &str) -> (String, String, String) {
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(parts.len(), 4, "{traceparent}");
    (
        parts[1].to_string(),
        parts[2].to_string(),
        parts[3].to_string(),
    )
}

fn b3_headers(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            name == "b3" || name.starts_with("x-b3-")
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    found.sort();
    found
}

/// workload_metrics-SOL-4: with a Zipkin provider, a fresh gateway root is
/// propagated as B3 (multi-header) beside W3C, carrying the same IDs and
/// sampling decision, so a B3-only backend joins the exported trace.
#[tokio::test]
async fn zipkin_provider_injects_the_active_span_as_b3() {
    let plugin = WorkloadMetrics::new(&json!({
        "sampling_percentage": 100.0,
        "tracing_providers": [{
            "kind": "zipkin",
            "config": {"url": "http://127.0.0.1:9411/api/v2/spans"}
        }]
    }))
    .expect("zipkin workload metrics");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let traceparent = headers.get("traceparent").expect("W3C context").clone();
    let (trace_id, span_id, flags) = traceparent_parts(&traceparent);
    assert_eq!(flags, "01");
    assert_eq!(
        b3_headers(&headers),
        vec![
            ("x-b3-sampled".to_string(), "1".to_string()),
            ("x-b3-spanid".to_string(), span_id),
            ("x-b3-traceid".to_string(), trace_id),
        ],
        "a fresh root has no parent and the request used no single header"
    );
}

/// workload_metrics-SOL-4: an incoming single-header `b3` is replaced by the
/// gateway span (with the caller's span as parent), not forwarded stale.
#[tokio::test]
async fn incoming_single_header_b3_is_replaced_with_the_gateway_span() {
    let plugin = WorkloadMetrics::new(&json!({"sampling_percentage": 100.0}))
        .expect("sampling workload metrics");
    let trace_id = "abcdef1234567890abcdef1234567890";
    let caller_span = "1234567890abcdef";
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::from([("b3".to_string(), format!("{trace_id}-{caller_span}-1"))]);
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let traceparent = headers.get("traceparent").expect("W3C context").clone();
    let (w3c_trace, gateway_span, _) = traceparent_parts(&traceparent);
    assert_eq!(w3c_trace, trace_id);
    assert_ne!(gateway_span, caller_span);
    assert_eq!(
        headers.get("b3").map(String::as_str),
        Some(format!("{trace_id}-{gateway_span}-1-{caller_span}").as_str())
    );
    assert_eq!(
        headers.get("x-b3-spanid").map(String::as_str),
        Some(gateway_span.as_str())
    );
    assert_eq!(
        headers.get("x-b3-parentspanid").map(String::as_str),
        Some(caller_span)
    );
}

/// workload_metrics-SOL-4: when W3C context wins over a conflicting stale
/// multi-header B3 copy, every casing of the stale copy is replaced by the
/// active span instead of pointing a B3-only backend at another trace.
#[tokio::test]
async fn stale_multi_header_b3_is_rewritten_from_the_active_w3c_span() {
    let plugin = WorkloadMetrics::new(&json!({"sampling_percentage": 100.0}))
        .expect("sampling workload metrics");
    let w3c_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    let w3c_parent = "00f067aa0ba902b7";
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::from([
        (
            "traceparent".to_string(),
            format!("00-{w3c_trace}-{w3c_parent}-01"),
        ),
        (
            "X-B3-TraceId".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        ("X-B3-SpanId".to_string(), "bbbbbbbbbbbbbbbb".to_string()),
        ("x-b3-sampled".to_string(), "0".to_string()),
        ("x-b3-flags".to_string(), "1".to_string()),
    ]);
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let traceparent = headers.get("traceparent").expect("W3C context").clone();
    let (trace_id, span_id, _) = traceparent_parts(&traceparent);
    assert_eq!(trace_id, w3c_trace);
    assert_eq!(
        b3_headers(&headers),
        vec![
            ("x-b3-parentspanid".to_string(), w3c_parent.to_string()),
            ("x-b3-sampled".to_string(), "1".to_string()),
            ("x-b3-spanid".to_string(), span_id),
            ("x-b3-traceid".to_string(), trace_id),
        ]
    );
}

/// Metrics-only instances own no trace context: B3 headers pass untouched.
#[tokio::test]
async fn metrics_only_instance_leaves_b3_headers_alone() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("metrics-only workload metrics");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let original = HashMap::from([(
        "b3".to_string(),
        "abcdef1234567890abcdef1234567890-1234567890abcdef-1".to_string(),
    )]);
    let mut headers = original.clone();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(b3_headers(&headers), b3_headers(&original));
    assert!(!headers.contains_key("traceparent"));
}
