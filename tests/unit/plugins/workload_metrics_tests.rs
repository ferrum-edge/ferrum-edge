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
        &json!({"custom_env_tags": {"region": "FERRUM_TEST_REGION"}}),
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
                "custom_header_tags": {"region": "x-region"}
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
        (json!({"direction_emit": {"unused": true}}), true),
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
            "agent_url": "http://localhost:8126", "service": null
        }}),
        json!({"kind": "lightstep", "config": {
            "collector_url": "https://example.com/v1/traces", "accessTokenEnv": "LIGHTSTEP_TOKEN"
        }}),
    ] {
        cases.push((
            json!({"tracing_provider": selected, "span_reporting_disabled": true}),
            true,
        ));
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
