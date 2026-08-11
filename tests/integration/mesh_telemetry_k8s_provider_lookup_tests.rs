use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshTracingConfig, TagOverrideOperation, TelemetryTracingMode, TracingProvider,
};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, TransactionSummary};
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn k8s_object(
    api_version: &str,
    kind: &str,
    name: &str,
    namespace: &str,
    spec: Value,
) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: Default::default(),
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn telemetry(spec: Value) -> K8sObject {
    k8s_object(
        "telemetry.istio.io/v1",
        "Telemetry",
        "sample",
        "default",
        spec,
    )
}

fn istio_mesh_config(mesh: &str) -> K8sObject {
    k8s_object(
        "v1",
        "ConfigMap",
        "istio",
        "istio-system",
        json!({
            "data": {
                "mesh": mesh,
            }
        }),
    )
}

fn translated_tracing(objects: &[K8sObject]) -> (MeshTracingConfig, Vec<String>) {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");
    let mesh = result.config.mesh.expect("mesh config");
    let tracing = mesh.telemetry_resources[0]
        .config
        .tracing
        .clone()
        .expect("tracing config");
    (tracing, result.warnings)
}

fn telemetry_translation_error(spec: Value) -> String {
    translate_k8s_objects(&[telemetry(spec)], options())
        .expect_err("Telemetry translation must fail")
        .to_string()
}

#[test]
fn k8s_telemetry_name_only_provider_resolves_from_mesh_config() {
    let (tracing, warnings) = translated_tracing(&[
        istio_mesh_config(
            r#"
extensionProviders:
- name: zipkin-prod
  zipkin:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
"#,
        ),
        telemetry(json!({
            "tracing": [{
                "providers": [{
                    "name": "zipkin-prod"
                }]
            }]
        })),
    ]);

    match tracing.providers.first().expect("provider translated") {
        TracingProvider::Zipkin { url } => {
            assert_eq!(
                url,
                "http://zipkin.istio-system.svc.cluster.local:9411/api/v2/spans"
            );
        }
        other => panic!("expected Zipkin provider, got {other:?}"),
    }
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn k8s_telemetry_default_provider_resolves_from_mesh_config() {
    let (tracing, warnings) = translated_tracing(&[
        istio_mesh_config(
            r#"
defaultProviders:
  tracing:
  - otel-default
extensionProviders:
- name: otel-default
  opentelemetry:
    service: otel-collector.istio-system.svc.cluster.local
    port: 4318
"#,
        ),
        telemetry(json!({
            "tracing": [{
                "randomSamplingPercentage": 37.5
            }]
        })),
    ]);

    assert_eq!(tracing.sampling_percentage, Some(37.5));
    match tracing
        .providers
        .first()
        .expect("default provider translated")
    {
        TracingProvider::OpenTelemetry { endpoint } => {
            assert_eq!(
                endpoint,
                "http://otel-collector.istio-system.svc.cluster.local:4318"
            );
        }
        other => panic!("expected OpenTelemetry provider, got {other:?}"),
    }
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn k8s_telemetry_missing_mesh_config_provider_warns_and_skips() {
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "providers": [{
                "name": "missing-provider"
            }]
        }]
    }))]);

    assert!(
        tracing.providers.is_empty(),
        "missing provider reference must not surface a tracing provider"
    );
    assert!(
        warnings.iter().any(|warning| warning.contains(
            "Telemetry default/sample references unknown meshConfig extensionProvider 'missing-provider'"
        )),
        "missing provider should emit an operator-visible warning: {warnings:?}"
    );
}

#[test]
fn k8s_telemetry_inline_provider_still_translates_without_mesh_config() {
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "providers": [{
                "name": "datadog",
                "agentUrl": "http://datadog-agent:8126",
                "service": "reviews"
            }]
        }]
    }))]);

    match tracing
        .providers
        .first()
        .expect("inline provider translated")
    {
        TracingProvider::Datadog { agent_url, service } => {
            assert_eq!(agent_url, "http://datadog-agent:8126");
            assert_eq!(service.as_deref(), Some("reviews"));
        }
        other => panic!("expected Datadog provider, got {other:?}"),
    }
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn k8s_telemetry_non_tracing_extension_provider_lookup_distinguishes_from_unknown() {
    // Operator declared an `envoyExtAuthzHttp` extensionProvider and then
    // mistakenly referenced it from Telemetry tracing. The warning must
    // distinguish "declared but not tracing" from "name not declared at all"
    // so the operator can locate the misconfiguration.
    let (tracing, warnings) = translated_tracing(&[
        istio_mesh_config(
            r#"
extensionProviders:
- name: ext-authz
  envoyExtAuthzHttp:
    service: authz.default.svc.cluster.local
    port: 9000
    scheme: https
"#,
        ),
        telemetry(json!({
            "tracing": [{
                "providers": [{
                    "name": "ext-authz"
                }]
            }]
        })),
    ]);

    assert!(
        tracing.providers.is_empty(),
        "non-tracing extensionProvider must not surface a tracing provider"
    );
    assert!(
        warnings.iter().any(|warning| warning.contains(
            "Telemetry default/sample references meshConfig extensionProvider 'ext-authz' which is declared but not a tracing provider type"
        )),
        "warning should distinguish declared-but-not-tracing from unknown: {warnings:?}"
    );
}

#[test]
fn k8s_telemetry_malformed_mesh_config_does_not_block_sibling_telemetry() {
    // A stray invalid-YAML edit in the istio ConfigMap must not silently
    // empty the registry and drop all Telemetry; the reconciler's
    // skip-retries fallback drops the bad ConfigMap and continues. An
    // inline-provider Telemetry resource still translates so the mesh
    // keeps emitting spans.
    use ferrum_edge::config_sources::k8s::{K8sTranslateError, translate_k8s_objects};

    let objects = vec![
        istio_mesh_config("not: valid: yaml"),
        telemetry(json!({
            "tracing": [{
                "providers": [{
                    "name": "datadog",
                    "agentUrl": "http://datadog-agent:8126",
                    "service": "reviews"
                }]
            }]
        })),
    ];

    // First pass surfaces the malformed ConfigMap as an InvalidResource
    // error so the reconciler can drop it on retry.
    let err = translate_k8s_objects(&objects, options())
        .expect_err("invalid mesh ConfigMap must surface as an error");
    match err {
        K8sTranslateError::InvalidResource { kind, name, .. } => {
            assert_eq!(kind, "ConfigMap");
            assert_eq!(name, "istio");
        }
        other => panic!("expected InvalidResource error, got {other:?}"),
    }

    // After the reconciler drops the bad ConfigMap, the Telemetry resource
    // still resolves through inline-provider translation — no provider
    // requires meshConfig because the spec carries its own config.
    let healthy = vec![objects[1].clone()];
    let translation = translate_k8s_objects(&healthy, options())
        .expect("sibling Telemetry must still translate after malformed ConfigMap is skipped");
    let mesh = translation.config.mesh.expect("mesh config emitted");
    let tracing = mesh.telemetry_resources[0]
        .config
        .tracing
        .clone()
        .expect("tracing config emitted");
    match tracing.providers.first().expect("inline provider emitted") {
        TracingProvider::Datadog { agent_url, .. } => {
            assert_eq!(agent_url, "http://datadog-agent:8126");
        }
        other => panic!("expected Datadog inline provider, got {other:?}"),
    }
}

#[test]
fn k8s_telemetry_match_mode_client_preserves_client_only_entries() {
    // Before GAP-3F, the translator silently dropped CLIENT-only Telemetry
    // entries because Ferrum only emitted SERVER spans. The translator now
    // carries CLIENT through so the auto-injected workload_metrics plugin
    // can gate emission per-direction.
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "match": { "mode": "CLIENT" },
            "providers": [{
                "name": "zipkin",
                "url": "http://zipkin:9411/api/v2/spans"
            }],
            "randomSamplingPercentage": 12.5
        }],
    }))]);

    assert!(
        warnings.is_empty(),
        "no warnings for CLIENT-only tracing match.mode: {warnings:?}",
    );
    assert_eq!(tracing.mode, Some(TelemetryTracingMode::Client));
    assert_eq!(tracing.sampling_percentage, Some(12.5));
    assert!(
        !tracing.providers.is_empty(),
        "CLIENT-only entry must still surface its provider so propagation works",
    );
}

#[test]
fn k8s_telemetry_match_mode_client_and_server_carries_both_directions() {
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "match": { "mode": "CLIENT_AND_SERVER" },
            "providers": [{
                "name": "zipkin",
                "url": "http://zipkin:9411/api/v2/spans"
            }],
        }],
    }))]);

    assert!(warnings.is_empty(), "warnings: {warnings:?}");
    assert_eq!(tracing.mode, Some(TelemetryTracingMode::ClientAndServer));
}

#[test]
fn k8s_telemetry_match_mode_unset_resolves_to_server() {
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "providers": [{
                "name": "zipkin",
                "url": "http://zipkin:9411/api/v2/spans"
            }],
        }],
    }))]);

    assert!(warnings.is_empty(), "warnings: {warnings:?}");
    assert_eq!(tracing.mode, Some(TelemetryTracingMode::Server));
}

#[test]
fn k8s_telemetry_match_mode_server_plus_client_union_becomes_client_and_server() {
    let zipkin_provider = json!({
        "name": "zipkin",
        "url": "http://zipkin:9411/api/v2/spans"
    });
    let (tracing, _warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [
            { "match": { "mode": "SERVER" }, "providers": [zipkin_provider.clone()] },
            { "match": { "mode": "CLIENT" }, "providers": [zipkin_provider] }
        ],
    }))]);

    assert_eq!(tracing.mode, Some(TelemetryTracingMode::ClientAndServer));
}

#[tokio::test]
async fn translated_standard_metric_family_disable_and_override_are_live() {
    let translation = translate_k8s_objects(
        &[telemetry(json!({
            "metrics": [{
                "overrides": [
                    {
                        "match": {"metric": "REQUEST_SIZE"},
                        "disabled": true
                    },
                    {
                        "match": {"metric": "REQUEST_DURATION"},
                        "disabled": true
                    },
                    {
                        "match": {"metric": "TCP_SENT_BYTES"},
                        "tagOverrides": {
                            "source_workload": {
                                "operation": "UPSERT",
                                "value": "\"edge\""
                            }
                        }
                    }
                ]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");
    let metrics = translation
        .config
        .mesh
        .expect("mesh config")
        .telemetry_resources[0]
        .config
        .metrics
        .clone()
        .expect("metrics config");
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": serde_json::to_value(metrics).expect("serialize metrics")
    }))
    .expect("standard families construct");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    let disabled = ctx
        .metadata
        .get("mesh.metrics.disabled")
        .map(String::as_str)
        .expect("disabled marker");
    assert!(
        disabled.split(',').any(|n| n == "request_size"),
        "REQUEST_SIZE disable must stamp request_size: {disabled}"
    );
    assert!(
        disabled.split(',').any(|n| n == "request_duration"),
        "REQUEST_DURATION disable must stamp request_duration: {disabled}"
    );
    assert!(
        ctx.metadata
            .get("mesh.metrics.tcp_sent_bytes.tag_overrides")
            .is_some_and(|plan| plan.contains("s0,4:edge;")),
        "TCP_SENT_BYTES tag override must be stamped"
    );
}

#[tokio::test]
async fn translated_disabled_override_without_match_suppresses_all_mesh_metrics() {
    let translation = translate_k8s_objects(
        &[telemetry(json!({
            "metrics": [{
                "overrides": [{"disabled": true}]
            }]
        }))],
        options(),
    )
    .expect("disabled override without match defaults to ALL_METRICS");
    let metrics = translation
        .config
        .mesh
        .expect("mesh config")
        .telemetry_resources[0]
        .config
        .metrics
        .clone()
        .expect("metrics config");
    assert_eq!(metrics.disabled_metrics, vec!["ALL_METRICS"]);

    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
        "labels": {"app": "frontend"},
        "metrics": serde_json::to_value(metrics).expect("serialize metrics")
    }))
    .expect("translated ALL_METRICS policy");
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.disabled")
            .map(String::as_str),
        Some(
            "request_count,request_duration,request_size,response_size,tcp_opened_connections,tcp_closed_connections,tcp_sent_bytes,tcp_received_bytes,grpc_request_messages,grpc_response_messages"
        )
    );

    let registry = MetricsRegistry::new();
    registry.record(&TransactionSummary {
        namespace: "default".to_string(),
        timestamp_received: "2026-07-15T00:00:00Z".to_string(),
        client_ip: "10.0.0.2".to_string(),
        http_method: "GET".to_string(),
        request_path: "/".to_string(),
        proxy_id: Some("frontend".to_string()),
        response_status_code: 200,
        latency_total_ms: 12.0,
        latency_backend_total_ms: 8.0,
        metadata: ctx.metadata,
        ..TransactionSummary::default()
    });
    let output = registry.render_uncached();
    assert!(
        !output.contains("ferrum_mesh_requests_total{"),
        "ALL_METRICS must suppress the emitted counter family"
    );
    assert!(
        !output.contains("ferrum_mesh_request_duration_ms_bucket{"),
        "ALL_METRICS must suppress the emitted histogram family"
    );
    assert!(
        !output.contains("ferrum_mesh_request_bytes_"),
        "ALL_METRICS must suppress REQUEST_SIZE"
    );
    assert!(
        !output.contains("ferrum_mesh_response_bytes_"),
        "ALL_METRICS must suppress RESPONSE_SIZE"
    );
}

#[test]
fn workload_metrics_still_rejects_unknown_or_malformed_metric_policy() {
    let unknown = WorkloadMetrics::new(&json!({
        "metrics": {"disabled_metrics": ["NOT_AN_ISTIO_METRIC"]}
    }));
    let unknown_error = match unknown {
        Ok(_) => panic!("unknown metric family must be rejected"),
        Err(error) => error,
    };
    assert!(unknown_error.contains("unsupported disabled metric"));

    let malformed_translation = translate_k8s_objects(
        &[telemetry(json!({
            "metrics": [{
                "overrides": [{
                    "match": {"metric": 7},
                    "disabled": true
                }]
            }]
        }))],
        options(),
    )
    .expect_err("non-string Istio metric selector must be rejected");
    assert!(
        malformed_translation
            .to_string()
            .contains("match.metric must be a string")
    );

    let malformed = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": 7,
                "name": "source_workload",
                "operation": {"type": "remove"}
            }]
        }
    }));
    let malformed_error = match malformed {
        Ok(_) => panic!("non-string metric selector must be rejected"),
        Err(error) => error,
    };
    assert!(malformed_error.contains("must be a string"));
}

#[tokio::test]
async fn k8s_telemetry_header_default_is_fallback_and_present_header_wins() {
    let translation = translate_k8s_objects(
        &[telemetry(json!({
            "tracing": [{
                "customTags": {
                    "tenant": {
                        "header": {
                            "name": "x-tenant",
                            "defaultValue": "unknown"
                        }
                    }
                }
            }]
        }))],
        options(),
    )
    .expect("header custom tag with default translates");
    let tracing = translation
        .config
        .mesh
        .expect("mesh config")
        .telemetry_resources[0]
        .config
        .tracing
        .clone()
        .expect("tracing config");
    assert_eq!(
        tracing.custom_tags.get("tenant").map(String::as_str),
        Some("unknown")
    );
    assert_eq!(
        tracing.custom_header_tags.get("tenant").map(String::as_str),
        Some("x-tenant")
    );

    let plugin = WorkloadMetrics::new(&json!({
        "custom_tags": tracing.custom_tags,
        "custom_header_tags": tracing.custom_header_tags,
    }))
    .expect("translated custom tags construct workload_metrics");

    let mut absent_ctx =
        RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut absent_headers = HashMap::new();
    assert!(matches!(
        plugin
            .before_proxy(&mut absent_ctx, &mut absent_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        absent_ctx.metadata.get("tenant").map(String::as_str),
        Some("unknown")
    );

    let mut present_ctx =
        RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut present_headers = HashMap::from([("x-tenant".to_string(), "acme".to_string())]);
    assert!(matches!(
        plugin
            .before_proxy(&mut present_ctx, &mut present_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        present_ctx.metadata.get("tenant").map(String::as_str),
        Some("acme")
    );
}

#[tokio::test]
async fn k8s_telemetry_environment_tag_resolves_on_data_plane_not_controller() {
    const ENV_VAR: &str = "FERRUM_TEST_TELEMETRY_DP_ENV_TAG";

    let translation = translate_k8s_objects(
        &[telemetry(json!({
            "tracing": [{
                "customTags": {
                    "cluster": {
                        "environment": {
                            "name": ENV_VAR,
                            "defaultValue": "fallback-cluster"
                        }
                    },
                    "region": {
                        "environment": {
                            "name": "FERRUM_TEST_TELEMETRY_DP_ENV_TAG_MISSING"
                        }
                    }
                }
            }]
        }))],
        options(),
    )
    .expect("environment custom tags translate");
    let tracing = translation
        .config
        .mesh
        .expect("mesh config")
        .telemetry_resources[0]
        .config
        .tracing
        .clone()
        .expect("tracing config");

    assert_eq!(
        tracing.custom_tags.get("cluster").map(String::as_str),
        Some("fallback-cluster")
    );
    assert!(!tracing.custom_tags.contains_key("region"));
    assert_eq!(
        tracing.custom_env_tags.get("cluster").map(String::as_str),
        Some(ENV_VAR)
    );
    assert_eq!(
        tracing.custom_env_tags.get("region").map(String::as_str),
        Some("FERRUM_TEST_TELEMETRY_DP_ENV_TAG_MISSING")
    );

    // Translator must not resolve controller-host environment: only typed
    // lookups + optional defaults are carried for DP construction/reload.
    let missing_plugin = ferrum_edge::_test_support::workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_tags": tracing.custom_tags,
            "custom_env_tags": tracing.custom_env_tags,
        }),
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect("missing DP env keeps default / omits tag");

    let mut missing_ctx =
        RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();
    assert!(matches!(
        missing_plugin
            .before_proxy(&mut missing_ctx, &mut headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        missing_ctx.metadata.get("cluster").map(String::as_str),
        Some("fallback-cluster")
    );
    assert!(!missing_ctx.metadata.contains_key("region"));

    let present_plugin = ferrum_edge::_test_support::workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_tags": {
                "cluster": "fallback-cluster"
            },
            "custom_env_tags": {
                "cluster": ENV_VAR
            },
        }),
        |name| {
            if name == ENV_VAR {
                Ok("live-cluster".to_string())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    )
    .expect("present DP env overrides default at construction/reload");

    let mut present_ctx =
        RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        present_plugin
            .before_proxy(&mut present_ctx, &mut headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        present_ctx.metadata.get("cluster").map(String::as_str),
        Some("live-cluster")
    );

    let empty_plugin = ferrum_edge::_test_support::workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_tags": {
                "cluster": "fallback-cluster"
            },
            "custom_env_tags": {
                "cluster": ENV_VAR
            },
        }),
        |name| {
            if name == ENV_VAR {
                Ok(String::new())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    )
    .expect("empty but present env value is a resolved value");
    let mut empty_ctx =
        RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        empty_plugin
            .before_proxy(&mut empty_ctx, &mut headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        empty_ctx.metadata.get("cluster").map(String::as_str),
        Some("")
    );

    let oversized = ferrum_edge::_test_support::workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {
                "cluster": ENV_VAR
            },
        }),
        |name| {
            if name == ENV_VAR {
                Ok("x".repeat(1025))
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    );
    let oversized_err = oversized
        .err()
        .expect("oversized resolved env value fails closed");
    assert!(
        oversized_err.contains("exceeds 1024 bytes"),
        "got {oversized_err}"
    );
    // Do not assert the resolved secret/value appears in the error.
    assert!(!oversized_err.contains(&"x".repeat(32)));
    assert!(!oversized_err.contains(ENV_VAR));
}

#[test]
fn k8s_telemetry_rejects_workload_metrics_constructor_blackout_vectors() {
    let too_many_custom_tags = (0..33)
        .map(|index| {
            let tag = if index < 17 {
                json!({"literal": {"value": "v"}})
            } else {
                json!({"header": {"name": format!("x-tag-{index}")}})
            };
            (format!("tag_{index}"), tag)
        })
        .collect::<serde_json::Map<String, Value>>();
    let too_long_custom_tag_name = [("x".repeat(129), json!({"literal": {"value": "v"}}))]
        .into_iter()
        .collect::<serde_json::Map<String, Value>>();
    let oversized_custom_tag_value = "x".repeat(1025);
    let oversized_metric_literal =
        serde_json::to_string(&"x".repeat(257)).expect("serialize metric literal");
    let cases = vec![
        (
            "unsupported metric tag",
            json!({
                "metrics": [{
                    "overrides": [{
                        "match": {"metric": "REQUEST_COUNT"},
                        "tagOverrides": {
                            "request_host": {"operation": "UPSERT", "value": "\"edge\""}
                        }
                    }]
                }]
            }),
            "unsupported metric tag 'request_host'",
        ),
        (
            "oversized metric tag value",
            json!({
                "metrics": [{
                    "overrides": [{
                        "match": {"metric": "REQUEST_COUNT"},
                        "tagOverrides": {
                            "source_workload": {
                                "operation": "UPSERT",
                                "value": oversized_metric_literal
                            }
                        }
                    }]
                }]
            }),
            "metric tag 'source_workload' value exceeds 256 bytes",
        ),
        (
            "credential-bearing custom header",
            json!({
                "tracing": [{
                    "customTags": {
                        "tenant": {"header": {"name": "Authorization"}}
                    }
                }]
            }),
            "cannot copy sensitive header 'Authorization'",
        ),
        (
            "environment tag missing name",
            json!({
                "tracing": [{
                    "customTags": {
                        "cluster": {"environment": {"defaultValue": "x"}}
                    }
                }]
            }),
            "environment.name is required",
        ),
        (
            "environment tag invalid name",
            json!({
                "tracing": [{
                    "customTags": {
                        "cluster": {"environment": {"name": "BAD-NAME"}}
                    }
                }]
            }),
            "invalid environment variable name",
        ),
        (
            "invalid custom header name",
            json!({
                "tracing": [{
                    "customTags": {
                        "tenant": {"header": {"name": "bad header"}}
                    }
                }]
            }),
            "has invalid header name 'bad header'",
        ),
        (
            "combined custom tag count",
            json!({
                "tracing": [{"customTags": Value::Object(too_many_custom_tags)}]
            }),
            "custom tag count exceeds 32",
        ),
        (
            "custom tag name bound",
            json!({
                "tracing": [{
                    "customTags": Value::Object(too_long_custom_tag_name)
                }]
            }),
            "invalid custom tag name",
        ),
        (
            "custom tag value bound",
            json!({
                "tracing": [{
                    "customTags": {
                        "tenant": {"literal": {"value": oversized_custom_tag_value}}
                    }
                }]
            }),
            "custom tag 'tenant' value exceeds 1024 bytes",
        ),
        (
            "reserved custom tag collision",
            json!({
                "tracing": [{
                    "customTags": {
                        "trace_id": {"literal": {"value": "attacker-controlled"}}
                    }
                }]
            }),
            "custom tag name 'trace_id' is reserved or sensitive",
        ),
        (
            "unknown disabled metric",
            json!({
                "metrics": [{
                    "overrides": [{
                        "match": {"metric": "NOT_AN_ISTIO_METRIC"},
                        "disabled": true
                    }]
                }]
            }),
            "unsupported disabled metric 'NOT_AN_ISTIO_METRIC'",
        ),
        (
            "unknown tag override operation",
            json!({
                "metrics": [{
                    "overrides": [{
                        "match": {"metric": "REQUEST_COUNT"},
                        "tagOverrides": {
                            "source_workload": {"operation": "RENAME"}
                        }
                    }]
                }]
            }),
            "operation 'RENAME' is unsupported",
        ),
        (
            "invalid tracing provider endpoint",
            json!({
                "tracing": [{
                    "providers": [{
                        "name": "opentelemetry",
                        "endpoint": "not a URL"
                    }]
                }]
            }),
            "OTLP: 'endpoint' must be a valid URL",
        ),
    ];

    for (name, spec, expected) in cases {
        let error = telemetry_translation_error(spec);
        assert!(
            error.contains(expected),
            "{name} should fail visibly with '{expected}', got: {error}"
        );
    }
}

#[test]
fn k8s_telemetry_metric_upsert_rejects_missing_empty_and_unsupported_cel() {
    let oversized = format!("request.{}", "x".repeat(600));
    let cases = [
        (
            "missing value",
            json!({"operation": "UPSERT"}),
            "UPSERT value is required",
            "REQUEST_COUNT",
        ),
        (
            "empty value",
            json!({"operation": "UPSERT", "value": ""}),
            "UPSERT value is required",
            "REQUEST_COUNT",
        ),
        (
            "unsupported attribute",
            json!({"operation": "UPSERT", "value": "request.headers[\"authorization\"]"}),
            "unsupported attribute",
            "REQUEST_COUNT",
        ),
        (
            "http-only attribute on tcp family",
            json!({"operation": "UPSERT", "value": "request.host"}),
            "HTTP-only attributes that are unrepresentable for TCP metric families",
            "TCP_SENT_BYTES",
        ),
        (
            "oversized expression",
            json!({"operation": "UPSERT", "value": oversized}),
            "exceeds maximum length",
            "REQUEST_COUNT",
        ),
    ];

    for (name, tag_override, expected, metric) in cases {
        let error = telemetry_translation_error(json!({
            "metrics": [{
                "overrides": [{
                    "match": {"metric": metric},
                    "tagOverrides": {"source_workload": tag_override}
                }]
            }]
        }));
        assert!(
            error.contains(expected),
            "{name} should fail visibly with '{expected}', got: {error}"
        );
        assert!(
            !error.contains("authorization"),
            "{name} must not echo attacker-controlled expression text: {error}"
        );
    }
}

#[test]
fn k8s_telemetry_metric_upsert_accepts_double_quoted_string_literal() {
    let translation = translate_k8s_objects(
        &[telemetry(json!({
            "metrics": [{
                "overrides": [{
                    "match": {"metric": "REQUEST_COUNT"},
                    "tagOverrides": {
                        "source_workload": {
                            "operation": "UPSERT",
                            "value": "\"edge\""
                        }
                    }
                }]
            }]
        }))],
        options(),
    )
    .expect("double-quoted string literal translates");
    let metrics = translation
        .config
        .mesh
        .expect("mesh config")
        .telemetry_resources[0]
        .config
        .metrics
        .clone()
        .expect("metrics config");

    assert_eq!(metrics.tag_overrides.len(), 1);
    assert_eq!(
        metrics.tag_overrides[0].metric.as_deref(),
        Some("REQUEST_COUNT")
    );
    assert!(matches!(
        &metrics.tag_overrides[0].operation,
        TagOverrideOperation::Set { value } if value == "edge"
    ));
}

#[test]
fn k8s_telemetry_metric_upsert_accepts_bounded_cel_expressions() {
    use ferrum_edge::modes::mesh::metric_tag_cel::{MetricTagCelAttr, MetricTagCelExpr};

    let translation = translate_k8s_objects(
        &[telemetry(json!({
            "metrics": [{
                "overrides": [{
                    "match": {"metric": "REQUEST_COUNT"},
                    "tagOverrides": {
                        "source_workload": {
                            "operation": "UPSERT",
                            "value": "request.host"
                        },
                        "destination_service": {
                            "operation": "UPSERT",
                            "value": "string(destination.port)"
                        },
                        "response_flags": {
                            "operation": "UPSERT",
                            "value": "has(request.host) ? request.host : \"unknown\""
                        }
                    }
                }]
            }]
        }))],
        options(),
    )
    .expect("bounded CEL expressions translate");
    let metrics = translation
        .config
        .mesh
        .expect("mesh config")
        .telemetry_resources[0]
        .config
        .metrics
        .clone()
        .expect("metrics config");

    assert_eq!(metrics.tag_overrides.len(), 3);
    assert!(metrics.tag_overrides.iter().any(|ovr| {
        matches!(
            &ovr.operation,
            TagOverrideOperation::SetExpr {
                expression: MetricTagCelExpr::Attribute {
                    name: MetricTagCelAttr::RequestHost
                }
            } if ovr.name == "source_workload"
        )
    }));
    assert!(metrics.tag_overrides.iter().any(|ovr| {
        matches!(
            &ovr.operation,
            TagOverrideOperation::SetExpr {
                expression: MetricTagCelExpr::StringOfInt {
                    attribute: MetricTagCelAttr::DestinationPort
                }
            } if ovr.name == "destination_service"
        )
    }));
    assert!(metrics.tag_overrides.iter().any(|ovr| {
        matches!(
            &ovr.operation,
            TagOverrideOperation::SetExpr {
                expression: MetricTagCelExpr::HasThenElse { .. }
            } if ovr.name == "response_flags"
        )
    }));
}

#[test]
fn k8s_telemetry_metric_upsert_counts_surrounding_whitespace_in_cel_limit() {
    use ferrum_edge::modes::mesh::metric_tag_cel::MAX_METRIC_TAG_CEL_EXPR_LEN;

    let padded = format!("{}request.host", " ".repeat(MAX_METRIC_TAG_CEL_EXPR_LEN));
    let error = telemetry_translation_error(json!({
        "metrics": [{
            "overrides": [{
                "match": {"metric": "REQUEST_COUNT"},
                "tagOverrides": {
                    "source_workload": {
                        "operation": "UPSERT",
                        "value": padded
                    }
                }
            }]
        }]
    }));

    assert!(error.contains("exceeds maximum length"), "{error}");
    assert!(!error.contains("request.host"));
}
