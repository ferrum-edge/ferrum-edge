//! External coverage for Telemetry metric tagOverride CEL compilation and
//! evaluation on the live mesh metric emission path.

use std::collections::HashMap;

use ferrum_edge::modes::mesh::metric_tag_cel::{
    MAX_METRIC_TAG_CEL_EXPR_LEN, MetricTagCelAttr, MetricTagCelContext, MetricTagCelExpr,
    evaluate_metric_tag_cel, parse_metric_tag_cel_expression, sanitize_metric_tag_value,
    validate_metric_tag_cel_for_families,
};
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};
use serde_json::json;

use super::plugin_utils::create_test_proxy;

fn mesh_identity_metadata(mut metadata: HashMap<String, String>) -> HashMap<String, String> {
    for (key, value) in [
        ("mesh.source.workload", "frontend"),
        ("mesh.source.namespace", "default"),
        (
            "mesh.source.principal",
            "spiffe://cluster.local/ns/default/sa/frontend",
        ),
        ("mesh.source.app", "frontend"),
        ("mesh.source.service", "frontend"),
        ("mesh.destination.workload", "backend"),
        ("mesh.destination.namespace", "default"),
        (
            "mesh.destination.principal",
            "spiffe://cluster.local/ns/default/sa/backend",
        ),
        ("mesh.destination.app", "backend"),
        ("mesh.destination.service", "backend"),
        ("mesh.request_protocol", "http"),
        ("mesh.response_flags", "-"),
        ("mesh.connection_security_policy", "mutual_tls"),
    ] {
        metadata.insert(key.into(), value.into());
    }
    metadata
}

#[tokio::test]
async fn cel_tag_override_evaluates_on_live_request_count_path() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "string(destination.port)"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "source_app",
                "operation": {"type": "set", "value": "edge"}
            }]
        }
    }))
    .expect("cel overrides");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/checkout".into());
    ctx.request_authority = Some("reviews.default.svc.cluster.local".into());
    ctx.mesh_outbound_destination_authz_port = Some(9080);
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Outbound);
    let mut headers = HashMap::new();
    assert!(matches!(
        workload_metrics.before_proxy(&mut ctx, &mut headers).await,
        ferrum_edge::plugins::PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.cel.request_host")
            .map(String::as_str),
        Some("reviews.default.svc.cluster.local")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.cel.destination_port")
            .map(String::as_str),
        Some("9080")
    );
    assert!(
        ctx.metadata
            .get("mesh.metrics.request_count.tag_overrides")
            .is_some_and(|plan| plan.contains("x0,") && plan.contains("s3,4:edge;")),
        "compiled plan should mix CEL and literal opcodes: {:?}",
        ctx.metadata.get("mesh.metrics.request_count.tag_overrides")
    );

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        request_path: "/checkout".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();

    assert!(
        counter.contains(r#"source_workload="reviews.default.svc.cluster.local""#),
        "{counter}"
    );
    assert!(
        counter.contains(r#"destination_service="9080""#),
        "{counter}"
    );
    assert!(counter.contains(r#"source_app="edge""#), "{counter}");
}

#[tokio::test]
async fn cel_reads_original_attribution_not_prior_label_mutations() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set", "value": "overridden"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "source.workload"}
            }]
        }
    }))
    .expect("mixed ordered overrides");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    workload_metrics.before_proxy(&mut ctx, &mut headers).await;

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();

    assert!(
        counter.contains(r#"source_workload="overridden""#),
        "{counter}"
    );
    assert!(
        counter.contains(r#"destination_service="frontend""#),
        "CEL must read the original source.workload attribution: {counter}"
    );
}

#[tokio::test]
async fn cel_cannot_read_a_label_removed_earlier_in_the_override_plan() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_principal",
                "operation": {"type": "remove"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "source_app",
                "operation": {
                    "type": "set_expr",
                    "cel": "has(source.principal) ? source.principal : \"redacted\""
                }
            }, {
                "metric": "REQUEST_COUNT",
                "name": "response_code",
                "operation": {"type": "remove"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {
                    "type": "set_expr",
                    "cel": "string(response.code)"
                }
            }]
        }
    }))
    .expect("ordered remove and CEL override");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    let mut headers = HashMap::new();
    workload_metrics.before_proxy(&mut ctx, &mut headers).await;

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();

    assert!(
        !counter.contains("source_principal="),
        "removed source_principal must stay absent: {counter}"
    );
    assert!(
        counter.contains(r#"source_app="redacted""#),
        "CEL must treat removed source.principal as absent: {counter}"
    );
    assert!(
        !counter.contains("response_code="),
        "removed response_code must stay absent: {counter}"
    );
    assert!(
        counter.contains(r#"destination_service="""#),
        "CEL must render a removed response.code as absent: {counter}"
    );
    assert!(
        !counter.contains(r#"destination_service="200""#),
        "removed response.code must not leak into another label: {counter}"
    );
    assert!(
        !counter.contains("spiffe://cluster.local/ns/default/sa/frontend"),
        "removed source.principal value must not leak into another label: {counter}"
    );
    assert!(
        counter.contains(r#"destination_principal="spiffe://cluster.local/ns/default/sa/backend""#),
        "unremoved destination.principal must remain available: {counter}"
    );
}

#[tokio::test]
async fn missing_cel_attribute_emits_empty_label_not_invented_data() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("cel override");
    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    // No request_authority / Host header → request.host missing.
    let mut headers = HashMap::new();
    workload_metrics.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata.remove("mesh.metrics.cel.request_host");

    let registry = MetricsRegistry::new();
    let summary = TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    };
    registry.record(&summary);
    let counter = registry
        .render_uncached()
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter")
        .to_string();
    assert!(counter.contains(r#"source_workload="""#), "{counter}");
}

#[test]
fn rejects_unsupported_malformed_and_costly_cel() {
    let err = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.headers[\"authorization\"]"}
            }]
        }
    }))
    .err()
    .expect("headers unsupported");
    assert!(err.contains("unsupported attribute") || err.contains("rejected"));
    assert!(!err.contains("authorization"));

    let err = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "TCP_SENT_BYTES",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.method"}
            }]
        }
    }))
    .err()
    .expect("http-only on tcp");
    assert!(
        err.contains("HTTP-only") || err.contains("unrepresentable") || err.contains("rejected")
    );

    let oversized = format!("request.{}", "x".repeat(MAX_METRIC_TAG_CEL_EXPR_LEN));
    let err = parse_metric_tag_cel_expression(&oversized).expect_err("oversize");
    assert!(err.contains("exceeds maximum length"));
    assert!(!err.contains("xxxxx"));

    let whitespace_padded = format!("{}request.host", " ".repeat(MAX_METRIC_TAG_CEL_EXPR_LEN));
    let err = parse_metric_tag_cel_expression(&whitespace_padded)
        .expect_err("raw expression length must include surrounding whitespace");
    assert!(err.contains("exceeds maximum length"));
    assert!(!err.contains("request.host"));

    let expr = parse_metric_tag_cel_expression("request.host").unwrap();
    assert!(validate_metric_tag_cel_for_families(&expr, true).is_err());
    assert!(sanitize_metric_tag_value("a\nb\"c").contains('_'));
}

#[test]
fn compiled_cel_forms_evaluate_with_missing_attribute_semantics() {
    let host = parse_metric_tag_cel_expression("request.host").expect("request.host");
    assert_eq!(
        host,
        MetricTagCelExpr::Attribute {
            name: MetricTagCelAttr::RequestHost
        }
    );
    let port = parse_metric_tag_cel_expression("string(destination.port)")
        .expect("string destination port");
    assert_eq!(
        port,
        MetricTagCelExpr::StringOfInt {
            attribute: MetricTagCelAttr::DestinationPort
        }
    );
    let fallback =
        parse_metric_tag_cel_expression(r#"has(request.host) ? request.host : "unknown""#)
            .expect("bounded ternary");
    assert!(matches!(fallback, MetricTagCelExpr::HasThenElse { .. }));

    let ctx = MetricTagCelContext {
        source_workload: "frontend",
        source_namespace: "default",
        source_principal: "spiffe://cluster.local/ns/default/sa/frontend",
        source_app: "frontend",
        source_service: "frontend",
        destination_workload: "backend",
        destination_namespace: "default",
        destination_principal: "spiffe://cluster.local/ns/default/sa/backend",
        destination_app: "backend",
        destination_service: "backend",
        request_protocol: "http",
        response_flags: "-",
        connection_security_policy: "mutual_tls",
        request_method: Some("GET"),
        request_host: None,
        response_code: Some(200),
        destination_port: Some(8080),
    };
    assert_eq!(evaluate_metric_tag_cel(&host, ctx), "");
    assert_eq!(evaluate_metric_tag_cel(&port, ctx), "8080");
    assert_eq!(evaluate_metric_tag_cel(&fallback, ctx), "unknown");
    assert_eq!(sanitize_metric_tag_value("a\nb\"c"), "a_b_c");
}

#[test]
fn metric_tag_override_count_and_aggregate_plan_bytes_are_bounded() {
    let too_many: Vec<_> = (0..129)
        .map(|_| {
            json!({
                "name": "source_workload",
                "operation": {"type": "remove"}
            })
        })
        .collect();
    let error = WorkloadMetrics::new(&json!({
        "metrics": {"tag_overrides": too_many}
    }))
    .err()
    .expect("override count must be bounded");
    assert!(error.contains("exceeds 128 entries"), "{error}");

    let oversized_plan: Vec<_> = (0..7)
        .map(|_| {
            let value = "x".repeat(256);
            json!({
                "name": "source_workload",
                "operation": {"type": "set", "value": value}
            })
        })
        .collect();
    let error = WorkloadMetrics::new(&json!({
        "metrics": {"tag_overrides": oversized_plan}
    }))
    .err()
    .expect("aggregate encoded plans must be bounded");
    assert!(error.contains("exceed 16384 bytes"), "{error}");
}

#[tokio::test]
async fn tag_override_reload_update_and_delete_change_emitted_labels() {
    let first = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"},
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("first generation");
    let updated = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"},
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set", "value": "reloaded"}
            }]
        }
    }))
    .expect("updated generation");
    let deleted = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"},
        "metrics": {"tag_overrides": []}
    }))
    .expect("deleted");

    async fn emit(plugin: &WorkloadMetrics) -> String {
        let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
        ctx.request_authority = Some("reviews.default.svc".into());
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        let registry = MetricsRegistry::new();
        let summary = TransactionSummary {
            http_method: "GET".into(),
            response_status_code: 200,
            metadata: mesh_identity_metadata(ctx.metadata),
            ..TransactionSummary::default()
        };
        registry.record(&summary);
        registry
            .render_uncached()
            .lines()
            .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
            .expect("counter")
            .to_string()
    }

    let first_line = emit(&first).await;
    assert!(
        first_line.contains(r#"source_workload="reviews.default.svc""#),
        "{first_line}"
    );

    let updated_line = emit(&updated).await;
    assert!(
        updated_line.contains(r#"source_workload="reloaded""#),
        "{updated_line}"
    );

    let deleted_line = emit(&deleted).await;
    assert!(
        deleted_line.contains(r#"source_workload="frontend""#),
        "{deleted_line}"
    );
}

#[tokio::test]
async fn mesh_series_budget_caps_cel_cardinality_and_keeps_admitted_keys_updating() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("cel host override");

    let registry = MetricsRegistry::new();
    registry.set_mesh_series_budget_per_family_for_test(4);

    async fn emit_host(plugin: &WorkloadMetrics, registry: &MetricsRegistry, host: &str) {
        let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
        ctx.request_authority = Some(host.into());
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        let summary = TransactionSummary {
            http_method: "GET".into(),
            response_status_code: 200,
            metadata: mesh_identity_metadata(ctx.metadata),
            ..TransactionSummary::default()
        };
        registry.record(&summary);
    }

    for i in 0..12 {
        emit_host(&workload_metrics, &registry, &format!("host-{i}.example")).await;
    }

    assert_eq!(
        registry.mesh_series_live_for_test("REQUEST_COUNT"),
        Some(4),
        "live series must stop at the exact budget"
    );
    assert_eq!(registry.mesh_request_counter.len(), 4);
    let overflow = registry
        .mesh_series_overflow_for_test("REQUEST_COUNT")
        .expect("request_count overflow");
    assert!(overflow >= 8, "expected dropped admissions, got {overflow}");

    // Re-record an already-admitted host; the series must still update.
    let admitted_host = "host-0.example";
    let before = registry
        .mesh_request_counter
        .iter()
        .find(|entry| entry.key().source_workload.as_ref() == admitted_host)
        .map(|entry| {
            entry
                .value()
                .value
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .expect("admitted host series");
    emit_host(&workload_metrics, &registry, admitted_host).await;
    let after = registry
        .mesh_request_counter
        .iter()
        .find(|entry| entry.key().source_workload.as_ref() == admitted_host)
        .map(|entry| {
            entry
                .value()
                .value
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .expect("admitted host series after update");
    assert_eq!(after, before + 1);
    assert_eq!(registry.mesh_request_counter.len(), 4);

    let rendered = registry.render_uncached();
    let overflow_lines: Vec<_> = rendered
        .lines()
        .filter(|line| line.starts_with("ferrum_mesh_metric_series_overflow_total{"))
        .collect();
    assert!(
        !overflow_lines.is_empty(),
        "overflow observability must render: {rendered}"
    );
    for line in &overflow_lines {
        assert!(
            line.contains(r#"family="request_count""#),
            "overflow labels must be fixed family names only: {line}"
        );
        assert!(
            !line.contains("host-") && !line.contains("example"),
            "overflow must not echo CEL/host values: {line}"
        );
    }
}

#[test]
fn mesh_series_budget_admission_is_exact_under_concurrent_distinct_keys() {
    let registry = std::sync::Arc::new(MetricsRegistry::new());
    registry.set_mesh_series_budget_per_family_for_test(4);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(33));
    let mut workers = Vec::new();

    for i in 0..32 {
        let registry = std::sync::Arc::clone(&registry);
        let barrier = std::sync::Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let mut metadata = mesh_identity_metadata(HashMap::new());
            metadata.insert("mesh.source.workload".into(), format!("host-{i}.example"));
            let summary = TransactionSummary {
                http_method: "GET".into(),
                response_status_code: 200,
                metadata,
                ..TransactionSummary::default()
            };
            barrier.wait();
            registry.record(&summary);
        }));
    }

    barrier.wait();
    for worker in workers {
        worker.join().expect("concurrent admission worker");
    }

    assert_eq!(registry.mesh_series_live_for_test("REQUEST_COUNT"), Some(4));
    assert_eq!(registry.mesh_request_counter.len(), 4);
    assert_eq!(
        registry.mesh_series_overflow_for_test("REQUEST_COUNT"),
        Some(28),
        "every distinct key beyond the exact budget must be dropped once"
    );
}

#[tokio::test]
async fn mesh_series_budget_releases_capacity_on_stale_eviction() {
    let workload_metrics = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("cel host override");
    let registry = MetricsRegistry::new();
    registry.set_mesh_series_budget_per_family_for_test(2);

    for host in ["a.example", "b.example"] {
        let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
        ctx.request_authority = Some(host.into());
        let mut headers = HashMap::new();
        workload_metrics.before_proxy(&mut ctx, &mut headers).await;
        registry.record(&TransactionSummary {
            http_method: "GET".into(),
            response_status_code: 200,
            metadata: mesh_identity_metadata(ctx.metadata),
            ..TransactionSummary::default()
        });
    }
    assert_eq!(registry.mesh_series_live_for_test("REQUEST_COUNT"), Some(2));

    // Force every series stale and reclaim the live budget.
    let evicted = registry.evict_stale(0);
    assert!(evicted >= 2);
    assert_eq!(registry.mesh_series_live_for_test("REQUEST_COUNT"), Some(0));
    assert!(registry.mesh_request_counter.is_empty());

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    ctx.request_authority = Some("c.example".into());
    let mut headers = HashMap::new();
    workload_metrics.before_proxy(&mut ctx, &mut headers).await;
    registry.record(&TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    });
    assert_eq!(registry.mesh_series_live_for_test("REQUEST_COUNT"), Some(1));
    assert_eq!(registry.mesh_request_counter.len(), 1);
}

#[tokio::test]
async fn static_and_selective_cel_configs_stamp_only_required_attributes() {
    let no_cel = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "labels": {"app": "frontend"}
    }))
    .expect("static config");
    let mut ctx = RequestContext::new("10.0.0.2".into(), "POST".into(), "/pay".into());
    ctx.request_authority = Some("checkout.default.svc".into());
    ctx.mesh_outbound_destination_authz_port = Some(8080);
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Outbound);
    let mut headers = HashMap::new();
    no_cel.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        !ctx.metadata.contains_key("mesh.metrics.cel.request_host"),
        "no-CEL config must not stamp request.host"
    );
    assert!(
        !ctx.metadata.contains_key("mesh.metrics.cel.request_method"),
        "no-CEL config must not stamp request.method"
    );
    assert!(
        !ctx.metadata
            .contains_key("mesh.metrics.cel.destination_port"),
        "no-CEL config must not stamp destination.port"
    );

    let host_only = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("host cel");
    let mut ctx = RequestContext::new("10.0.0.2".into(), "POST".into(), "/pay".into());
    ctx.request_authority = Some("checkout.default.svc".into());
    ctx.mesh_outbound_destination_authz_port = Some(8080);
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Outbound);
    // Plant stale values that must be cleared when not required.
    ctx.metadata
        .insert("mesh.metrics.cel.request_method".into(), "STALE".into());
    ctx.metadata
        .insert("mesh.metrics.cel.destination_port".into(), "9999".into());
    let mut headers = HashMap::new();
    host_only.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.cel.request_host")
            .map(String::as_str),
        Some("checkout.default.svc")
    );
    assert!(
        !ctx.metadata.contains_key("mesh.metrics.cel.request_method"),
        "host-only CEL must clear unused method stamp"
    );
    assert!(
        !ctx.metadata
            .contains_key("mesh.metrics.cel.destination_port"),
        "host-only CEL must clear unused destination.port stamp"
    );

    let port_only = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "string(destination.port)"}
            }]
        }
    }))
    .expect("port cel");
    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    ctx.request_authority = Some("reviews.default.svc".into());
    ctx.mesh_outbound_destination_authz_port = Some(9080);
    ctx.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Outbound);
    ctx.metadata
        .insert("mesh.metrics.cel.request_host".into(), "stale-host".into());
    let mut headers = HashMap::new();
    port_only.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.cel.destination_port")
            .map(String::as_str),
        Some("9080")
    );
    assert!(
        !ctx.metadata.contains_key("mesh.metrics.cel.request_host"),
        "port-only CEL must not stamp request.host"
    );
    assert!(
        !ctx.metadata.contains_key("mesh.metrics.cel.request_method"),
        "port-only CEL must not stamp request.method"
    );

    // HTTP inbound attribution must use the same transport-derived port as
    // mesh authorization. A Sidecar ingress route is scoped to its declared
    // listener port, not the separate backend/defaultEndpoint dial port.
    let mut ingress_proxy = create_test_proxy();
    ingress_proxy.id = "__mesh-ingress-default-reviews-8443".into();
    ingress_proxy.backend_port = 8080;
    let mut ingress = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    ingress.mesh_direction = Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Inbound);
    ingress.matched_proxy = Some(std::sync::Arc::new(ingress_proxy));
    ingress.frontend_listen_port = Some(15006);
    ingress.mesh_inbound_listener_authz_port = Some(8443);
    port_only.before_proxy(&mut ingress, &mut headers).await;
    assert_eq!(
        ingress
            .metadata
            .get("mesh.metrics.cel.destination_port")
            .map(String::as_str),
        Some("8443"),
        "ingress metrics must use the declared listener port, not backend port 8080"
    );

    // If the request-path stamp is absent, the shared resolver deliberately
    // falls back to the actual inbound listener rather than misattributing the
    // backend dial port as the policy/metric destination.
    ingress.mesh_inbound_listener_authz_port = None;
    port_only.before_proxy(&mut ingress, &mut headers).await;
    assert_eq!(
        ingress
            .metadata
            .get("mesh.metrics.cel.destination_port")
            .map(String::as_str),
        Some("15006"),
        "missing ingress stamp must not fall back to backend port 8080"
    );

    // Stream path: destination.port is stamped only when needed; HTTP-only
    // keys stay cleared even if previously present.
    let mut stream = ferrum_edge::plugins::StreamConnectionContext::new(
        "10.0.0.2".into(),
        "10.0.0.3".into(),
        "proxy-1".into(),
        Some("reviews.catalog.svc.cluster.local".into()),
        0,
        ferrum_edge::config::types::BackendScheme::Tcp,
        std::sync::Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    stream.destination_port = Some(15001);
    stream.metadata = Some(HashMap::from([
        ("mesh.metrics.cel.request_host".into(), "leak".into()),
        ("mesh.metrics.cel.request_method".into(), "GET".into()),
        ("mesh.metrics.cel.destination_port".into(), "1".into()),
    ]));
    no_cel.on_stream_connect(&mut stream).await;
    let meta = stream.metadata.as_ref().expect("metadata");
    assert!(!meta.contains_key("mesh.metrics.cel.request_host"));
    assert!(!meta.contains_key("mesh.metrics.cel.request_method"));
    assert!(
        !meta.contains_key("mesh.metrics.cel.destination_port"),
        "static stream config must not stamp destination.port"
    );

    let mut stream = ferrum_edge::plugins::StreamConnectionContext::new(
        "10.0.0.2".into(),
        "10.0.0.3".into(),
        "proxy-1".into(),
        Some("reviews.catalog.svc.cluster.local".into()),
        0,
        ferrum_edge::config::types::BackendScheme::Tcp,
        std::sync::Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    stream.destination_port = Some(15001);
    stream.connection_destination_port = Some(9080);
    port_only.on_stream_connect(&mut stream).await;
    let meta = stream.metadata.as_ref().expect("metadata");
    assert_eq!(
        meta.get("mesh.metrics.cel.destination_port")
            .map(String::as_str),
        Some("9080"),
        "stream metrics must prefer the trusted original destination used by authz"
    );
    assert!(!meta.contains_key("mesh.metrics.cel.request_host"));
    assert!(!meta.contains_key("mesh.metrics.cel.request_method"));
}

#[tokio::test]
async fn multiple_effective_instances_union_surviving_family_cel_inputs() {
    // Effective instances compose per family: the later REQUEST_DURATION plan
    // must not clear request.host while the earlier REQUEST_COUNT plan remains
    // active, and the earlier instance must not suppress the later method need.
    let request_count = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("request-count host CEL");
    let request_duration = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_DURATION",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "request.method"}
            }]
        }
    }))
    .expect("request-duration method CEL");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "POST".into(), "/pay".into());
    ctx.request_authority = Some("checkout.default.svc".into());
    let mut headers = HashMap::new();
    request_count.before_proxy(&mut ctx, &mut headers).await;
    request_duration.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.cel.request_host")
            .map(String::as_str),
        Some("checkout.default.svc")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.metrics.cel.request_method")
            .map(String::as_str),
        Some("POST")
    );

    let registry = MetricsRegistry::new();
    registry.record(&TransactionSummary {
        http_method: "POST".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    });
    let output = registry.render_uncached();
    let request_count = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("request count");
    let request_duration = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_request_duration_ms_count{"))
        .expect("request duration");
    assert!(
        request_count.contains(r#"source_workload="checkout.default.svc""#),
        "{request_count}"
    );
    assert!(
        request_duration.contains(r#"destination_service="POST""#),
        "{request_duration}"
    );
}

#[tokio::test]
async fn later_same_family_plan_replaces_cel_input_requirements() {
    let cel = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }]
        }
    }))
    .expect("request-count host CEL");
    let replacement = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set", "value": "replacement"}
            }]
        }
    }))
    .expect("request-count replacement");

    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    ctx.request_authority = Some("stale.example".into());
    let mut headers = HashMap::new();
    cel.before_proxy(&mut ctx, &mut headers).await;
    replacement.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        !ctx.metadata.contains_key("mesh.metrics.cel.request_host"),
        "same-family replacement without CEL must retire the old input need"
    );

    let registry = MetricsRegistry::new();
    registry.record(&TransactionSummary {
        http_method: "GET".into(),
        response_status_code: 200,
        metadata: mesh_identity_metadata(ctx.metadata),
        ..TransactionSummary::default()
    });
    let output = registry.render_uncached();
    let request_count = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("request count");
    assert!(
        request_count.contains(r#"source_workload="replacement""#),
        "{request_count}"
    );
}

#[tokio::test]
async fn multiple_stream_instances_preserve_surviving_destination_port_need() {
    let opened = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "TCP_OPENED_CONNECTIONS",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "string(destination.port)"}
            }]
        }
    }))
    .expect("TCP opened destination-port CEL");
    let sent = WorkloadMetrics::new(&json!({
        "metrics": {
            "tag_overrides": [{
                "metric": "TCP_SENT_BYTES",
                "name": "source_workload",
                "operation": {"type": "set", "value": "edge"}
            }]
        }
    }))
    .expect("TCP sent static override");

    let mut stream = ferrum_edge::plugins::StreamConnectionContext::new(
        "10.0.0.2".into(),
        "10.0.0.3".into(),
        "proxy-1".into(),
        Some("reviews.catalog.svc.cluster.local".into()),
        0,
        ferrum_edge::config::types::BackendScheme::Tcp,
        std::sync::Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    stream.destination_port = Some(15001);
    stream.connection_destination_port = Some(9080);
    stream.metadata = Some(HashMap::from([(
        "mesh.metrics.prometheus_metrics_observed".into(),
        "1".into(),
    )]));
    opened.on_stream_connect(&mut stream).await;
    sent.on_stream_connect(&mut stream).await;

    let metadata = stream.metadata.as_mut().expect("stream metadata");
    assert_eq!(
        metadata
            .get("mesh.metrics.cel.destination_port")
            .map(String::as_str),
        Some("9080")
    );
    let registry = MetricsRegistry::new();
    registry.finalize_mesh_tcp_opened(
        metadata,
        "reviews.catalog.svc.cluster.local",
        Some("reviews.catalog.svc.cluster.local"),
    );
    let output = registry.render_uncached();
    let opened = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_tcp_connections_opened_total{"))
        .expect("TCP opened metric");
    assert!(opened.contains(r#"destination_service="9080""#), "{opened}");
}
