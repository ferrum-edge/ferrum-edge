//! Bench: Gateway API status planning over 1k and 10k routes (#2397).
//!
//! Measures `plan_gateway_api_status_updates_budgeted` with the production
//! 256-work-budget so large snapshots stay near-linear in the budgeted window
//! rather than O(routes × snapshot) from per-object retranslation.
//!
//! Source-only in normal agent workflows — do not run locally when the
//! repository forbids cargo/benchmark execution; CI or an explicit operator
//! bench job owns execution.

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, gateway_api_route_conflicts,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates_budgeted,
};
use ferrum_edge::k8s_controller::status_plan::{
    DEFAULT_STATUS_PLAN_WORK_BUDGET, StatusPlanBudget,
};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("bench trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: if kind == "GatewayClass" {
                String::new()
            } else {
                "default".to_string()
            },
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn build_snapshot(route_count: usize) -> Vec<K8sObject> {
    let mut objects = vec![
        object(
            "GatewayClass",
            "ferrum",
            json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
        ),
        object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        ),
    ];
    for index in 0..route_count {
        let name = format!("route-{index:05}");
        objects.push(object(
            "HTTPRoute",
            &name,
            json!({
                "hostnames": [format!("{name}.example.com")],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": format!("/{name}")}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        ));
    }
    objects
}

fn bench_gateway_api_status_planning(c: &mut Criterion) {
    let mut group = c.benchmark_group("gateway_api_status_planning");
    for &routes in &[1_000usize, 10_000] {
        let objects = build_snapshot(routes);
        let conflicts = gateway_api_route_conflicts(&objects, &options());
        group.bench_with_input(BenchmarkId::new("routes", routes), &routes, |b, _| {
            b.iter(|| {
                let outcome = plan_gateway_api_status_updates_budgeted(
                    black_box(&objects),
                    options(),
                    black_box(&conflicts),
                    Default::default(),
                    None,
                    StatusPlanBudget::new(DEFAULT_STATUS_PLAN_WORK_BUDGET, 0),
                );
                black_box(outcome);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_gateway_api_status_planning);
criterion_main!(benches);
