//! Correctness tests for Gateway API / Istio status planning indexes,
//! fair work budget, and translation reuse (#2397).

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, gateway_api_route_conflicts,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, StatusTranslationReuse,
    plan_gateway_api_status_updates, plan_gateway_api_status_updates_budgeted,
};
use ferrum_edge::k8s_controller::status_plan::{
    DEFAULT_STATUS_PLAN_WORK_BUDGET, StatusPlanBudget, select_fair_work_window,
};
use ferrum_edge::k8s_controller::istio_status::plan_istio_status_updates_budgeted;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

const STATUS_SRC: &str = include_str!("../../../src/k8s_controller/status.rs");
const RECONCILER_SRC: &str = include_str!("../../../src/k8s_controller/reconciler.rs");
const TRANSLATE_SRC: &str = include_str!("../../../src/config_sources/k8s/mod.rs");

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "Namespace" || kind == "Service" || kind == "Secret" {
            "v1".to_string()
        } else {
            "gateway.networking.k8s.io/v1".to_string()
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: if kind == "GatewayClass" || kind == "Namespace" {
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

fn ferrum_gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn ferrum_gateway() -> K8sObject {
    object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
        }),
    )
}

fn http_route(name: &str) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        json!({
            "hostnames": [format!("{name}.example.com")],
            "parentRefs": [{"name": "edge"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": format!("/{name}")}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    )
}

fn base_objects_with_routes(route_count: usize) -> Vec<K8sObject> {
    let mut objects = vec![ferrum_gateway_class(), ferrum_gateway()];
    for index in 0..route_count {
        objects.push(http_route(&format!("route-{index:04}")));
    }
    objects
}

#[test]
fn status_planning_avoids_per_object_retranslate_and_post_cap() {
    assert!(
        STATUS_SRC.contains("plan_gateway_api_status_updates_budgeted"),
        "budgeted planner must own the production path"
    );
    assert!(
        STATUS_SRC.contains("GatewayApiStatusIndexes"),
        "immutable per-reconcile indexes are required"
    );
    assert!(
        STATUS_SRC.contains("StatusTranslationReuse"),
        "primary translation reuse must be wired"
    );
    assert!(
        !STATUS_SRC.contains("translate_k8s_objects_with_filter(objects, options"),
        "per-object filtered retranslation must not remain in status.rs"
    );
    assert!(
        RECONCILER_SRC.contains("plan_gateway_api_status_updates_budgeted"),
        "reconciler must plan under the work budget"
    );
    assert!(
        !RECONCILER_SRC.contains("updates.truncate(GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP)"),
        "post-plan truncate must not remain as the only CPU bound"
    );
    assert!(
        TRANSLATE_SRC.contains("Vec<&K8sObject>"),
        "translator must borrow included objects instead of deep-cloning"
    );
    assert!(
        TRANSLATE_SRC.contains("translate_k8s_objects_collecting_skips"),
        "skip-collecting translate helper must exist for status reuse"
    );
}

#[test]
fn fair_budget_bounds_expensive_planning_before_writes() {
    let objects = base_objects_with_routes(8);
    let conflicts = gateway_api_route_conflicts(&objects, &options());

    let first = plan_gateway_api_status_updates_budgeted(
        &objects,
        options(),
        &conflicts,
        Default::default(),
        None,
        StatusPlanBudget::new(3, 0),
    );
    assert_eq!(first.eligible_candidates, 10); // class + gateway + 8 routes
    assert_eq!(first.planned_candidates, 3);
    assert!(first.updates.len() <= 3);
    assert_eq!(first.next_cursor, 3);

    let second = plan_gateway_api_status_updates_budgeted(
        &objects,
        options(),
        &conflicts,
        Default::default(),
        None,
        StatusPlanBudget::new(3, first.next_cursor),
    );
    assert_eq!(second.planned_candidates, 3);
    assert_eq!(second.next_cursor, 6);

    let first_names: Vec<&str> = first.updates.iter().map(|u| u.name.as_str()).collect();
    let second_names: Vec<&str> = second.updates.iter().map(|u| u.name.as_str()).collect();
    for name in &second_names {
        assert!(
            !first_names.contains(name),
            "rotating window must advance to later candidates; saw {name} again"
        );
    }
}

#[test]
fn fair_budget_boundary_matches_default_cap() {
    let window = select_fair_work_window(400, StatusPlanBudget::new(DEFAULT_STATUS_PLAN_WORK_BUDGET, 0));
    assert_eq!(window.take, DEFAULT_STATUS_PLAN_WORK_BUDGET);
    assert_eq!(window.next_cursor, DEFAULT_STATUS_PLAN_WORK_BUDGET);

    let wrap = select_fair_work_window(
        5,
        StatusPlanBudget::new(DEFAULT_STATUS_PLAN_WORK_BUDGET, 3),
    );
    assert_eq!(wrap.take, 5);
    assert_eq!(wrap.start, 3);
}

#[test]
fn budgeted_full_coverage_matches_unlimited_plan_over_rotations() {
    let objects = base_objects_with_routes(5);
    let conflicts = gateway_api_route_conflicts(&objects, &options());
    let unlimited = plan_gateway_api_status_updates(&objects, options(), &conflicts);

    let mut cursor = 0usize;
    let mut seen = HashMap::<(String, String), Value>::new();
    for _ in 0..8 {
        let outcome = plan_gateway_api_status_updates_budgeted(
            &objects,
            options(),
            &conflicts,
            Default::default(),
            None,
            StatusPlanBudget::new(2, cursor),
        );
        cursor = outcome.next_cursor;
        for update in outcome.updates {
            seen.insert((update.kind.clone(), update.name.clone()), update.status);
        }
    }

    assert_eq!(seen.len(), unlimited.len());
    for update in &unlimited {
        let key = (update.kind.clone(), update.name.clone());
        assert_eq!(
            seen.get(&key),
            Some(&update.status),
            "status parity mismatch for {}/{}",
            update.kind,
            update.name
        );
    }
}

#[test]
fn translation_reuse_preserves_gateway_status_parity() {
    let objects = base_objects_with_routes(3);
    let conflicts = gateway_api_route_conflicts(&objects, &options());
    let baseline = plan_gateway_api_status_updates(&objects, options(), &conflicts);

    let (translation, errors) =
        ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
            &objects,
            options(),
        )
        .expect("primary translation");
    let reuse = StatusTranslationReuse::from_owned(translation, errors);
    let reused = plan_gateway_api_status_updates_budgeted(
        &objects,
        options(),
        &conflicts,
        Default::default(),
        Some(&reuse),
        StatusPlanBudget::unlimited(0),
    );
    assert_eq!(reused.updates, baseline);
    assert!(Arc::strong_count(&reuse.translation) >= 1);
}

#[test]
fn large_snapshot_eligible_set_is_ordered_and_budget_bounded() {
    let objects = base_objects_with_routes(280);
    let conflicts = gateway_api_route_conflicts(&objects, &options());
    let (translation, errors) =
        ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
            &objects,
            options(),
        )
        .expect("primary translation");
    let reuse = StatusTranslationReuse::from_owned(translation, errors);
    let outcome = plan_gateway_api_status_updates_budgeted(
        &objects,
        options(),
        &conflicts,
        Default::default(),
        Some(&reuse),
        StatusPlanBudget::new(DEFAULT_STATUS_PLAN_WORK_BUDGET, 0),
    );
    assert_eq!(outcome.eligible_candidates, 282); // class + gateway + 280 routes
    assert_eq!(outcome.planned_candidates, DEFAULT_STATUS_PLAN_WORK_BUDGET);
    assert!(outcome.updates.len() <= DEFAULT_STATUS_PLAN_WORK_BUDGET);

    let keys: Vec<(&str, &str)> = outcome
        .updates
        .iter()
        .map(|u| (u.kind.as_str(), u.name.as_str()))
        .collect();
    let mut last = ("", "");
    for key in &keys {
        assert!(
            key >= &last,
            "updates must follow deterministic (kind, name) order"
        );
        last = *key;
    }
    assert_eq!(keys.len(), outcome.updates.len());
}

#[test]
fn istio_budgeted_planning_reuses_shared_translation_path() {
    let objects = vec![K8sObject {
        api_version: "security.istio.io/v1".to_string(),
        kind: "AuthorizationPolicy".to_string(),
        metadata: K8sMetadata {
            name: "allow-nothing".to_string(),
            uid: "uid-allow".to_string(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({ "action": "ALLOW" }),
        status: Value::Object(serde_json::Map::new()),
    }];
    let outcome = plan_istio_status_updates_budgeted(
        &objects,
        options(),
        None,
        StatusPlanBudget::new(1, 0),
    );
    assert_eq!(outcome.eligible_candidates, 1);
    assert_eq!(outcome.planned_candidates, 1);
    assert_eq!(outcome.updates.len(), 1);
    assert_eq!(outcome.updates[0].kind, "AuthorizationPolicy");
}
