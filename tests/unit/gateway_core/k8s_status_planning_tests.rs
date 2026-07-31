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

#[test]
fn status_indexes_and_borrowed_eligibility_are_wired() {
    assert!(
        STATUS_SRC.contains("namespaces_by_name"),
        "namespace label index required for selector allowedRoutes"
    );
    assert!(
        STATUS_SRC.contains("routes_by_gateway"),
        "routes-by-gateway index required for attachedRoutes"
    );
    assert!(
        STATUS_SRC.contains("status_candidate_is_eligible"),
        "pre-budget eligibility must be a dedicated borrowed predicate"
    );
    assert!(
        STATUS_SRC.contains("route_parent_refs_borrowed"),
        "parentRefs must be borrowed before the fair budget"
    );
    assert!(
        STATUS_SRC.contains("route_has_managed_parent_ref_indexed"),
        "eligibility must not materialize owned parentRefs for every candidate"
    );
    assert!(
        !STATUS_SRC.contains(".iter()\n            .find(|(key, _)| key.matches_object(object))"),
        "result_for must not linearly scan the error map"
    );
    assert!(
        STATUS_SRC.contains("self.errors.get(&exact)"),
        "result_for must use keyed HashMap get"
    );
    assert!(
        TRANSLATE_SRC.contains("skipped_identities"),
        "collecting-skips include filter must use an identity HashSet"
    );
    assert!(
        !TRANSLATE_SRC.contains("skipped\n                .keys()\n                .any(|key: &K8sResourceKey| key.matches_object(object))"),
        "collecting-skips must not linearly scan skipped keys per object"
    );
}

#[test]
fn invalid_heavy_error_lookup_stays_keyed_not_linear() {
    // Many invalid resources + many planned objects must still resolve via
    // HashMap get (exact then versionless), never O(planned × errors).
    let mut errors = HashMap::new();
    for index in 0..512 {
        let key = ferrum_edge::config_sources::k8s::K8sResourceKey {
            api_version: String::new(),
            kind: "HTTPRoute".to_string(),
            namespace: "default".to_string(),
            name: format!("invalid-{index:04}"),
        };
        errors.insert(
            key,
            ferrum_edge::config_sources::k8s::K8sTranslateError::InvalidResource {
                kind: "HTTPRoute".to_string(),
                namespace: "default".to_string(),
                name: format!("invalid-{index:04}"),
                message: "synthetic invalid".to_string(),
            },
        );
    }
    // One live-versioned association plus the versionless fallback target.
    errors.insert(
        ferrum_edge::config_sources::k8s::K8sResourceKey {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            namespace: "default".to_string(),
            name: "live-ok".to_string(),
        },
        ferrum_edge::config_sources::k8s::K8sTranslateError::InvalidResource {
            kind: "HTTPRoute".to_string(),
            namespace: "default".to_string(),
            name: "live-ok".to_string(),
            message: "should not be selected for versionless object".to_string(),
        },
    );
    errors.insert(
        ferrum_edge::config_sources::k8s::K8sResourceKey {
            api_version: String::new(),
            kind: "HTTPRoute".to_string(),
            namespace: "default".to_string(),
            name: "versionless-hit".to_string(),
        },
        ferrum_edge::config_sources::k8s::K8sTranslateError::InvalidResource {
            kind: "HTTPRoute".to_string(),
            namespace: "default".to_string(),
            name: "versionless-hit".to_string(),
            message: "versionless fallback".to_string(),
        },
    );

    let (translation, _) = ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
        &base_objects_with_routes(1),
        options(),
    )
    .expect("baseline translation");
    let reuse = StatusTranslationReuse::from_owned(translation, errors);

    let versionless_object = http_route("versionless-hit");
    match reuse.result_for(&versionless_object) {
        Err(error) => assert!(error.to_string().contains("versionless fallback")),
        Ok(_) => panic!("versionless error key must still match live objects"),
    }

    let miss = http_route("not-in-error-map");
    assert!(reuse.result_for(&miss).is_ok());

    // Structural regression: the hot path must keep using get(), not find().
    let result_for = STATUS_SRC
        .split("pub fn result_for<'a>(")
        .nth(1)
        .and_then(|rest| rest.split("Ok(self.translation.as_ref())").next())
        .expect("result_for body");
    assert!(result_for.contains("self.errors.get(&exact)"));
    assert!(result_for.contains("self.errors.get(&versionless)"));
    assert!(!result_for.contains(".find("));
    assert!(!result_for.contains("matches_object"));
}

#[test]
fn mixed_valid_invalid_and_rotating_windows_preserve_status_parity() {
    let mut objects = vec![ferrum_gateway_class(), ferrum_gateway()];
    for index in 0..6 {
        objects.push(http_route(&format!("ok-{index}")));
    }
    // Invalid route: empty rules with a parent — still Ferrum-managed for status.
    objects.push(object(
        "HTTPRoute",
        "invalid-empty",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": []
        }),
    ));
    let conflicts = gateway_api_route_conflicts(&objects, &options());
    let unlimited = plan_gateway_api_status_updates(&objects, options(), &conflicts);

    let (translation, errors) =
        ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
            &objects,
            options(),
        )
        .expect("primary translation");
    let reuse = StatusTranslationReuse::from_owned(translation, errors);

    let mut cursor = 0usize;
    let mut seen = HashMap::<(String, String), Value>::new();
    for _ in 0..12 {
        let outcome = plan_gateway_api_status_updates_budgeted(
            &objects,
            options(),
            &conflicts,
            Default::default(),
            Some(&reuse),
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
            "rotating-window parity mismatch for {}/{}",
            update.kind,
            update.name
        );
    }
    assert!(
        unlimited.iter().any(|update| update.name == "invalid-empty"),
        "invalid empty route must still receive status planning"
    );
}

#[test]
fn namespace_selector_and_cross_namespace_grant_parity() {
    let gateway_class = ferrum_gateway_class();
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {
                        "from": "Selector",
                        "selector": { "matchLabels": { "allow": "true" } }
                    }
                }
            }]
        }),
    );
    let allowed_ns = K8sObject {
        api_version: "v1".to_string(),
        kind: "Namespace".to_string(),
        metadata: K8sMetadata {
            name: "tenant-a".to_string(),
            uid: "uid-tenant-a".to_string(),
            namespace: String::new(),
            generation: Some(1),
            labels: HashMap::from([("allow".to_string(), "true".to_string())]),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({}),
        status: Value::Object(serde_json::Map::new()),
    };
    let denied_ns = K8sObject {
        api_version: "v1".to_string(),
        kind: "Namespace".to_string(),
        metadata: K8sMetadata {
            name: "tenant-b".to_string(),
            uid: "uid-tenant-b".to_string(),
            namespace: String::new(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({}),
        status: Value::Object(serde_json::Map::new()),
    };
    let mut allowed_route = object(
        "HTTPRoute",
        "allowed",
        json!({
            "parentRefs": [{"name": "edge", "namespace": "default"}],
            "rules": [{
                "backendRefs": [{
                    "name": "api",
                    "namespace": "backend",
                    "port": 8080
                }]
            }]
        }),
    );
    allowed_route.metadata.namespace = "tenant-a".to_string();
    let mut denied_route = object(
        "HTTPRoute",
        "denied",
        json!({
            "parentRefs": [{"name": "edge", "namespace": "default"}],
            "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
        }),
    );
    denied_route.metadata.namespace = "tenant-b".to_string();
    let mut grant = object(
        "ReferenceGrant",
        "allow-backend",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "HTTPRoute",
                "namespace": "tenant-a"
            }],
            "to": [{ "group": "", "kind": "Service", "name": "api" }]
        }),
    );
    grant.metadata.namespace = "backend".to_string();
    let backend_svc = K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: "api".to_string(),
            uid: "uid-api".to_string(),
            namespace: "backend".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({ "ports": [{"port": 8080}] }),
        status: Value::Object(serde_json::Map::new()),
    };

    let objects = vec![
        gateway_class,
        gateway,
        allowed_ns,
        denied_ns,
        allowed_route,
        denied_route,
        grant,
        backend_svc,
    ];
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
        StatusPlanBudget::unlimited(0),
    );

    let gateway_update = outcome
        .updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("gateway status");
    let attached = gateway_update.status["listeners"][0]["attachedRoutes"]
        .as_u64()
        .expect("attachedRoutes");
    assert_eq!(attached, 1, "only selector-matching namespace attaches");

    let allowed = outcome
        .updates
        .iter()
        .find(|update| update.name == "allowed")
        .expect("allowed route");
    let denied = outcome
        .updates
        .iter()
        .find(|update| update.name == "denied")
        .expect("denied route");
    let allowed_reason = allowed.status["parents"][0]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .and_then(|condition| condition["reason"].as_str());
    let denied_reason = denied.status["parents"][0]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .and_then(|condition| condition["reason"].as_str());
    assert_eq!(allowed_reason, Some("Accepted"));
    assert_eq!(denied_reason, Some("NotAllowedByListeners"));

    let resolved = allowed.status["parents"][0]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "ResolvedRefs")
        .and_then(|condition| condition["status"].as_str());
    assert_eq!(
        resolved,
        Some("True"),
        "cross-namespace backend must be permitted by ReferenceGrant"
    );
}

#[test]
fn multiple_gateways_and_listeners_attached_routes_stay_scoped() {
    let gateway_class = ferrum_gateway_class();
    let edge_a = object(
        "Gateway",
        "edge-a",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {"name": "http", "port": 80, "protocol": "HTTP"},
                {"name": "http-alt", "port": 8080, "protocol": "HTTP"}
            ]
        }),
    );
    let edge_b = object(
        "Gateway",
        "edge-b",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {"name": "http", "port": 80, "protocol": "HTTP"}
            ]
        }),
    );
    let route_a = object(
        "HTTPRoute",
        "route-a",
        json!({
            "hostnames": ["a.example.com"],
            "parentRefs": [{"name": "edge-a", "sectionName": "http"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/a"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );
    let route_b = object(
        "HTTPRoute",
        "route-b",
        json!({
            "hostnames": ["b.example.com"],
            "parentRefs": [{"name": "edge-b"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/b"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );
    let route_both = object(
        "HTTPRoute",
        "route-both",
        json!({
            "hostnames": ["both.example.com"],
            "parentRefs": [
                {"name": "edge-a", "sectionName": "http-alt"},
                {"name": "edge-b"}
            ],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/both"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );

    let objects = vec![gateway_class, edge_a, edge_b, route_a, route_b, route_both];
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
        StatusPlanBudget::unlimited(0),
    );

    let gateway_a = outcome
        .updates
        .iter()
        .find(|update| update.name == "edge-a")
        .expect("edge-a");
    let gateway_b = outcome
        .updates
        .iter()
        .find(|update| update.name == "edge-b")
        .expect("edge-b");
    let listeners_a = gateway_a.status["listeners"].as_array().unwrap();
    let listeners_b = gateway_b.status["listeners"].as_array().unwrap();
    let attached_a_http = listeners_a
        .iter()
        .find(|listener| listener["name"] == "http")
        .and_then(|listener| listener["attachedRoutes"].as_u64());
    let attached_a_alt = listeners_a
        .iter()
        .find(|listener| listener["name"] == "http-alt")
        .and_then(|listener| listener["attachedRoutes"].as_u64());
    let attached_b = listeners_b
        .iter()
        .find(|listener| listener["name"] == "http")
        .and_then(|listener| listener["attachedRoutes"].as_u64());
    assert_eq!(attached_a_http, Some(1), "sectionName scopes route-a only");
    assert_eq!(attached_a_alt, Some(1), "sectionName scopes route-both alt");
    assert_eq!(attached_b, Some(2), "edge-b sees route-b and route-both");
}
