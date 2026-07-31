//! Correctness tests for Gateway API / Istio status planning indexes,
//! fair work budget, and translation reuse (#2397).

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, gateway_api_route_conflicts,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::istio_status::plan_istio_status_updates_budgeted;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, StatusTranslationReuse, plan_gateway_api_status_updates,
    plan_gateway_api_status_updates_budgeted,
};
use ferrum_edge::k8s_controller::status_plan::{
    DEFAULT_STATUS_PLAN_WORK_BUDGET, StatusPlanBudget, select_fair_work_window,
};
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
    let window = select_fair_work_window(
        400,
        StatusPlanBudget::new(DEFAULT_STATUS_PLAN_WORK_BUDGET, 0),
    );
    assert_eq!(window.take, DEFAULT_STATUS_PLAN_WORK_BUDGET);
    assert_eq!(window.next_cursor, DEFAULT_STATUS_PLAN_WORK_BUDGET);

    let wrap =
        select_fair_work_window(5, StatusPlanBudget::new(DEFAULT_STATUS_PLAN_WORK_BUDGET, 3));
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
    let outcome =
        plan_istio_status_updates_budgeted(&objects, options(), None, StatusPlanBudget::new(1, 0));
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
        STATUS_SRC.contains("reference_grant_permissions"),
        "ReferenceGrant from×to permission index required"
    );
    assert!(
        STATUS_SRC.contains("ReferenceGrantPermissionIndex"),
        "permission index type must exist"
    );
    assert!(
        !STATUS_SRC.contains("reference_grants_by_ns"),
        "raw grant-vector namespace scan must not remain"
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
        TRANSLATE_SRC.contains("SkippedObjectIdentities"),
        "collecting-skips must use a borrowed skip-identity index"
    );
    assert!(
        TRANSLATE_SRC.contains("contains_object"),
        "skip filter must borrow object identity"
    );
    assert!(
        !TRANSLATE_SRC.contains("skipped\n                .keys()\n                .any(|key: &K8sResourceKey| key.matches_object(object))"),
        "collecting-skips must not linearly scan skipped keys per object"
    );
    assert!(
        !TRANSLATE_SRC.contains("HashSet::<(String, String, String)>"),
        "version-blind owned triple HashSet must not remain"
    );
    assert!(
        !TRANSLATE_SRC.contains("object.kind.clone(),\n                object.metadata.namespace.clone(),\n                object.metadata.name.clone()"),
        "skip membership must not clone identity strings per candidate"
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

    let (translation, _) =
        ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
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
        unlimited
            .iter()
            .any(|update| update.name == "invalid-empty"),
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

fn condition_status(status: &Value, condition_type: &str) -> Option<&str> {
    status
        .pointer("/parents/0/conditions")
        .or_else(|| status.pointer("/listeners/0/conditions"))
        .or_else(|| status.get("conditions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|condition| condition.get("type").and_then(Value::as_str) == Some(condition_type))
        .and_then(|condition| condition.get("status").and_then(Value::as_str))
}

fn condition_reason(status: &Value, condition_type: &str) -> Option<&str> {
    status
        .pointer("/parents/0/conditions")
        .or_else(|| status.pointer("/listeners/0/conditions"))
        .or_else(|| status.get("conditions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|condition| condition.get("type").and_then(Value::as_str) == Some(condition_type))
        .and_then(|condition| condition.get("reason").and_then(Value::as_str))
}

fn backend_service(namespace: &str, name: &str) -> K8sObject {
    K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({ "ports": [{"port": 8080}] }),
        status: Value::Object(serde_json::Map::new()),
    }
}

fn place_in_namespace(mut object: K8sObject, namespace: &str) -> K8sObject {
    object.metadata.namespace = namespace.to_string();
    object
}

#[test]
fn collecting_skips_exact_api_version_does_not_skip_sibling_version() {
    // Same kind/namespace/name across two API versions: an exact skip for one
    // version must still attempt the other (matches_object exactness).
    let first = K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "EnvoyFilter".to_string(),
        metadata: K8sMetadata {
            name: "dup".to_string(),
            uid: "uid-dup-v1".to_string(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({}),
        status: Value::Object(serde_json::Map::new()),
    };
    let mut second = first.clone();
    second.api_version = "networking.istio.io/v1alpha3".to_string();
    second.metadata.uid = "uid-dup-v1alpha3".to_string();
    // Keep a managed Gateway so translation has a non-empty happy path beside skips.
    let objects = vec![
        ferrum_gateway_class(),
        ferrum_gateway(),
        first.clone(),
        second.clone(),
    ];

    let (_translation, skipped) =
        ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
            &objects,
            options(),
        )
        .expect("collecting skips must terminate");

    assert_eq!(
        skipped.len(),
        2,
        "each API version must be attempted and recorded; a version-blind skip set would hide the sibling"
    );
    assert!(
        skipped.keys().any(|key| {
            key.api_version == "networking.istio.io/v1"
                && key.kind == "EnvoyFilter"
                && key.name == "dup"
        }),
        "exact v1 skip key required"
    );
    assert!(
        skipped.keys().any(|key| {
            key.api_version == "networking.istio.io/v1alpha3"
                && key.kind == "EnvoyFilter"
                && key.name == "dup"
        }),
        "sibling v1alpha3 must still be attempted after exact v1 skip"
    );

    // Versionless key still matches either live object (parity with matches_object).
    let versionless = ferrum_edge::config_sources::k8s::K8sResourceKey {
        api_version: String::new(),
        kind: "EnvoyFilter".to_string(),
        namespace: "default".to_string(),
        name: "dup".to_string(),
    };
    assert!(versionless.matches_object(&first));
    assert!(versionless.matches_object(&second));
    let exact_v1 = ferrum_edge::config_sources::k8s::K8sResourceKey {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "EnvoyFilter".to_string(),
        namespace: "default".to_string(),
        name: "dup".to_string(),
    };
    assert!(exact_v1.matches_object(&first));
    assert!(!exact_v1.matches_object(&second));
}

#[test]
fn collecting_skips_index_is_nested_borrowed_not_linear_or_allocating() {
    let skip_type = TRANSLATE_SRC
        .split("struct SkippedObjectIdentities")
        .nth(1)
        .and_then(|rest| {
            rest.split("pub fn translate_k8s_objects_collecting_skips")
                .next()
        })
        .expect("SkippedObjectIdentities body");
    assert!(
        skip_type.contains("versionless"),
        "versionless empty-api_version set required"
    );
    assert!(
        skip_type.contains("exact"),
        "exact api_version set required"
    );
    assert!(
        skip_type.contains("fn contains_object"),
        "borrowed object membership required"
    );
    let contains_object = skip_type
        .split("fn contains_object(&self, object: &K8sObject) -> bool")
        .nth(1)
        .expect("contains_object body");
    assert!(
        contains_object.contains(".as_str()"),
        "lookup must borrow object fields as &str"
    );
    assert!(
        !contains_object.contains(".clone()"),
        "contains_object must not clone strings"
    );
    assert!(
        !contains_object.contains(".keys()"),
        "must not walk key iterators on lookup"
    );
    assert!(
        !contains_object.contains("matches_object"),
        "must not fall back to linear matches_object scans"
    );
    assert!(
        !contains_object.contains("to_string(") && !contains_object.contains("String::from"),
        "lookup must not construct owned identity strings"
    );

    // Many skipped identities: structural guarantee that membership stays keyed.
    let mut objects = vec![ferrum_gateway_class(), ferrum_gateway()];
    for index in 0..64 {
        objects.push(K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: "EnvoyFilter".to_string(),
            metadata: K8sMetadata {
                name: format!("filter-{index:03}"),
                uid: format!("uid-filter-{index:03}"),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: json!({}),
            status: Value::Object(serde_json::Map::new()),
        });
    }
    let (_translation, skipped) =
        ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips(
            &objects,
            options(),
        )
        .expect("many skips must terminate");
    assert_eq!(skipped.len(), 64);
    assert!(
        TRANSLATE_SRC.contains("skipped_identities.contains_object(object)"),
        "include filter must call borrowed contains_object"
    );
    assert!(
        TRANSLATE_SRC.contains("skipped_identities.insert_key(&key)"),
        "skip index must ingest the full resource key (including api_version)"
    );
}

#[test]
fn reference_grant_named_and_wildcard_backend_permissions() {
    let gateway_class = ferrum_gateway_class();
    let gateway = ferrum_gateway();
    let named_route = place_in_namespace(
        object(
            "HTTPRoute",
            "named-ok",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                }]
            }),
        ),
        "apps",
    );
    let wildcard_route = place_in_namespace(
        object(
            "HTTPRoute",
            "wild-ok",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{
                    "backendRefs": [{"name": "other", "namespace": "backend", "port": 8080}]
                }]
            }),
        ),
        "apps",
    );
    let named_grant = place_in_namespace(
        object(
            "ReferenceGrant",
            "named-api",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let wildcard_grant = place_in_namespace(
        object(
            "ReferenceGrant",
            "wild-svc",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service" }]
            }),
        ),
        "backend",
    );
    let objects = vec![
        gateway_class,
        gateway,
        named_route,
        wildcard_route,
        named_grant,
        wildcard_grant,
        backend_service("backend", "api"),
        backend_service("backend", "other"),
    ];
    let conflicts = gateway_api_route_conflicts(&objects, &options());
    let outcome = plan_gateway_api_status_updates(&objects, options(), &conflicts);
    let named = outcome
        .iter()
        .find(|u| u.name == "named-ok")
        .expect("named");
    let wild = outcome.iter().find(|u| u.name == "wild-ok").expect("wild");
    assert_eq!(
        condition_status(&named.status, "ResolvedRefs"),
        Some("True")
    );
    assert_eq!(condition_status(&wild.status, "ResolvedRefs"), Some("True"));
}

#[test]
fn reference_grant_malformed_name_and_group_fail_closed_at_status_boundaries() {
    // Absent `to.name` remains the valid Gateway API wildcard (covered by
    // reference_grant_named_and_wildcard_backend_permissions). Present non-string
    // `to.name` and missing/non-string required `group` must never grant.
    let malformed_names: &[(&str, Value)] = &[
        ("null", Value::Null),
        ("bool", json!(true)),
        ("number", json!(1)),
        ("array", json!(["api"])),
        ("object", json!({ "n": "api" })),
    ];

    for (label, bad_name) in malformed_names {
        let mut to_svc = json!({ "group": "", "kind": "Service" });
        to_svc
            .as_object_mut()
            .expect("object")
            .insert("name".to_string(), bad_name.clone());
        let mut to_secret = json!({ "group": "", "kind": "Secret" });
        to_secret
            .as_object_mut()
            .expect("object")
            .insert("name".to_string(), bad_name.clone());

        let gateway_class = ferrum_gateway_class();
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [{
                            "name": "edge-cert",
                            "namespace": "certs"
                        }]
                    }
                }]
            }),
        );
        let route = place_in_namespace(
            object(
                "HTTPRoute",
                "cross",
                json!({
                    "parentRefs": [{"name": "edge", "namespace": "default"}],
                    "rules": [{
                        "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                    }]
                }),
            ),
            "apps",
        );
        let secret_grant = place_in_namespace(
            object(
                "ReferenceGrant",
                "bad-secret-name",
                json!({
                    "from": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "namespace": "default"
                    }],
                    "to": [to_secret]
                }),
            ),
            "certs",
        );
        let backend_grant = place_in_namespace(
            object(
                "ReferenceGrant",
                "bad-svc-name",
                json!({
                    "from": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "HTTPRoute",
                        "namespace": "apps"
                    }],
                    "to": [to_svc]
                }),
            ),
            "backend",
        );
        let secret = K8sObject {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            metadata: K8sMetadata {
                name: "edge-cert".to_string(),
                uid: "uid-edge-cert".to_string(),
                namespace: "certs".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: json!({
                "type": "kubernetes.io/tls",
                "data": { "tls.crt": "QQ==", "tls.key": "QQ==" }
            }),
            status: Value::Object(serde_json::Map::new()),
        };
        let objects = vec![
            gateway_class,
            gateway,
            route,
            secret_grant,
            backend_grant,
            secret,
            backend_service("backend", "api"),
        ];
        let outcome = plan_gateway_api_status_updates(
            &objects,
            options(),
            &gateway_api_route_conflicts(&objects, &options()),
        );
        let gateway_status = outcome.iter().find(|u| u.kind == "Gateway").expect("gw");
        let route_status = outcome.iter().find(|u| u.name == "cross").expect("route");
        assert_eq!(
            condition_reason(&gateway_status.status, "ResolvedRefs"),
            Some("RefNotPermitted"),
            "present non-string to.name ({label}) must not grant Secret"
        );
        assert_eq!(
            condition_reason(&route_status.status, "ResolvedRefs"),
            Some("RefNotPermitted"),
            "present non-string to.name ({label}) must not grant Service"
        );
    }

    // Missing / non-string required groups must not collapse to core "".
    let group_cases: &[(&str, Value)] = &[
        ("missing", json!({})), // handled by omitting the key below
        ("null", Value::Null),
        ("bool", json!(false)),
        ("number", json!(0)),
        ("array", json!([])),
        ("object", json!({ "g": "" })),
    ];
    for (label, bad_group) in group_cases {
        for which in ["from", "to"] {
            let mut from = json!({
                "group": "gateway.networking.k8s.io",
                "kind": "HTTPRoute",
                "namespace": "apps"
            });
            let mut to = json!({ "group": "", "kind": "Service", "name": "api" });
            if *label == "missing" {
                if which == "from" {
                    from.as_object_mut().unwrap().remove("group");
                } else {
                    to.as_object_mut().unwrap().remove("group");
                }
            } else if which == "from" {
                from.as_object_mut()
                    .unwrap()
                    .insert("group".to_string(), bad_group.clone());
            } else {
                to.as_object_mut()
                    .unwrap()
                    .insert("group".to_string(), bad_group.clone());
            }
            let objects = vec![
                ferrum_gateway_class(),
                ferrum_gateway(),
                place_in_namespace(
                    object(
                        "HTTPRoute",
                        "cross",
                        json!({
                            "parentRefs": [{"name": "edge", "namespace": "default"}],
                            "rules": [{
                                "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                            }]
                        }),
                    ),
                    "apps",
                ),
                place_in_namespace(
                    object(
                        "ReferenceGrant",
                        "bad-group",
                        json!({ "from": [from], "to": [to] }),
                    ),
                    "backend",
                ),
                backend_service("backend", "api"),
            ];
            let outcome = plan_gateway_api_status_updates(
                &objects,
                options(),
                &gateway_api_route_conflicts(&objects, &options()),
            );
            let route_status = outcome.iter().find(|u| u.name == "cross").expect("route");
            assert_eq!(
                condition_reason(&route_status.status, "ResolvedRefs"),
                Some("RefNotPermitted"),
                "malformed {which}.group ({label}) must not grant Service"
            );
        }
    }

    // Explicit core-group empty string still permits Service and Secret refs.
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "tls": {
                    "certificateRefs": [{
                        "name": "edge-cert",
                        "namespace": "certs"
                    }]
                }
            }]
        }),
    );
    let secret = K8sObject {
        api_version: "v1".to_string(),
        kind: "Secret".to_string(),
        metadata: K8sMetadata {
            name: "edge-cert".to_string(),
            uid: "uid-edge-cert".to_string(),
            namespace: "certs".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({
            "type": "kubernetes.io/tls",
            "data": { "tls.crt": "QQ==", "tls.key": "QQ==" }
        }),
        status: Value::Object(serde_json::Map::new()),
    };
    let objects = vec![
        ferrum_gateway_class(),
        gateway,
        place_in_namespace(
            object(
                "HTTPRoute",
                "cross",
                json!({
                    "parentRefs": [{"name": "edge", "namespace": "default"}],
                    "rules": [{
                        "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                    }]
                }),
            ),
            "apps",
        ),
        place_in_namespace(
            object(
                "ReferenceGrant",
                "allow-cert",
                json!({
                    "from": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "namespace": "default"
                    }],
                    "to": [{ "group": "", "kind": "Secret", "name": "edge-cert" }]
                }),
            ),
            "certs",
        ),
        place_in_namespace(
            object(
                "ReferenceGrant",
                "allow-api",
                json!({
                    "from": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "HTTPRoute",
                        "namespace": "apps"
                    }],
                    "to": [{ "group": "", "kind": "Service", "name": "api" }]
                }),
            ),
            "backend",
        ),
        secret,
        backend_service("backend", "api"),
    ];
    let outcome = plan_gateway_api_status_updates(
        &objects,
        options(),
        &gateway_api_route_conflicts(&objects, &options()),
    );
    let gateway_status = outcome.iter().find(|u| u.kind == "Gateway").expect("gw");
    let route_status = outcome.iter().find(|u| u.name == "cross").expect("route");
    assert_eq!(
        condition_reason(&gateway_status.status, "ResolvedRefs"),
        Some("InvalidCertificateRef"),
        "explicit group:\"\" must still grant Secret (then TLS validity applies)"
    );
    assert_eq!(
        condition_status(&route_status.status, "ResolvedRefs"),
        Some("True"),
        "explicit group:\"\" must still grant Service"
    );
}

#[test]
fn reference_grant_denies_wrong_from_to_and_malformed_entries() {
    let gateway_class = ferrum_gateway_class();
    let gateway = ferrum_gateway();
    let route = place_in_namespace(
        object(
            "HTTPRoute",
            "cross",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                }]
            }),
        ),
        "apps",
    );
    let wrong_from_group = place_in_namespace(
        object(
            "ReferenceGrant",
            "bad-from-group",
            json!({
                "from": [{
                    "group": "example.com",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let wrong_from_kind = place_in_namespace(
        object(
            "ReferenceGrant",
            "bad-from-kind",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "TCPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let wrong_from_ns = place_in_namespace(
        object(
            "ReferenceGrant",
            "bad-from-ns",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "other"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let wrong_to_group = place_in_namespace(
        object(
            "ReferenceGrant",
            "bad-to-group",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "apps", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let wrong_to_kind = place_in_namespace(
        object(
            "ReferenceGrant",
            "bad-to-kind",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Secret", "name": "api" }]
            }),
        ),
        "backend",
    );
    let wrong_to_name = place_in_namespace(
        object(
            "ReferenceGrant",
            "bad-to-name",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "other" }]
            }),
        ),
        "backend",
    );
    let malformed_from = place_in_namespace(
        object(
            "ReferenceGrant",
            "malformed-from",
            json!({
                "from": "not-an-array",
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let malformed_to = place_in_namespace(
        object(
            "ReferenceGrant",
            "malformed-to",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": "not-an-array"
            }),
        ),
        "backend",
    );
    let malformed_entry = place_in_namespace(
        object(
            "ReferenceGrant",
            "malformed-entry",
            json!({
                "from": [{ "group": "gateway.networking.k8s.io", "kind": "HTTPRoute" }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    let objects = vec![
        gateway_class,
        gateway,
        route,
        wrong_from_group,
        wrong_from_kind,
        wrong_from_ns,
        wrong_to_group,
        wrong_to_kind,
        wrong_to_name,
        malformed_from,
        malformed_to,
        malformed_entry,
        backend_service("backend", "api"),
    ];
    let conflicts = gateway_api_route_conflicts(&objects, &options());
    let outcome = plan_gateway_api_status_updates(&objects, options(), &conflicts);
    let route_status = outcome
        .iter()
        .find(|u| u.name == "cross")
        .expect("route status");
    assert_eq!(
        condition_status(&route_status.status, "ResolvedRefs"),
        Some("False")
    );
    assert_eq!(
        condition_reason(&route_status.status, "ResolvedRefs"),
        Some("RefNotPermitted")
    );
}

#[test]
fn reference_grant_gateway_certificate_and_route_backend_parity() {
    let gateway_class = ferrum_gateway_class();
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "tls": {
                    "certificateRefs": [{
                        "name": "edge-cert",
                        "namespace": "certs"
                    }]
                }
            }]
        }),
    );
    let route = place_in_namespace(
        object(
            "HTTPRoute",
            "cross",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                }]
            }),
        ),
        "apps",
    );
    let secret_grant = place_in_namespace(
        object(
            "ReferenceGrant",
            "allow-cert",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "default"
                }],
                "to": [{ "group": "", "kind": "Secret", "name": "edge-cert" }]
            }),
        ),
        "certs",
    );
    let backend_grant = place_in_namespace(
        object(
            "ReferenceGrant",
            "allow-api",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    );
    // Present but invalid TLS material: permission check must pass (not RefNotPermitted)
    // before certificate validity is evaluated.
    let secret = K8sObject {
        api_version: "v1".to_string(),
        kind: "Secret".to_string(),
        metadata: K8sMetadata {
            name: "edge-cert".to_string(),
            uid: "uid-edge-cert".to_string(),
            namespace: "certs".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({
            "type": "kubernetes.io/tls",
            "data": { "tls.crt": "QQ==", "tls.key": "QQ==" }
        }),
        status: Value::Object(serde_json::Map::new()),
    };

    let without_grants = vec![
        gateway_class.clone(),
        gateway.clone(),
        route.clone(),
        secret.clone(),
        backend_service("backend", "api"),
    ];
    let without = plan_gateway_api_status_updates(
        &without_grants,
        options(),
        &gateway_api_route_conflicts(&without_grants, &options()),
    );
    let gateway_without = without.iter().find(|u| u.kind == "Gateway").unwrap();
    let route_without = without.iter().find(|u| u.name == "cross").unwrap();
    assert_eq!(
        condition_reason(&gateway_without.status, "ResolvedRefs"),
        Some("RefNotPermitted")
    );
    assert_eq!(
        condition_reason(&route_without.status, "ResolvedRefs"),
        Some("RefNotPermitted")
    );

    let with_grants = vec![
        gateway_class,
        gateway,
        route,
        secret_grant,
        backend_grant,
        secret,
        backend_service("backend", "api"),
    ];
    let with = plan_gateway_api_status_updates(
        &with_grants,
        options(),
        &gateway_api_route_conflicts(&with_grants, &options()),
    );
    let gateway_with = with.iter().find(|u| u.kind == "Gateway").unwrap();
    let route_with = with.iter().find(|u| u.name == "cross").unwrap();
    assert_eq!(
        condition_reason(&gateway_with.status, "ResolvedRefs"),
        Some("InvalidCertificateRef"),
        "matching Secret grant must clear RefNotPermitted before TLS validity"
    );
    assert_eq!(
        condition_status(&route_with.status, "ResolvedRefs"),
        Some("True"),
        "matching backend grant must permit the Service ref"
    );
}

#[test]
fn reference_grant_permission_index_avoids_raw_grant_scans() {
    assert!(
        STATUS_SRC.contains("reference_grant_permissions.allows("),
        "lookups must consult the precomputed permission index"
    );
    assert!(
        !STATUS_SRC.contains("reference_grants_by_ns"),
        "raw per-namespace grant vectors must be gone"
    );
    assert!(
        !STATUS_SRC.contains("reference_grant_has_from"),
        "per-lookup grant reparse helpers must be gone"
    );
    assert!(
        !STATUS_SRC.contains("reference_grant_has_secret_to"),
        "per-lookup grant reparse helpers must be gone"
    );
    assert!(
        !STATUS_SRC.contains("reference_grant_has_route_from"),
        "per-lookup grant reparse helpers must be gone"
    );
    assert!(
        !STATUS_SRC.contains("reference_grant_has_backend_to"),
        "per-lookup grant reparse helpers must be gone"
    );

    let ingest = STATUS_SRC
        .split("fn ingest(&mut self, grant: &'a K8sObject)")
        .nth(1)
        .and_then(|rest| rest.split("fn allows(").next())
        .expect("permission index ingest");
    assert!(
        ingest.contains("from_entries") && ingest.contains("to_entries"),
        "index must expand from×to once at build time"
    );
    assert!(
        STATUS_SRC.contains("fn reference_grant_optional_to_name"),
        "optional to.name tri-state helper must exist"
    );
    assert!(
        !ingest.contains("unwrap_or_default()"),
        "required group fields must not fail-open to empty core group"
    );
    assert!(
        !ingest.contains("Missing / non-string"),
        "ingest must not document non-string name as wildcard"
    );
    assert!(
        ingest.contains("reference_grant_optional_to_name(to)"),
        "ingest must use the unambiguous optional-name helper"
    );

    // Invalid-heavy / many-grants: planning must still succeed with the index.
    let mut objects = vec![ferrum_gateway_class(), ferrum_gateway()];
    for index in 0..128 {
        objects.push(place_in_namespace(
            object(
                "ReferenceGrant",
                &format!("noise-{index:03}"),
                json!({
                    "from": [{
                        "group": "gateway.networking.k8s.io",
                        "kind": "HTTPRoute",
                        "namespace": format!("noise-{index:03}")
                    }],
                    "to": [{ "group": "", "kind": "Service", "name": format!("svc-{index:03}") }]
                }),
            ),
            "backend",
        ));
    }
    // One valid grant buried among the noise.
    objects.push(place_in_namespace(
        object(
            "ReferenceGrant",
            "allow-api",
            json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "apps"
                }],
                "to": [{ "group": "", "kind": "Service", "name": "api" }]
            }),
        ),
        "backend",
    ));
    objects.push(place_in_namespace(
        object(
            "HTTPRoute",
            "cross",
            json!({
                "parentRefs": [{"name": "edge", "namespace": "default"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "namespace": "backend", "port": 8080}]
                }]
            }),
        ),
        "apps",
    ));
    objects.push(backend_service("backend", "api"));

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
    let route = outcome
        .updates
        .iter()
        .find(|u| u.name == "cross")
        .expect("route");
    assert_eq!(
        condition_status(&route.status, "ResolvedRefs"),
        Some("True"),
        "precomputed index must find the matching grant among many without raw vector scans"
    );
}
