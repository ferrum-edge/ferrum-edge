//! Integration coverage for Gateway API `ListenerSet` attachment (#3277).
//!
//! Pins translate → status planning for valid attachment, NotAllowed default,
//! hostname conflict fail-closed, and delete withdrawal without spawning the
//! proxy binary (hosted CI owns the live black-box lab step).

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
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

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    )
}

fn gateway(allowed: bool) -> K8sObject {
    let mut spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "http",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "gw.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]
    });
    if allowed {
        spec.as_object_mut().unwrap().insert(
            "allowedListeners".to_string(),
            json!({ "namespaces": { "from": "Same" } }),
        );
    }
    object("Gateway", "edge", spec)
}

fn listenerset() -> K8sObject {
    object(
        "ListenerSet",
        "extra",
        json!({
            "parentRef": {
                "kind": "Gateway",
                "name": "edge",
                "namespace": "default"
            },
            "listeners": [{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "set.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]
        }),
    )
}

fn service() -> K8sObject {
    let mut svc = object(
        "Service",
        "backend",
        json!({
            "selector": { "app": "backend" },
            "ports": [{ "port": 8080, "protocol": "TCP" }]
        }),
    );
    svc.api_version = "v1".to_string();
    svc
}

fn route() -> K8sObject {
    object(
        "HTTPRoute",
        "set-route",
        json!({
            "parentRefs": [{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default"
            }],
            "hostnames": ["set.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": "/set" } }],
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    )
}

#[test]
fn listenerset_attachment_status_and_withdrawal_round_trip() {
    let with_set = vec![
        gateway_class(),
        gateway(true),
        listenerset(),
        service(),
        route(),
    ];
    let translation = translate_k8s_objects(&with_set, options()).expect("translate");
    assert!(
        translation
            .listenerset_statuses
            .iter()
            .any(|status| status.attached && status.accepted)
    );
    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "set.example.com") })
    );

    let updates =
        plan_gateway_api_status_updates(&with_set, options(), &translation.route_conflicts);
    assert!(updates.iter().any(|update| {
        update.kind == "Gateway"
            && update.name == "edge"
            && update.status["attachedListenerSets"].as_u64() == Some(1)
    }));
    assert!(updates.iter().any(|update| {
        update.kind == "ListenerSet"
            && update.name == "extra"
            && update.status["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| condition["type"] == "Accepted" && condition["status"] == "True")
    }));

    let without_set: Vec<_> = with_set
        .into_iter()
        .filter(|object| object.kind != "ListenerSet")
        .collect();
    let (withdrawn, skipped) =
        translate_k8s_objects_collecting_skips(&without_set, options()).expect("withdraw");
    assert!(
        skipped.values().any(|error| {
            let error = error.to_string();
            error.contains("set-route")
                && error.contains("not permitted by the target ListenerSet listener")
        }),
        "the route to the deleted ListenerSet must be skipped: {skipped:?}"
    );
    assert!(withdrawn.listenerset_statuses.is_empty());
    assert!(
        !withdrawn
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.hosts.iter().any(|host| host == "set.example.com"))
    );
}

#[test]
fn listenerset_not_allowed_by_default_fails_closed() {
    let objects = vec![gateway_class(), gateway(false), listenerset(), service()];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "extra")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "NotAllowed");
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let gateway_update = updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("gateway status");
    assert_eq!(
        gateway_update.status["attachedListenerSets"].as_u64(),
        Some(0)
    );
}

#[test]
fn foreign_listenerset_status_does_not_claim_ferrum_ownership() {
    let mut foreign = listenerset();
    foreign.spec["parentRef"]["name"] = json!("foreign-edge");
    foreign.status = json!({
        "conditions": [{
            "type": "Accepted",
            "status": "True",
            "reason": "Accepted",
            "message": "Another controller accepted this ListenerSet"
        }]
    });

    let foreign_updates = plan_gateway_api_status_updates(&[foreign.clone()], options(), &[]);
    assert!(
        foreign_updates
            .iter()
            .all(|update| update.kind != "ListenerSet"),
        "a generic foreign Accepted reason must not make Ferrum overwrite an unmanaged ListenerSet"
    );

    foreign.status["conditions"][0]["message"] =
        json!("[ferrum-edge] previously managed ListenerSet");
    let cleanup_updates = plan_gateway_api_status_updates(&[foreign], options(), &[]);
    assert!(
        cleanup_updates
            .iter()
            .any(|update| update.kind == "ListenerSet"),
        "Ferrum's explicit marker must retain eligibility to clean up its own stale status"
    );
}
