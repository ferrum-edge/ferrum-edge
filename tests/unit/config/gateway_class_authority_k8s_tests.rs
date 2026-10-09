//! GatewayClass observed-authority contract (issue #3835).
//!
//! A Gateway is Ferrum-managed only when the current snapshot contains the
//! referenced GatewayClass and `spec.controllerName` exactly matches Ferrum.
//! The class name spelling is never a fallback — including the default `ferrum`.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayClassAuthority, K8sMetadata, K8sObject,
    K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::plan_gateway_api_status_updates;
use serde_json::{Value, json};

const TRANSLATE_SRC: &str = include_str!("../../../src/config_sources/k8s/mod.rs");
const STATUS_SRC: &str = include_str!("../../../src/k8s_controller/status.rs");
const AUTHORITY_SRC: &str = include_str!("../../../src/config_sources/k8s/gateway_class.rs");

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: namespace.to_string(),
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

fn gateway_class(name: &str, controller: &str) -> K8sObject {
    object(
        "GatewayClass",
        name,
        "",
        json!({ "controllerName": controller }),
    )
}

fn ferrum_class() -> K8sObject {
    gateway_class("ferrum", FERRUM_GATEWAY_CONTROLLER_NAME)
}

fn http_gateway(class_name: &str) -> K8sObject {
    object(
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": class_name,
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    )
}

fn https_gateway(class_name: &str) -> K8sObject {
    object(
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": class_name,
            "listeners": [{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "tls": {
                    "certificateRefs": [{"name": "edge-cert"}]
                },
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    )
}

fn tls_secret() -> K8sObject {
    K8sObject {
        api_version: "v1".to_string(),
        kind: "Secret".to_string(),
        metadata: K8sMetadata {
            name: "edge-cert".to_string(),
            uid: "uid-edge-cert".to_string(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec: json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": "cA==",
                "tls.key": "cA=="
            }
        }),
        status: Value::Object(serde_json::Map::new()),
    }
}

fn http_route() -> K8sObject {
    object(
        "HTTPRoute",
        "app",
        "default",
        json!({
            "parentRefs": [{"name": "edge"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/app"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    )
}

fn service() -> K8sObject {
    K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: "api".to_string(),
            uid: "uid-api".to_string(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec: json!({
            "selector": {"app": "api"},
            "ports": [{"port": 8080, "targetPort": 8080}]
        }),
        status: Value::Object(serde_json::Map::new()),
    }
}

fn programmed(objects: &[K8sObject]) -> bool {
    let translation = translate_k8s_objects(objects, options()).expect("translation succeeds");
    !translation.config.proxies.is_empty() || !translation.materialized_gateway_listeners.is_empty()
}

fn gateway_status_planned(objects: &[K8sObject]) -> bool {
    plan_gateway_api_status_updates(objects, options(), &[])
        .iter()
        .any(|update| update.kind == "Gateway" && update.name == "edge")
}

fn translation_and_status_agree(objects: &[K8sObject]) {
    let owned = programmed(objects);
    assert_eq!(
        owned,
        gateway_status_planned(objects),
        "translation programming and Gateway status eligibility must share one authority verdict"
    );
}

#[test]
fn name_only_fallbacks_are_gone_from_translation_and_status() {
    assert!(
        AUTHORITY_SRC.contains("GatewayClassAuthority"),
        "translation and status must share one GatewayClass authority type"
    );
    assert!(
        !TRANSLATE_SRC.contains("class_name == \"ferrum\"")
            && !TRANSLATE_SRC.contains("unwrap_or_else(|| class_name == \"ferrum\")"),
        "translator must not infer ownership from the literal class name"
    );
    assert!(
        !STATUS_SRC.contains("DEFAULT_FERRUM_GATEWAY_CLASS_NAME"),
        "status planning must not keep a name-only default-class fallback"
    );
    assert!(
        STATUS_SRC.contains("GatewayClassAuthority::for_gateway"),
        "status planning must use the shared GatewayClass authority helper"
    );
}

#[test]
fn absent_class_named_ferrum_is_not_managed() {
    let objects = vec![http_gateway("ferrum"), http_route(), service()];
    assert!(
        !programmed(&objects),
        "an absent GatewayClass must not produce listeners, proxies, or route attachments"
    );
    assert!(
        !gateway_status_planned(&objects),
        "an absent GatewayClass must not plan Gateway Accepted/Programmed status"
    );
    translation_and_status_agree(&objects);

    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .is_empty(),
        "absent class must not produce a frontend TLS serving plan"
    );
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains(r#"GatewayClass "ferrum" is not present"#)),
        "missing class must surface a bounded unresolved-authority diagnostic: {:?}",
        translation.warnings
    );

    let https_objects = vec![https_gateway("ferrum"), tls_secret()];
    let https_translation =
        translate_k8s_objects(&https_objects, options()).expect("https snapshot translates");
    assert!(
        https_translation
            .config
            .frontend_tls_certificate_sources
            .is_empty(),
        "an absent class must not produce a frontend TLS serving plan"
    );
}

#[test]
fn creating_owned_class_programs_the_unchanged_gateway() {
    let without_class = vec![http_gateway("ferrum"), http_route(), service()];
    assert!(!programmed(&without_class));

    let with_class = vec![
        ferrum_class(),
        http_gateway("ferrum"),
        http_route(),
        service(),
    ];
    assert!(
        programmed(&with_class),
        "creating the owned GatewayClass must program the unchanged Gateway"
    );
    translation_and_status_agree(&with_class);
}

#[test]
fn deleting_owned_class_withdraws_generated_state() {
    let present = vec![
        ferrum_class(),
        http_gateway("ferrum"),
        http_route(),
        service(),
    ];
    let owned = translate_k8s_objects(&present, options()).expect("owned snapshot translates");
    assert!(
        !owned.config.proxies.is_empty(),
        "owned class must materialize route proxies"
    );
    assert!(
        !owned.materialized_gateway_listeners.is_empty(),
        "owned class must materialize gateway listeners"
    );

    let deleted: Vec<K8sObject> = present
        .into_iter()
        .filter(|object| object.kind != "GatewayClass")
        .collect();
    let withdrawn = translate_k8s_objects(&deleted, options()).expect("deleted class translates");
    assert!(
        withdrawn.config.proxies.is_empty(),
        "deleting the GatewayClass must withdraw generated proxies"
    );
    assert!(
        withdrawn.materialized_gateway_listeners.is_empty(),
        "deleting the GatewayClass must withdraw generated listeners"
    );
    assert!(
        withdrawn.materialized_route_parents.is_empty(),
        "deleting the GatewayClass must withdraw route attachments"
    );
    assert!(
        !gateway_status_planned(&deleted),
        "status planning must stop claiming the Gateway after class deletion"
    );
}

#[test]
fn changing_controller_name_to_foreign_withdraws() {
    let owned = vec![
        ferrum_class(),
        http_gateway("ferrum"),
        http_route(),
        service(),
    ];
    assert!(programmed(&owned));

    let foreign = vec![
        gateway_class("ferrum", "example.com/other-controller"),
        http_gateway("ferrum"),
        http_route(),
        service(),
    ];
    assert!(
        !programmed(&foreign),
        "a controllerName change away from Ferrum must withdraw programming"
    );
    assert!(!gateway_status_planned(&foreign));
    translation_and_status_agree(&foreign);
}

#[test]
fn foreign_owned_class_named_ferrum_is_never_managed() {
    let objects = vec![
        gateway_class("ferrum", "example.com/other-controller"),
        http_gateway("ferrum"),
        http_route(),
        service(),
    ];
    assert!(!programmed(&objects));
    assert!(!gateway_status_planned(&objects));
    translation_and_status_agree(&objects);
}

#[test]
fn ferrum_owned_non_default_class_name_is_supported() {
    let objects = vec![
        gateway_class("edge-class", FERRUM_GATEWAY_CONTROLLER_NAME),
        http_gateway("edge-class"),
        http_route(),
        service(),
    ];
    assert!(
        programmed(&objects),
        "a Ferrum-owned class with a non-default name must still program"
    );
    translation_and_status_agree(&objects);
}

#[test]
fn informer_list_order_does_not_change_authority() {
    let class = ferrum_class();
    let gateway = http_gateway("ferrum");
    let route = http_route();
    let svc = service();

    let class_first = vec![class.clone(), gateway.clone(), route.clone(), svc.clone()];
    let gateway_first = vec![gateway, route, svc, class];
    assert!(programmed(&class_first));
    assert!(programmed(&gateway_first));
    translation_and_status_agree(&class_first);
    translation_and_status_agree(&gateway_first);
}

#[test]
fn incomplete_snapshot_without_cluster_scoped_class_cannot_become_ownership() {
    // The incomplete/failed cluster-scoped list shape is a snapshot that
    // contains namespaced Gateways/Routes but no GatewayClass objects. That
    // must fail closed as Missing, never as name-inferred ownership.
    let incomplete = vec![http_gateway("ferrum"), http_route(), service()];
    let translation =
        translate_k8s_objects(&incomplete, options()).expect("incomplete snapshot translates");
    assert!(
        translation.config.proxies.is_empty()
            && translation.materialized_gateway_listeners.is_empty()
            && translation.materialized_route_parents.is_empty()
            && translation
                .config
                .frontend_tls_certificate_sources
                .is_empty(),
        "an incomplete cluster-scoped snapshot must not become positive ownership"
    );
    assert!(
        !gateway_status_planned(&incomplete),
        "status must not claim Accepted/Programmed from an incomplete class snapshot"
    );
    assert_eq!(
        GatewayClassAuthority::for_gateway(&http_gateway("ferrum"), |_| None),
        GatewayClassAuthority::Missing
    );
}

#[test]
fn empty_gateway_class_name_is_missing_not_owned() {
    let gateway = object(
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "",
            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
        }),
    );
    assert_eq!(
        GatewayClassAuthority::for_gateway(&gateway, |_| {
            panic!("empty class name must not consult the index")
        }),
        GatewayClassAuthority::Missing
    );
    assert!(!programmed(&[ferrum_class(), gateway]));
}
