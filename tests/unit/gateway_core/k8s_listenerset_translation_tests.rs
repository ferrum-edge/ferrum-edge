//! Gateway API `ListenerSet` translation, attachment, and status coverage (#3277).
//!
//! Pins allowedListeners gating, parentRef attachment, listener merge/conflict
//! precedence, HTTPRoute parentRef to ListenerSet materialization, status
//! parity (`Accepted`/`Programmed`/`Conflicted`, Gateway `attachedListenerSets`),
//! and update/delete withdrawal — not only first-start construction.

use base64::Engine as _;
use ferrum_edge::config_sources::k8s::{
    GatewayApiListenerKey, GatewayApiListenerParentKind, K8sMetadata, K8sObject,
    K8sTranslationOptions, translate_k8s_objects, translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::reconciler::merge_k8s_translation;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};

const WATCHER_SRC: &str = include_str!("../../../src/k8s_controller/watcher.rs");
const RBAC_SRC: &str =
    include_str!("../../../charts/ferrum-mesh/templates/control-plane-rbac.yaml");

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
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

fn tls_secret(name: &str, namespace: &str) -> K8sObject {
    let mut secret = object(
        "Secret",
        name,
        json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": base64::engine::general_purpose::STANDARD
                    .encode(include_bytes!("../../certs/server.crt")),
                "tls.key": base64::engine::general_purpose::STANDARD
                    .encode(include_bytes!("../../certs/server.key"))
            }
        }),
    );
    secret.api_version = "v1".to_string();
    secret.metadata.namespace = namespace.to_string();
    secret
}

fn http_gateway(name: &str, allowed_from: Option<&str>) -> K8sObject {
    let mut spec = json!({
        "gatewayClassName": "ferrum",
        "listeners": [{
            "name": "http",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "gateway.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]
    });
    if let Some(from) = allowed_from {
        spec.as_object_mut().unwrap().insert(
            "allowedListeners".to_string(),
            json!({ "namespaces": { "from": from } }),
        );
    }
    object("Gateway", name, spec)
}

fn listenerset(name: &str, gateway: &str, listeners: Value) -> K8sObject {
    object(
        "ListenerSet",
        name,
        json!({
            "parentRef": {
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": gateway,
                "namespace": "default"
            },
            "listeners": listeners
        }),
    )
}

fn http_route(name: &str, parent_refs: Value, hostname: &str, path: &str) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        json!({
            "parentRefs": parent_refs,
            "hostnames": [hostname],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": path } }],
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    )
}

fn service(name: &str) -> K8sObject {
    let mut svc = object(
        "Service",
        name,
        json!({
            "ports": [{ "port": 8080, "protocol": "TCP" }]
        }),
    );
    svc.api_version = "v1".to_string();
    svc
}

#[test]
fn watcher_and_rbac_cover_listenerset() {
    assert!(
        WATCHER_SRC.contains("kind: \"ListenerSet\""),
        "controller must optionally watch ListenerSet"
    );
    assert!(
        WATCHER_SRC.contains("plural: \"listenersets\""),
        "ListenerSet plural must be listenersets"
    );
    assert!(
        RBAC_SRC.contains("listenersets"),
        "chart RBAC must grant ListenerSet list/watch"
    );
    assert!(
        RBAC_SRC.contains("listenersets/status"),
        "chart RBAC must grant ListenerSet status patch"
    );
}

#[test]
fn listenerset_default_not_allowed() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", None),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "extra.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
        service("backend"),
        http_route(
            "via-disallowed-listenerset",
            json!([{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default"
            }]),
            "extra.example.com",
            "/must-not-attach",
        ),
    ];
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, options()).expect("translate");
    assert!(
        skipped.values().any(|error| {
            let error = error.to_string();
            error.contains("via-disallowed-listenerset")
                && error.contains("not permitted by the target ListenerSet listener")
        }),
        "the disallowed ListenerSet route must fail closed: {skipped:?}"
    );
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "extra")
        .expect("listenerset status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "NotAllowed");
    assert!(!status.attached);

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let listenerset_update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == "extra")
        .expect("ListenerSet status update");
    let accepted = listenerset_update.status["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .unwrap();
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], "NotAllowed");

    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "via-disallowed-listenerset")
        .expect("HTTPRoute status update");
    let route_conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions");
    let route_accepted = route_conditions
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .expect("route Accepted condition");
    assert_eq!(route_accepted["status"], "False");
    assert_eq!(route_accepted["reason"], "NotAllowedByListeners");
}

#[test]
fn listenerset_namespace_selector_reuses_strict_gateway_validation() {
    let mut namespace = object("Namespace", "extension-ns", json!({}));
    namespace.api_version = "v1".to_string();
    namespace.metadata.namespace.clear();
    namespace
        .metadata
        .labels
        .insert("team".to_string(), "payments".to_string());

    let mut selected_gateway = http_gateway("selected", None);
    selected_gateway.spec.as_object_mut().unwrap().insert(
        "allowedListeners".to_string(),
        json!({
            "namespaces": {
                "from": "Selector",
                "selector": {"matchLabels": {"team": "payments"}}
            }
        }),
    );
    let mut selected = listenerset(
        "selected-set",
        "selected",
        json!([{
            "name": "http",
            "port": 8080,
            "protocol": "HTTP"
        }]),
    );
    selected.metadata.namespace = "extension-ns".to_string();

    let mut malformed_gateway = http_gateway("malformed", None);
    malformed_gateway.spec.as_object_mut().unwrap().insert(
        "allowedListeners".to_string(),
        json!({
            "namespaces": {
                "from": "Selector",
                "selector": {"matchLabels": []}
            }
        }),
    );
    let malformed = listenerset(
        "malformed-set",
        "malformed",
        json!([{
            "name": "http",
            "port": 8081,
            "protocol": "HTTP"
        }]),
    );

    let translation = translate_k8s_objects(
        &[
            namespace,
            gateway_class(),
            selected_gateway,
            selected,
            malformed_gateway,
            malformed,
        ],
        options().with_source_namespaces(vec!["default".to_string(), "extension-ns".to_string()]),
    )
    .expect("translate strict allowedListeners selectors");
    assert!(
        translation
            .listenerset_statuses
            .iter()
            .any(|status| { status.resource.name == "selected-set" && status.accepted })
    );
    assert!(translation.listenerset_statuses.iter().any(|status| {
        status.resource.name == "malformed-set"
            && !status.accepted
            && status.accepted_reason == "NotAllowed"
    }));
}

#[test]
fn listenerset_outside_source_namespaces_cannot_publish_route_policy() {
    let mut excluded = listenerset(
        "excluded-set",
        "edge",
        json!([{
            "name": "http",
            "port": 8081,
            "protocol": "HTTP",
            "hostname": "excluded.example.com",
            "allowedRoutes": { "namespaces": { "from": "All" } }
        }]),
    );
    excluded.metadata.namespace = "excluded".to_string();

    let mut gateway = http_gateway("edge", None);
    gateway.spec.as_object_mut().unwrap().insert(
        "allowedListeners".to_string(),
        json!({ "namespaces": { "from": "All" } }),
    );

    let objects = vec![
        gateway_class(),
        gateway,
        excluded,
        service("backend"),
        http_route(
            "must-not-use-excluded-listenerset",
            json!([{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "excluded-set",
                "namespace": "excluded"
            }]),
            "excluded.example.com",
            "/excluded",
        ),
    ];
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, options()).expect("translate");
    assert!(
        skipped.values().any(|error| {
            let error = error.to_string();
            error.contains("must-not-use-excluded-listenerset")
                && error.contains("not permitted by the target ListenerSet listener")
        }),
        "an out-of-scope ListenerSet must not publish route policy: {skipped:?}"
    );
    assert!(translation.listenerset_statuses.is_empty());
    assert!(translation.config.proxies.iter().all(|proxy| {
        !proxy
            .hosts
            .iter()
            .any(|host| host == "excluded.example.com")
    }));
}

#[test]
fn listenerset_attaches_and_materializes_http_route() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "extra.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
        service("backend"),
        http_route(
            "via-listenerset",
            json!([{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default"
            }]),
            "extra.example.com",
            "/via-set",
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "extra")
        .expect("listenerset status");
    assert!(status.accepted);
    assert!(status.attached);
    assert!(
        translation.config.proxies.iter().any(|proxy| {
            proxy.hosts.iter().any(|host| host == "extra.example.com")
                && proxy
                    .listen_path
                    .as_deref()
                    .is_some_and(|path| path.contains("via-set"))
        }),
        "HTTPRoute parentRef to ListenerSet must materialize a proxy: {:?}",
        translation.config.proxies
    );
    assert!(
        translation.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "listenerset-extra-extra-http")
        }),
        "accepted ListenerSet listener must materialize a mesh service"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let gateway_update = updates
        .iter()
        .find(|update| update.kind == "Gateway" && update.name == "edge")
        .expect("Gateway status");
    assert_eq!(
        gateway_update.status["attachedListenerSets"].as_u64(),
        Some(1)
    );
    let listenerset_update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == "extra")
        .expect("ListenerSet status");
    let accepted = listenerset_update.status["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .unwrap();
    assert_eq!(accepted["status"], "True");

    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "via-listenerset")
        .expect("HTTPRoute status");
    let route_conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions");
    for condition_type in ["Accepted", "Programmed"] {
        let condition = route_conditions
            .iter()
            .find(|condition| condition["type"] == condition_type)
            .expect("route condition");
        assert_eq!(
            condition["status"], "True",
            "ListenerSet route {condition_type} condition: {condition:?}"
        );
    }
}

#[test]
fn listenerset_invalid_parent_and_unmanaged_gateway_fail_closed() {
    let missing_parent = vec![
        gateway_class(),
        listenerset(
            "orphan",
            "missing",
            json!([{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&missing_parent, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "orphan")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ParentNotAccepted");

    let mut other_class = object(
        "GatewayClass",
        "other",
        json!({ "controllerName": "example.com/other" }),
    );
    other_class.metadata.namespace.clear();
    let unmanaged = vec![
        other_class,
        {
            let mut gw = http_gateway("foreign", Some("Same"));
            gw.spec
                .as_object_mut()
                .unwrap()
                .insert("gatewayClassName".to_string(), json!("other"));
            gw
        },
        listenerset(
            "foreign-set",
            "foreign",
            json!([{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&unmanaged, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "foreign-set")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ParentNotAccepted");
}

#[test]
fn listenerset_hostname_conflict_marks_loser_not_materialized() {
    let mut older = listenerset(
        "older",
        "edge",
        json!([{
            "name": "shared",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "conflict.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]),
    );
    older.metadata.creation_timestamp = Some("2024-01-01T00:00:00Z".to_string());
    let mut newer = listenerset(
        "newer",
        "edge",
        json!([{
            "name": "shared",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "conflict.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }]),
    );
    // A malformed/file-sourced object without a trustworthy API-server
    // timestamp must not preempt a proven older ListenerSet and steal traffic.
    newer.metadata.creation_timestamp = Some("not-a-timestamp".to_string());

    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        older,
        newer,
        service("backend"),
        http_route(
            "to-newer",
            json!([{
                "kind": "ListenerSet",
                "name": "newer",
                "namespace": "default"
            }]),
            "conflict.example.com",
            "/newer",
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let newer_status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "newer")
        .expect("newer status");
    assert!(
        newer_status
            .listener_conflicts
            .iter()
            .any(|(name, reason)| name == "shared" && reason == "HostnameConflict"),
        "newer listener must report HostnameConflict: {:?}",
        newer_status.listener_conflicts
    );
    assert!(
        !translation.config.proxies.iter().any(|proxy| {
            proxy
                .hosts
                .iter()
                .any(|host| host == "conflict.example.com")
                && proxy
                    .listen_path
                    .as_deref()
                    .is_some_and(|path| path.contains("newer"))
        }),
        "conflicted ListenerSet must not materialize route traffic"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let newer_update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == "newer")
        .expect("newer status update");
    let listener = newer_update.status["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|listener| listener["name"] == "shared")
        .expect("listener status");
    let conflicted = listener["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Conflicted")
        .unwrap();
    assert_eq!(conflicted["status"], "True");
    assert_eq!(conflicted["reason"], "HostnameConflict");
    for condition_type in ["Accepted", "Programmed"] {
        let condition = listener["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|condition| condition["type"] == condition_type)
            .expect("listener condition");
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "PortUnavailable");
    }
}

#[test]
fn listenerset_protocol_conflict_with_gateway_listener() {
    let objects = vec![
        gateway_class(),
        {
            let mut gw = http_gateway("edge", Some("Same"));
            gw.spec["listeners"] = json!([{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "shared.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]);
            gw
        },
        listenerset(
            "tcp-conflict",
            "edge",
            json!([{
                "name": "tcp",
                "port": 80,
                "protocol": "TCP",
                "allowedRoutes": {
                    "kinds": [{ "kind": "TCPRoute" }],
                    "namespaces": { "from": "Same" }
                }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "tcp-conflict")
        .expect("status");
    assert!(
        status
            .listener_conflicts
            .iter()
            .any(|(name, reason)| name == "tcp" && reason == "ProtocolConflict")
    );
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ListenersNotValid");
    let gateway_http = GatewayApiListenerKey {
        namespace: "default".to_string(),
        parent_kind: GatewayApiListenerParentKind::Gateway,
        gateway: "edge".to_string(),
        listener: "http".to_string(),
    };
    assert_eq!(
        translation
            .listener_conflicts
            .get(&gateway_http)
            .map(|conflict| conflict.reason),
        Some("ProtocolConflict"),
        "Gateway HTTP claim must appear in translation.listener_conflicts for status parity: {:?}",
        translation.listener_conflicts
    );
}

/// Regression for upstream `HTTPRouteHTTPSListener`: a Gateway may declare an
/// HTTPS catch-all listener alongside hostname-specific HTTPS siblings on the
/// same port. ListenerSet conflict finalization must not treat those Gateway
/// siblings as HostnameConflict losers — otherwise a sectionName attachment to
/// the hostname listener reports Accepted=True/NoRules with no materialization.
#[test]
fn gateway_https_catch_all_and_hostname_siblings_stay_materializable() {
    let secret = tls_secret("edge-cert", "default");

    let gateway = object(
        "Gateway",
        "same-namespace-with-https-listener",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "allowedRoutes": { "namespaces": { "from": "Same" } },
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{ "name": "edge-cert" }]
                    }
                },
                {
                    "name": "https-with-hostname",
                    "port": 443,
                    "hostname": "second-example.org",
                    "protocol": "HTTPS",
                    "allowedRoutes": { "namespaces": { "from": "Same" } },
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{ "name": "edge-cert" }]
                    }
                }
            ]
        }),
    );

    let route_with_hostname = object(
        "HTTPRoute",
        "httproute-https-test",
        json!({
            "parentRefs": [{ "name": "same-namespace-with-https-listener" }],
            "hostnames": ["example.org"],
            "rules": [{
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    );
    let route_no_hostname = object(
        "HTTPRoute",
        "httproute-https-test-no-hostname",
        json!({
            "parentRefs": [{
                "name": "same-namespace-with-https-listener",
                "sectionName": "https-with-hostname"
            }],
            "rules": [{
                "backendRefs": [{ "name": "backend", "port": 8080 }]
            }]
        }),
    );

    let objects = vec![
        gateway_class(),
        gateway,
        secret,
        service("backend"),
        route_with_hostname,
        route_no_hostname,
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "example.org") }),
        "catch-all HTTPS listener must still materialize hostname routes"
    );
    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "second-example.org") }),
        "hostname-specific HTTPS sibling must stay materializable for sectionName routes"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let no_hostname_update = updates
        .iter()
        .find(|update| {
            update.kind == "HTTPRoute" && update.name == "httproute-https-test-no-hostname"
        })
        .expect("no-hostname route status");
    let conditions = no_hostname_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("parent conditions");
    let accepted = conditions
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .expect("Accepted");
    let programmed = conditions
        .iter()
        .find(|condition| condition["type"] == "Programmed")
        .expect("Programmed");
    assert_eq!(accepted["status"], "True");
    assert_eq!(
        accepted["reason"], "Accepted",
        "must not report NoRules when the HTTPS sectionName listener materializes: {accepted}"
    );
    assert_eq!(programmed["status"], "True");
    assert_eq!(programmed["reason"], "Programmed");
}

#[test]
fn duplicate_gateway_listener_section_fails_closed() {
    let mut gateway = http_gateway("edge", Some("Same"));
    gateway.spec["listeners"] = json!([
        {
            "name": "a-primary",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "shared.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        },
        {
            "name": "b-duplicate",
            "port": 80,
            "protocol": "HTTP",
            "hostname": "shared.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }
    ]);
    let objects = vec![
        gateway_class(),
        gateway,
        service("backend"),
        http_route(
            "duplicate-section-route",
            json!([{
                "name": "edge",
                "sectionName": "b-duplicate"
            }]),
            "shared.example.com",
            "/must-not-materialize",
        ),
    ];

    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(translation.warnings.iter().any(|warning| {
        warning.contains("Gateway default/edge listener b-duplicate rejected: HostnameConflict")
    }));
    let duplicate_key = GatewayApiListenerKey {
        namespace: "default".to_string(),
        parent_kind: GatewayApiListenerParentKind::Gateway,
        gateway: "edge".to_string(),
        listener: "b-duplicate".to_string(),
    };
    let conflict = translation
        .listener_conflicts
        .get(&duplicate_key)
        .expect("duplicate Gateway listener must be recorded as conflicted");
    assert_eq!(conflict.reason, "HostnameConflict");
    assert!(
        !translation.config.proxies.iter().any(|proxy| proxy
            .listen_path
            .as_deref()
            .is_some_and(|path| path.contains("must-not-materialize"))),
        "a route attached to a duplicate Gateway section must not materialize"
    );
}

#[test]
fn incompatible_gateway_listener_protocol_fails_closed() {
    let mut gateway = http_gateway("edge", Some("Same"));
    gateway.spec["listeners"] = json!([
        {
            "name": "a-http",
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        },
        {
            "name": "b-tcp",
            "port": 80,
            "protocol": "TCP",
            "allowedRoutes": {
                "kinds": [{ "kind": "TCPRoute" }],
                "namespaces": { "from": "Same" }
            }
        }
    ]);
    let objects = vec![gateway_class(), gateway];

    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(translation.warnings.iter().any(|warning| {
        warning.contains("Gateway default/edge listener b-tcp rejected: ProtocolConflict")
    }));
    assert!(translation.warnings.iter().any(|warning| {
        warning.contains("Gateway default/edge listener a-http rejected: ProtocolConflict")
    }));
    assert!(
        translation
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.services.as_slice())
            .unwrap_or(&[])
            .iter()
            .all(|service| service.name != "edge-a-http" && service.name != "edge-b-tcp"),
        "neither protocol-conflicted claim may become a MeshService: {:?}",
        translation.config.mesh
    );

    for listener in ["a-http", "b-tcp"] {
        let key = GatewayApiListenerKey {
            namespace: "default".to_string(),
            parent_kind: GatewayApiListenerParentKind::Gateway,
            gateway: "edge".to_string(),
            listener: listener.to_string(),
        };
        let conflict = translation
            .listener_conflicts
            .get(&key)
            .unwrap_or_else(|| panic!("translation must record ProtocolConflict for {listener}"));
        assert_eq!(conflict.reason, "ProtocolConflict");
        assert_eq!(
            conflict.message,
            "Port 80 is claimed by incompatible protocol families on the same TCP \
             transport (HTTP-family vs raw stream), so every conflicting claim on this \
             port is refused (Conflicted)."
        );
        assert!(
            !conflict.message.contains("example.com"),
            "conflict message must not echo hostnames"
        );
    }
}

/// HTTP `a`, TCP `b`, HTTP `c` on one Gateway+port must refuse every TCP-family
/// participant regardless of listener/name order. A sequential accept/remove
/// walk wrongly lets the trailing HTTP claim survive when ordered `a,b,c`.
#[test]
fn three_claim_http_tcp_http_protocol_conflict_is_order_independent() {
    let orders: [[&str; 3]; 2] = [["a", "b", "c"], ["a", "c", "b"]];
    for names in orders {
        let listeners: Vec<Value> = names
            .iter()
            .map(|name| {
                let protocol = if *name == "b" { "TCP" } else { "HTTP" };
                let mut listener = json!({
                    "name": name,
                    "port": 8080,
                    "protocol": protocol,
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                });
                if protocol == "TCP" {
                    listener["allowedRoutes"] = json!({
                        "kinds": [{ "kind": "TCPRoute" }],
                        "namespaces": { "from": "Same" }
                    });
                }
                listener
            })
            .collect();
        let mut gateway = http_gateway("edge", Some("Same"));
        gateway.spec["listeners"] = Value::Array(listeners);
        let objects = vec![gateway_class(), gateway];
        let translation = translate_k8s_objects(&objects, options()).expect("translate");

        for name in names {
            let key = GatewayApiListenerKey {
                namespace: "default".to_string(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: "edge".to_string(),
                listener: name.to_string(),
            };
            let conflict = translation.listener_conflicts.get(&key).unwrap_or_else(|| {
                panic!(
                    "order {:?} must ProtocolConflict every TCP-family claim including {name}: {:?}",
                    names, translation.listener_conflicts
                )
            });
            assert_eq!(conflict.reason, "ProtocolConflict");
            assert_eq!(
                conflict.message,
                "Port 8080 is claimed by incompatible protocol families on the same TCP \
                 transport (HTTP-family vs raw stream), so every conflicting claim on this \
                 port is refused (Conflicted)."
            );
            assert!(
                translation.warnings.iter().any(|warning| {
                    warning.contains(&format!(
                        "Gateway default/edge listener {name} rejected: ProtocolConflict"
                    ))
                }),
                "order {:?} warnings must refuse {name}: {:?}",
                names,
                translation.warnings
            );
        }
        assert_eq!(
            translation.listener_conflicts.len(),
            3,
            "order {:?} must refuse exactly the three TCP-family claims: {:?}",
            names,
            translation.listener_conflicts
        );
        let services = translation
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.services.as_slice())
            .unwrap_or(&[]);
        for name in names {
            assert!(
                services
                    .iter()
                    .all(|service| service.name != format!("edge-{name}")),
                "order {:?} must not materialize conflicted MeshService edge-{name}: {:?}",
                names,
                services
                    .iter()
                    .map(|service| service.name.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }
}

/// Independent Gateways that share only a numeric port still share one OS
/// socket. Gateway team-a/alpha with only HTTP and team-b/beta with only TCP on
/// the same port must both ProtocolConflict (and any additional HTTP-family
/// participant must withdraw too). Status messages stay port/family wording —
/// never other namespaces' or Gateways' object/listener names.
#[test]
fn cross_gateway_http_and_tcp_on_same_port_protocol_conflict() {
    let orders: [[&str; 3]; 2] = [["alpha", "beta", "gamma"], ["gamma", "beta", "alpha"]];
    for gateway_order in orders {
        let mut objects = vec![gateway_class()];
        for name in gateway_order {
            let (namespace, listeners) = match name {
                "alpha" => (
                    "team-a",
                    json!([{
                        "name": "alpha-http",
                        "port": 8080,
                        "protocol": "HTTP",
                        "allowedRoutes": { "namespaces": { "from": "Same" } }
                    }]),
                ),
                "beta" => (
                    "team-b",
                    json!([
                        {
                            "name": "beta-tcp",
                            "port": 8080,
                            "protocol": "TCP",
                            "allowedRoutes": {
                                "kinds": [{ "kind": "TCPRoute" }],
                                "namespaces": { "from": "Same" }
                            }
                        },
                        {
                            "name": "beta-udp",
                            "port": 8080,
                            "protocol": "UDP",
                            "allowedRoutes": {
                                "kinds": [{ "kind": "UDPRoute" }],
                                "namespaces": { "from": "Same" }
                            }
                        }
                    ]),
                ),
                "gamma" => (
                    "team-c",
                    json!([{
                        "name": "gamma-http",
                        "port": 8080,
                        "protocol": "HTTP",
                        "allowedRoutes": { "namespaces": { "from": "Same" } }
                    }]),
                ),
                other => panic!("unexpected gateway fixture {other}"),
            };
            let mut gateway = http_gateway(name, Some("Same"));
            gateway.metadata.namespace = namespace.to_string();
            gateway.spec["listeners"] = listeners;
            objects.push(gateway);
        }

        let translation =
            translate_k8s_objects(&objects, options().with_source_namespaces(Vec::new()))
                .expect("translate");
        let expected_message = "Port 8080 is claimed by incompatible protocol families on the \
             same TCP transport (HTTP-family vs raw stream), so every conflicting claim on this \
             port is refused (Conflicted).";

        let expected = [
            ("team-a", "alpha", "alpha-http"),
            ("team-b", "beta", "beta-tcp"),
            ("team-c", "gamma", "gamma-http"),
        ];
        for (namespace, gateway, listener) in expected {
            let key = GatewayApiListenerKey {
                namespace: namespace.to_string(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: gateway.to_string(),
                listener: listener.to_string(),
            };
            let conflict = translation.listener_conflicts.get(&key).unwrap_or_else(|| {
                panic!(
                    "order {:?} must ProtocolConflict {namespace}/{gateway}#{listener}: {:?}",
                    gateway_order, translation.listener_conflicts
                )
            });
            assert_eq!(conflict.reason, "ProtocolConflict");
            assert_eq!(
                conflict.message, expected_message,
                "order {:?} message must be generic port/family wording without object names",
                gateway_order
            );
            let services = translation
                .config
                .mesh
                .as_ref()
                .map(|mesh| mesh.services.as_slice())
                .unwrap_or(&[]);
            assert!(
                services
                    .iter()
                    .all(|service| service.name != format!("{gateway}-{listener}")),
                "order {:?} must not materialize conflicted MeshService {gateway}-{listener}: {:?}",
                gateway_order,
                services
                    .iter()
                    .map(|service| service.name.as_str())
                    .collect::<Vec<_>>()
            );
        }

        let udp = GatewayApiListenerKey {
            namespace: "team-b".to_string(),
            parent_kind: GatewayApiListenerParentKind::Gateway,
            gateway: "beta".to_string(),
            listener: "beta-udp".to_string(),
        };
        assert!(
            !translation.listener_conflicts.contains_key(&udp),
            "order {:?} UDP must remain accepted beside global HTTP/TCP conflict: {:?}",
            gateway_order,
            translation.listener_conflicts
        );
        assert_eq!(
            translation.listener_conflicts.len(),
            3,
            "order {:?} must withdraw exactly the three TCP-family claims: {:?}",
            gateway_order,
            translation.listener_conflicts
        );
    }
}

/// UDP remains a separate transport: when HTTP and TCP conflict on a port, a
/// co-located UDP claim on the same number must stay accepted.
#[test]
fn udp_coexists_when_http_and_tcp_protocol_conflict_on_same_port() {
    let mut gateway = http_gateway("edge", Some("Same"));
    gateway.spec["listeners"] = json!([
        {
            "name": "http",
            "port": 9000,
            "protocol": "HTTP",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        },
        {
            "name": "tcp",
            "port": 9000,
            "protocol": "TCP",
            "allowedRoutes": {
                "kinds": [{ "kind": "TCPRoute" }],
                "namespaces": { "from": "Same" }
            }
        },
        {
            "name": "udp",
            "port": 9000,
            "protocol": "UDP",
            "allowedRoutes": {
                "kinds": [{ "kind": "UDPRoute" }],
                "namespaces": { "from": "Same" }
            }
        }
    ]);
    let objects = vec![gateway_class(), gateway];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    for listener in ["http", "tcp"] {
        let key = GatewayApiListenerKey {
            namespace: "default".to_string(),
            parent_kind: GatewayApiListenerParentKind::Gateway,
            gateway: "edge".to_string(),
            listener: listener.to_string(),
        };
        assert_eq!(
            translation
                .listener_conflicts
                .get(&key)
                .map(|conflict| conflict.reason),
            Some("ProtocolConflict"),
            "{listener} must ProtocolConflict: {:?}",
            translation.listener_conflicts
        );
    }
    let udp = GatewayApiListenerKey {
        namespace: "default".to_string(),
        parent_kind: GatewayApiListenerParentKind::Gateway,
        gateway: "edge".to_string(),
        listener: "udp".to_string(),
    };
    assert!(
        !translation.listener_conflicts.contains_key(&udp),
        "UDP must remain accepted beside an HTTP/TCP family conflict: {:?}",
        translation.listener_conflicts
    );
    assert!(
        !translation.warnings.iter().any(|warning| {
            warning.contains("Gateway default/edge listener udp rejected: ProtocolConflict")
        }),
        "UDP must not receive ProtocolConflict warnings: {:?}",
        translation.warnings
    );
}

#[test]
fn tcp_and_udp_gateway_listeners_may_share_a_numeric_port() {
    let mut gateway = http_gateway("edge", Some("Same"));
    gateway.spec["listeners"] = json!([
        {
            "name": "tcp",
            "port": 9000,
            "protocol": "TCP",
            "allowedRoutes": {
                "kinds": [{ "kind": "TCPRoute" }],
                "namespaces": { "from": "Same" }
            }
        },
        {
            "name": "udp",
            "port": 9000,
            "protocol": "UDP",
            "allowedRoutes": {
                "kinds": [{ "kind": "UDPRoute" }],
                "namespaces": { "from": "Same" }
            }
        }
    ]);
    let objects = vec![gateway_class(), gateway];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(
        translation.listener_conflicts.is_empty(),
        "TCP and UDP are different transports and must not ProtocolConflict on one number: {:?}",
        translation.listener_conflicts
    );
    assert!(
        !translation
            .warnings
            .iter()
            .any(|warning| warning.contains("ProtocolConflict")),
        "TCP+UDP must not emit ProtocolConflict warnings: {:?}",
        translation.warnings
    );
}

#[test]
fn tcp_and_tls_passthrough_listeners_may_share_a_numeric_port() {
    let mut gateway = http_gateway("edge", Some("Same"));
    gateway.spec["listeners"] = json!([
        {
            "name": "tcp",
            "port": 8443,
            "protocol": "TCP",
            "allowedRoutes": {
                "kinds": [{ "kind": "TCPRoute" }],
                "namespaces": { "from": "Same" }
            }
        },
        {
            "name": "tls",
            "port": 8443,
            "protocol": "TLS",
            "hostname": "sni.example.com",
            "tls": { "mode": "Passthrough" },
            "allowedRoutes": {
                "kinds": [{ "kind": "TLSRoute" }],
                "namespaces": { "from": "Same" }
            }
        }
    ]);
    let objects = vec![gateway_class(), gateway];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(
        translation.listener_conflicts.is_empty(),
        "raw TCP and TLS-passthrough share the opaque stream plane and must not ProtocolConflict: {:?}",
        translation.listener_conflicts
    );
    assert!(
        !translation
            .warnings
            .iter()
            .any(|warning| warning.contains("ProtocolConflict")),
        "TCP+TLS-passthrough must not emit ProtocolConflict warnings: {:?}",
        translation.warnings
    );
}

#[test]
fn listenerset_section_name_and_allowed_routes_gates() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([
                {
                    "name": "a",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "a.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "b",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "b.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }
            ]),
        ),
        service("backend"),
        http_route(
            "section-a",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default",
                "sectionName": "a"
            }]),
            "a.example.com",
            "/a",
        ),
        http_route(
            "bad-section",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default",
                "sectionName": "missing"
            }]),
            "a.example.com",
            "/missing",
        ),
    ];
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, options()).expect("translate");
    assert!(
        skipped.values().any(|error| {
            let error = error.to_string();
            error.contains("bad-section")
                && error.contains("does not match any known ListenerSet listener")
        }),
        "the invalid sibling route must be reported as skipped: {skipped:?}"
    );
    assert!(translation.config.proxies.iter().any(|proxy| {
        proxy.hosts.iter().any(|host| host == "a.example.com")
            && proxy
                .listen_path
                .as_deref()
                .is_some_and(|path| path.contains("/a"))
    }));
    assert!(
        !translation.config.proxies.iter().any(|proxy| proxy
            .listen_path
            .as_deref()
            .is_some_and(|path| path.contains("missing"))),
        "unknown sectionName must fail closed"
    );
}

#[test]
fn listenerset_update_and_delete_withdraw_materialization() {
    let base = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "extra-http",
                "port": 80,
                "protocol": "HTTP",
                "hostname": "extra.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
        service("backend"),
        http_route(
            "via-listenerset",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default"
            }]),
            "extra.example.com",
            "/via-set",
        ),
    ];
    let first = translate_k8s_objects(&base, options()).expect("first translate");
    assert!(
        first
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "extra.example.com") })
    );
    let managed = BTreeSet::from(["default".to_string()]);
    let active = merge_k8s_translation(
        &ferrum_edge::config::types::GatewayConfig::default(),
        &first.config,
        &managed,
    );
    assert!(
        active
            .proxies
            .iter()
            .any(|proxy| proxy.hosts.iter().any(|host| host == "extra.example.com")),
        "initial ListenerSet overlay must be published"
    );

    // Tighten allowedListeners to None and retranslate — ListenerSet withdraws.
    let mut tightened = base.clone();
    tightened[1] = http_gateway("edge", None);
    let (second, second_skipped) =
        translate_k8s_objects_collecting_skips(&tightened, options()).expect("second translate");
    assert!(
        second_skipped.values().any(|error| {
            let error = error.to_string();
            error.contains("via-listenerset")
                && error.contains("not permitted by the target ListenerSet listener")
        }),
        "the route to the withdrawn ListenerSet must be skipped: {second_skipped:?}"
    );
    assert!(
        second
            .listenerset_statuses
            .iter()
            .any(|status| status.resource.name == "extra" && !status.accepted)
    );
    assert!(
        !second
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "extra.example.com") }),
        "tightening allowedListeners must withdraw ListenerSet traffic"
    );

    // Delete ListenerSet entirely.
    let deleted: Vec<_> = base
        .into_iter()
        .filter(|object| object.kind != "ListenerSet")
        .collect();
    let (third, third_skipped) =
        translate_k8s_objects_collecting_skips(&deleted, options()).expect("third translate");
    assert!(
        third_skipped.values().any(|error| {
            let error = error.to_string();
            error.contains("via-listenerset")
                && error.contains("not permitted by the target ListenerSet listener")
        }),
        "the route to the deleted ListenerSet must be skipped: {third_skipped:?}"
    );
    assert!(third.listenerset_statuses.is_empty());
    assert!(
        !third
            .config
            .proxies
            .iter()
            .any(|proxy| { proxy.hosts.iter().any(|host| host == "extra.example.com") }),
        "deleting ListenerSet must withdraw materialization"
    );
    let after_delete = merge_k8s_translation(&active, &third.config, &managed);
    assert!(
        !after_delete
            .proxies
            .iter()
            .any(|proxy| proxy.hosts.iter().any(|host| host == "extra.example.com")),
        "reconciliation must remove the previously published ListenerSet proxy after deletion"
    );
}

#[test]
fn same_named_gateway_and_listenerset_tls_services_both_materialize() {
    let mut gateway = object(
        "Gateway",
        "shared",
        json!({
            "gatewayClassName": "ferrum",
            "allowedListeners": {"namespaces": {"from": "Same"}},
            "listeners": [{
                "name": "same",
                "port": 443,
                "protocol": "HTTPS",
                "hostname": "gateway.example.com",
                "allowedRoutes": {"namespaces": {"from": "Same"}},
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{"name": "gateway-cert"}]
                }
            }]
        }),
    );
    gateway.metadata.uid = "uid-gateway-shared".to_string();
    let mut set = listenerset(
        "shared",
        "shared",
        json!([{
            "name": "same",
            "port": 8443,
            "protocol": "HTTPS",
            "hostname": "set.example.com",
            "allowedRoutes": {"namespaces": {"from": "Same"}},
            "tls": {
                "mode": "Terminate",
                "certificateRefs": [{"name": "set-cert"}]
            }
        }]),
    );
    set.metadata.uid = "uid-listenerset-shared".to_string();

    let gateway_secret = tls_secret("gateway-cert", "default");
    let set_secret = tls_secret("set-cert", "default");

    let translation = translate_k8s_objects(
        &[gateway_class(), gateway, set, gateway_secret, set_secret],
        options(),
    )
    .expect("translate same-named Gateway and ListenerSet");
    assert!(
        translation.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "shared-same")
        }),
        "the winning Gateway listener should emit the colliding synthetic name"
    );
    assert!(
        translation.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "listenerset-shared-same")
        }),
        "the ListenerSet must retain its own certificate-backed service now that frontend TLS is listener-scoped"
    );
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.kind == "ListenerSet" && status.resource.name == "shared")
        .expect("ListenerSet translation status");
    assert!(
        status.accepted,
        "the non-conflicting ListenerSet stays accepted"
    );
    assert!(
        status.programmed && status.programmed_listeners == ["same"],
        "the independently certificate-backed ListenerSet listener must report Programmed"
    );
}

#[test]
fn listenerset_service_cannot_program_same_named_gateway() {
    let gateway = object(
        "Gateway",
        "shared",
        json!({
            "gatewayClassName": "ferrum",
            "allowedListeners": {"namespaces": {"from": "Same"}},
            "listeners": [{
                "name": "same",
                "protocol": "HTTP",
                "allowedRoutes": {"namespaces": {"from": "Same"}}
            }]
        }),
    );
    let set = listenerset(
        "shared",
        "shared",
        json!([{
            "name": "same",
            "port": 8080,
            "protocol": "HTTP",
            "allowedRoutes": {"namespaces": {"from": "Same"}}
        }]),
    );
    let objects = vec![gateway_class(), gateway, set];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translation.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "listenerset-shared-same")
        }),
        "the ListenerSet should emit a kind-scoped service"
    );

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let gateway_update = updates
        .iter()
        .find(|update| update.kind == "Gateway" && update.name == "shared")
        .expect("Gateway status update");
    let programmed = gateway_update.status["conditions"]
        .as_array()
        .expect("Gateway conditions")
        .iter()
        .find(|condition| condition["type"] == "Programmed")
        .expect("Gateway Programmed condition");
    assert_eq!(
        programmed["status"], "False",
        "a ListenerSet-owned service must not program the same-named Gateway"
    );
}

#[test]
fn listenerset_cross_namespace_secret_requires_listenerset_grant() {
    // Watch both namespaces so the certs Secret/ReferenceGrant are collected;
    // otherwise fail-closed looks identical to a missing grant.
    let opts = options().with_source_namespaces(vec!["default".to_string(), "certs".to_string()]);
    let secret = tls_secret("cert", "certs");

    let without_grant = vec![
        gateway_class(),
        http_gateway("edge", Some("All")),
        listenerset(
            "tls-set",
            "edge",
            json!([{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "hostname": "secure.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } },
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{
                        "name": "cert",
                        "namespace": "certs"
                    }]
                }
            }]),
        ),
        secret.clone(),
    ];
    let translation = translate_k8s_objects(&without_grant, opts.clone()).expect("translate");
    // Without a ListenerSet-scoped ReferenceGrant the HTTPS listener is not
    // materializable even when the Secret is observed.
    assert!(translation.config.mesh.as_ref().is_none_or(|mesh| {
        !mesh
            .services
            .iter()
            .any(|service| service.name == "listenerset-tls-set-https")
    }));

    let mut grant = object(
        "ReferenceGrant",
        "allow-listenerset-cert",
        json!({
            "from": [{
                "namespace": "default",
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet"
            }],
            "to": [{
                "group": "",
                "kind": "Secret",
                "name": "cert"
            }]
        }),
    );
    grant.api_version = "gateway.networking.k8s.io/v1beta1".to_string();
    grant.metadata.namespace = "certs".to_string();
    let mut with_grant = without_grant;
    with_grant.push(grant);
    let translation = translate_k8s_objects(&with_grant, opts).expect("translate with grant");
    assert!(
        translation.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "listenerset-tls-set-https")
        }),
        "a ListenerSet-scoped ReferenceGrant must authorize the valid cross-namespace TLS Secret"
    );
}

#[test]
fn cross_namespace_listenerset_extends_parent_gateway_tls_candidates() {
    let mut gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "allowedListeners": { "namespaces": { "from": "All" } },
            "listeners": [{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "hostname": "gateway.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } },
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{ "name": "gateway-cert" }]
                }
            }]
        }),
    );
    gateway.metadata.namespace = "gateway-ns".to_string();

    let mut set = listenerset(
        "extra",
        "edge",
        json!([{
            "name": "https-extra",
            "port": 443,
            "protocol": "HTTPS",
            "hostname": "extra.example.com",
            "allowedRoutes": { "namespaces": { "from": "Same" } },
            "tls": {
                "mode": "Terminate",
                "certificateRefs": [{ "name": "listenerset-cert" }]
            }
        }]),
    );
    set.metadata.namespace = "extension-ns".to_string();
    set.spec["parentRef"]["namespace"] = json!("gateway-ns");

    let objects = vec![
        gateway_class(),
        gateway,
        set,
        tls_secret("gateway-cert", "gateway-ns"),
        tls_secret("listenerset-cert", "extension-ns"),
    ];
    let opts = options()
        .with_source_namespaces(vec!["gateway-ns".to_string(), "extension-ns".to_string()]);
    let translation = translate_k8s_objects(&objects, opts.clone()).expect("translate");

    assert_eq!(translation.config.frontend_tls_certificate_sources.len(), 2);
    assert_eq!(
        translation.config.frontend_tls_source_namespace.as_deref(),
        Some("gateway-ns")
    );
    assert!(
        translation
            .config
            .frontend_tls_cert_path
            .as_deref()
            .is_some_and(|path| path.starts_with("k8s://gateway-ns/gateway-cert#tls.crt?")),
        "the parent Gateway must remain the deterministic fallback"
    );
    assert!(translation.config.mesh.as_ref().is_some_and(|mesh| {
        mesh.services
            .iter()
            .any(|service| service.namespace == "gateway-ns" && service.name == "edge-https")
            && mesh.services.iter().any(|service| {
                service.namespace == "extension-ns"
                    && service.name == "listenerset-extra-https-extra"
            })
    }));

    let updates = plan_gateway_api_status_updates(&objects, opts, &translation.route_conflicts);
    let gateway_update = updates
        .iter()
        .find(|update| {
            update.kind == "Gateway" && update.namespace == "gateway-ns" && update.name == "edge"
        })
        .expect("Gateway status update");
    let gateway_listener = gateway_update.status["listeners"]
        .as_array()
        .expect("Gateway listeners")
        .iter()
        .find(|listener| listener["name"] == "https")
        .expect("Gateway HTTPS listener");
    let conflicted = gateway_listener["conditions"]
        .as_array()
        .expect("Gateway listener conditions")
        .iter()
        .find(|condition| condition["type"] == "Conflicted")
        .expect("Gateway Conflicted condition");
    assert_eq!(conflicted["status"], "False");
    assert_eq!(conflicted["reason"], "NoConflicts");
}

fn listenerset_listener_condition<'a>(
    updates: &'a [ferrum_edge::k8s_controller::status::GatewayApiStatusUpdate],
    listenerset: &str,
    listener: &str,
    condition_type: &str,
) -> &'a Value {
    let update = updates
        .iter()
        .find(|update| update.kind == "ListenerSet" && update.name == listenerset)
        .expect("ListenerSet status update");
    let listeners = update.status["listeners"].as_array().expect("listeners");
    let listener_status = listeners
        .iter()
        .find(|entry| entry["name"] == listener)
        .expect("listener status");
    listener_status["conditions"]
        .as_array()
        .expect("conditions")
        .iter()
        .find(|condition| condition["type"] == condition_type)
        .expect("condition")
}

fn route_parent_condition<'a>(
    updates: &'a [ferrum_edge::k8s_controller::status::GatewayApiStatusUpdate],
    route: &str,
    condition_type: &str,
) -> &'a Value {
    let update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == route)
        .expect("HTTPRoute status update");
    let parents = update.status["parents"].as_array().expect("parents");
    parents[0]["conditions"]
        .as_array()
        .expect("conditions")
        .iter()
        .find(|condition| condition["type"] == condition_type)
        .expect("condition")
}

#[test]
fn listenerset_resolved_refs_same_namespace_tls_secret_outcomes() {
    let secret = tls_secret("edge-cert", "default");
    let with_secret = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "tls-set",
            "edge",
            json!([{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "hostname": "secure.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } },
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{ "name": "edge-cert" }]
                }
            }]),
        ),
        secret,
    ];
    let translation = translate_k8s_objects(&with_secret, options()).expect("translate");
    let updates = plan_gateway_api_status_updates(&with_secret, options(), &[]);
    let resolved = listenerset_listener_condition(&updates, "tls-set", "https", "ResolvedRefs");
    assert_eq!(resolved["status"], "True");
    assert_eq!(resolved["reason"], "ResolvedRefs");
    assert!(translation.config.mesh.as_ref().is_some_and(|mesh| {
        mesh.services
            .iter()
            .any(|service| service.name == "listenerset-tls-set-https")
    }));

    let missing = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "tls-set",
            "edge",
            json!([{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "hostname": "secure.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } },
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{ "name": "missing-cert" }]
                }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&missing, options()).expect("translate missing");
    let updates = plan_gateway_api_status_updates(&missing, options(), &[]);
    let resolved = listenerset_listener_condition(&updates, "tls-set", "https", "ResolvedRefs");
    assert_eq!(resolved["status"], "False");
    assert_eq!(resolved["reason"], "InvalidCertificateRef");
    let accepted = listenerset_listener_condition(&updates, "tls-set", "https", "Accepted");
    assert_eq!(accepted["status"], "True");
    assert!(translation.config.mesh.as_ref().is_none_or(|mesh| {
        !mesh
            .services
            .iter()
            .any(|service| service.name == "listenerset-tls-set-https")
    }));
}

#[test]
fn listenerset_resolved_refs_cross_namespace_grant_boundary() {
    let opts = options().with_source_namespaces(vec!["default".to_string(), "certs".to_string()]);
    let secret = tls_secret("cert", "certs");
    let without_grant = vec![
        gateway_class(),
        http_gateway("edge", Some("All")),
        listenerset(
            "tls-set",
            "edge",
            json!([{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "hostname": "secure.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } },
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{
                        "name": "cert",
                        "namespace": "certs"
                    }]
                }
            }]),
        ),
        secret.clone(),
    ];
    let updates = plan_gateway_api_status_updates(&without_grant, opts.clone(), &[]);
    let resolved = listenerset_listener_condition(&updates, "tls-set", "https", "ResolvedRefs");
    assert_eq!(resolved["status"], "False");
    assert_eq!(resolved["reason"], "RefNotPermitted");
    let accepted = listenerset_listener_condition(&updates, "tls-set", "https", "Accepted");
    assert_eq!(accepted["status"], "True");

    let mut grant = object(
        "ReferenceGrant",
        "allow-listenerset-cert",
        json!({
            "from": [{
                "namespace": "default",
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet"
            }],
            "to": [{
                "group": "",
                "kind": "Secret",
                "name": "cert"
            }]
        }),
    );
    grant.api_version = "gateway.networking.k8s.io/v1beta1".to_string();
    grant.metadata.namespace = "certs".to_string();
    let mut with_grant = without_grant;
    with_grant.push(grant);
    let updates = plan_gateway_api_status_updates(&with_grant, opts, &[]);
    let resolved = listenerset_listener_condition(&updates, "tls-set", "https", "ResolvedRefs");
    assert_eq!(resolved["status"], "True");
    assert_eq!(resolved["reason"], "ResolvedRefs");
}

#[test]
fn listenerset_resolved_refs_invalid_route_kinds() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "bad-kinds",
            "edge",
            json!([{
                "name": "http",
                "port": 8080,
                "protocol": "HTTP",
                "hostname": "kinds.example.com",
                "allowedRoutes": {
                    "namespaces": { "from": "Same" },
                    "kinds": [{ "kind": "TCPRoute" }]
                }
            }]),
        ),
    ];
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let resolved = listenerset_listener_condition(&updates, "bad-kinds", "http", "ResolvedRefs");
    assert_eq!(resolved["status"], "False");
    assert_eq!(resolved["reason"], "InvalidRouteKinds");
    let accepted = listenerset_listener_condition(&updates, "bad-kinds", "http", "Accepted");
    assert_eq!(accepted["status"], "True");
    let conflicted = listenerset_listener_condition(&updates, "bad-kinds", "http", "Conflicted");
    assert_eq!(conflicted["status"], "False");
}

#[test]
fn listenerset_route_status_unknown_section_and_namespace_rejection() {
    let opts = options().with_source_namespaces(vec!["default".to_string(), "other".to_string()]);
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "extra",
            "edge",
            json!([{
                "name": "a",
                "port": 8080,
                "protocol": "HTTP",
                "hostname": "a.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
        service("backend"),
        http_route(
            "bad-section",
            json!([{
                "kind": "ListenerSet",
                "name": "extra",
                "namespace": "default",
                "sectionName": "missing"
            }]),
            "a.example.com",
            "/missing",
        ),
        {
            let mut other_ns_route = http_route(
                "other-ns",
                json!([{
                    "kind": "ListenerSet",
                    "name": "extra",
                    "namespace": "default"
                }]),
                "a.example.com",
                "/other",
            );
            other_ns_route.metadata.namespace = "other".to_string();
            other_ns_route
        },
    ];
    let updates = plan_gateway_api_status_updates(&objects, opts, &[]);

    let accepted = route_parent_condition(&updates, "bad-section", "Accepted");
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], "NoMatchingParent");
    let resolved = route_parent_condition(&updates, "bad-section", "ResolvedRefs");
    assert_eq!(resolved["status"], "True");
    assert_eq!(resolved["reason"], "ResolvedRefs");

    let other = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "other-ns")
        .expect("other-ns route status");
    let accepted = other.status["parents"][0]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .unwrap();
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], "NotAllowedByListeners");
}

#[test]
fn listenerset_catch_all_and_wildcard_coexist_with_exact_hostname() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "mixed",
            "edge",
            json!([
                {
                    "name": "fallback",
                    "port": 8080,
                    "protocol": "HTTP",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "exact",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "exact.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "wild",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "*.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }
            ]),
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "mixed")
        .expect("status");
    assert!(status.accepted);
    assert!(status.listener_conflicts.is_empty());
    assert!(translation.config.mesh.as_ref().is_some_and(|mesh| {
        ["fallback", "exact", "wild"].iter().all(|listener| {
            mesh.services
                .iter()
                .any(|service| service.name == format!("listenerset-mixed-{listener}"))
        })
    }));
}

#[test]
fn listenerset_identical_hostnames_still_conflict() {
    let objects = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "dup",
            "edge",
            json!([
                {
                    "name": "first",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "same.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "second",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "same.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }
            ]),
        ),
    ];
    let translation = translate_k8s_objects(&objects, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "dup")
        .expect("status");
    assert!(
        status
            .listener_conflicts
            .iter()
            .any(|(name, reason)| name == "second" && reason == "HostnameConflict")
    );
    assert!(translation.config.mesh.as_ref().is_some_and(|mesh| {
        mesh.services
            .iter()
            .any(|service| service.name == "listenerset-dup-first")
            && !mesh
                .services
                .iter()
                .any(|service| service.name == "listenerset-dup-second")
    }));
}

#[test]
fn listenerset_invalid_shapes_fail_closed_with_field_diagnostics() {
    let missing_fields = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "missing",
            "edge",
            json!([{
                "hostname": "missing.example.com",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]),
        ),
    ];
    let translation = translate_k8s_objects(&missing_fields, options()).expect("translate");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "missing")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "ListenersNotValid");
    assert!(translation.config.mesh.as_ref().is_none_or(|mesh| {
        !mesh
            .services
            .iter()
            .any(|service| service.name.starts_with("listenerset-missing-"))
    }));
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains("spec.listeners[].name"))
    );

    let duplicates = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "dups",
            "edge",
            json!([
                {
                    "name": "http",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "a.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "http",
                    "port": 8081,
                    "protocol": "HTTP",
                    "hostname": "b.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }
            ]),
        ),
    ];
    let translation = translate_k8s_objects(&duplicates, options()).expect("translate dups");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "dups")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert!(status.accepted_message.contains("unique"));

    let mut over_limit_listeners = Vec::new();
    for index in 0..65 {
        over_limit_listeners.push(json!({
            "name": format!("http-{index}"),
            "port": 8080 + index,
            "protocol": "HTTP",
            "hostname": format!("h{index}.example.com"),
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }));
    }
    let over_limit = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset("too-many", "edge", Value::Array(over_limit_listeners)),
    ];
    let translation = translate_k8s_objects(&over_limit, options()).expect("translate over-limit");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "too-many")
        .expect("status");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert!(status.accepted_message.contains("at most 64"));
    assert!(translation.config.mesh.as_ref().is_none_or(|mesh| {
        !mesh
            .services
            .iter()
            .any(|service| service.name.starts_with("listenerset-too-many-"))
    }));

    let malformed = vec![
        gateway_class(),
        http_gateway("edge", Some("Same")),
        listenerset(
            "malformed",
            "edge",
            json!([
                {
                    "name": "bad-proto",
                    "port": 8080,
                    "protocol": "FTP",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "bad-tls",
                    "port": 8081,
                    "protocol": "HTTP",
                    "tls": { "mode": "Terminate" },
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "bad-host",
                    "port": 8082,
                    "protocol": "HTTP",
                    "hostname": "not a hostname!!",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                },
                {
                    "name": "ok",
                    "port": 8083,
                    "protocol": "HTTP",
                    "hostname": "ok.example.com",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }
            ]),
        ),
    ];
    let translation = translate_k8s_objects(&malformed, options()).expect("translate malformed");
    let status = translation
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.name == "malformed")
        .expect("status");
    assert!(
        status.accepted,
        "partially valid ListenerSets may remain accepted"
    );
    assert!(translation.config.mesh.as_ref().is_some_and(|mesh| {
        mesh.services
            .iter()
            .any(|service| service.name == "listenerset-malformed-ok")
            && !mesh.services.iter().any(|service| {
                service.name == "listenerset-malformed-bad-proto"
                    || service.name == "listenerset-malformed-bad-tls"
                    || service.name == "listenerset-malformed-bad-host"
            })
    }));
    let updates = plan_gateway_api_status_updates(&malformed, options(), &[]);
    for (listener, expected_reason) in [
        ("bad-proto", "UnsupportedProtocol"),
        ("bad-tls", "Invalid"),
        ("bad-host", "Invalid"),
    ] {
        let accepted = listenerset_listener_condition(&updates, "malformed", listener, "Accepted");
        assert_eq!(accepted["status"], "False");
        assert_eq!(accepted["reason"], expected_reason);
    }
    let ok = listenerset_listener_condition(&updates, "malformed", "ok", "Accepted");
    assert_eq!(ok["status"], "True");
}
